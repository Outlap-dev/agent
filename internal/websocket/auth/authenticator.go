// Package auth provides authentication functionality for WebSocket connections
package auth

import (
	"context"
	"fmt"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/websocket/retry"
	"pulseup-agent-go/internal/websocket/types"
	"pulseup-agent-go/pkg/logger"
)

// Authenticator handles WebSocket authentication
type Authenticator struct {
	logger         *logger.Logger
	failureTracker *retry.AuthFailureTracker
	authResult     chan types.AuthResult
	config         *AuthConfig
	certProvider   func() (string, error)
	signProvider   func([]byte) (string, error)
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	// Timeout for authentication attempts
	Timeout time.Duration `json:"timeout" yaml:"timeout"`

	// Whether to wait for explicit confirmation
	WaitForConfirmation bool `json:"wait_for_confirmation" yaml:"wait_for_confirmation"`

	// Retry configuration for authentication failures
	RetryConfig *retry.AuthRetryConfig `json:"retry_config" yaml:"retry_config"`

	// Authentication method (mtls only)
	Method string `json:"method" yaml:"method"`
}

// DefaultAuthConfig returns authentication configuration with sensible defaults
func DefaultAuthConfig() *AuthConfig {
	return &AuthConfig{
		Timeout:             30 * time.Second,
		WaitForConfirmation: true,
		RetryConfig:         retry.DefaultAuthRetryConfig(),
		Method:              "mtls",
	}
}

// NewAuthenticator creates a new authenticator instance
func NewAuthenticator(logger *logger.Logger, config *AuthConfig) *Authenticator {
	if config == nil {
		config = DefaultAuthConfig()
	}

	return &Authenticator{
		logger:         logger.With("component", "websocket_auth"),
		failureTracker: retry.NewAuthFailureTracker(config.RetryConfig),
		authResult:     make(chan types.AuthResult, 1),
		config:         config,
	}
}

// SetCertificateProvider sets a function that returns the client certificate PEM for mTLS auth messages
func (a *Authenticator) SetCertificateProvider(provider func() (string, error)) {
	a.certProvider = provider
}

// SetSignProvider sets a function that signs arbitrary data and returns base64 signature
func (a *Authenticator) SetSignProvider(provider func([]byte) (string, error)) {
	a.signProvider = provider
}

// Authenticate performs WebSocket authentication
func (a *Authenticator) Authenticate(ctx context.Context, sender types.MessageSender) (*types.AuthResult, error) {
	// Check if we should retry authentication
	if !a.failureTracker.ShouldRetryAuth() {
		count, lastFailure := a.failureTracker.GetFailureInfo()
		return nil, fmt.Errorf("too many consecutive authentication failures (%d), last failure: %v",
			count, lastFailure.Format(time.RFC3339))
	}

	if a.config.Method != "mtls" {
		return nil, fmt.Errorf("unsupported authentication method: %s", a.config.Method)
	}

	a.logger.Debug("Using mTLS authentication - waiting for challenge")

	a.logger.Debug("Authentication message sent, waiting for response")

	// If not waiting for confirmation, assume success for backward compatibility
	if !a.config.WaitForConfirmation {
		result := &types.AuthResult{Success: true}
		a.failureTracker.RecordSuccess()
		return result, nil
	}

	// Wait for authentication response
	timeout := time.After(a.config.Timeout)

	select {
	case result := <-a.authResult:
		if result.Success {
			a.failureTracker.RecordSuccess()
		} else {
			a.logger.Error("Authentication failed", "error", result.Error)
			// Don't record failure here - it's handled in HandleAuthResponse for proper classification
		}
		return &result, nil

	case <-timeout:
		a.logger.Error("Authentication timeout")
		a.failureTracker.RecordFailure()
		return nil, fmt.Errorf("authentication timeout after %v", a.config.Timeout)

	case <-ctx.Done():
		a.logger.Debug("Authentication cancelled")
		return nil, fmt.Errorf("authentication cancelled: %w", ctx.Err())
	}
}

// HandleAuthChallenge processes server nonce and sends auth_proof
func (a *Authenticator) HandleAuthChallenge(msg map[string]interface{}, sender types.MessageSender) error {
	data, _ := msg["data"].(map[string]interface{})
	nonce, _ := data["nonce"].(string)
	if nonce == "" {
		return fmt.Errorf("missing nonce in challenge")
	}
	if a.certProvider == nil || a.signProvider == nil {
		return fmt.Errorf("certificate or signer not configured")
	}
	pem, err := a.certProvider()
	if err != nil || pem == "" {
		return fmt.Errorf("failed to get certificate")
	}
	sig, err := a.signProvider([]byte(nonce))
	if err != nil || sig == "" {
		return fmt.Errorf("failed to sign nonce: %w", err)
	}
	proof := types.Message{Type: "auth_proof", Data: map[string]interface{}{
		"method":      "mtls",
		"certificate": pem,
		"signature":   sig,
		"nonce":       nonce,
		"version":     config.GetVersionString(),
	}}
	return sender.SendMessage(proof)
}

// HandleAuthResponse processes an authentication response message
func (a *Authenticator) HandleAuthResponse(msg map[string]interface{}) (*types.AuthResult, error) {
	a.logger.Debug("Processing auth response", "msg", msg)

	data, ok := msg["data"].(map[string]interface{})
	if !ok {
		result := types.AuthResult{
			Success: false,
			Error:   "invalid auth response format",
		}

		// Try to send result to waiting authenticator
		select {
		case a.authResult <- result:
		default:
			a.logger.Warn("Auth result channel full")
		}

		return &result, fmt.Errorf("invalid auth_response format")
	}

	// Parse response fields
	success, _ := data["success"].(bool)
	serverUID, _ := data["server_uid"].(string)
	errorMsg, _ := data["error"].(string)

	result := types.AuthResult{
		Success:   success,
		ServerUID: serverUID,
		Error:     errorMsg,
	}

	// Send result to waiting authenticator
	select {
	case a.authResult <- result:
	default:
		a.logger.Warn("Auth result channel full, response may be lost")
	}

	if success {
		a.logger.Debug("Auth response indicates success", "server_uid", serverUID)
	} else {
		// Classify the error type
		errorType := types.ClassifyAuthError(errorMsg)
		a.logger.Debug("Auth response indicates failure", "error", errorMsg, "error_type", errorType)

		// Record failure based on error type
		if errorType.IsPermanent() {
			a.logger.Error("Permanent authentication failure detected", "error", errorMsg, "error_type", errorType)
			// Set a special failure mode for permanent errors
			a.failureTracker.RecordPermanentFailure()
		} else {
			// Record normal failure for temporary errors
			a.failureTracker.RecordFailure()
		}
	}

	return &result, nil
}

// ShouldRetry determines if authentication should be retried after a failure
func (a *Authenticator) ShouldRetry() bool {
	return a.failureTracker.ShouldRetryAuth()
}

// GetRetryDelay returns the delay before the next authentication retry
func (a *Authenticator) GetRetryDelay() time.Duration {
	return a.failureTracker.NextAuthDelay()
}

// GetFailureInfo returns information about recent authentication failures
func (a *Authenticator) GetFailureInfo() (count int, lastFailure time.Time) {
	return a.failureTracker.GetFailureInfo()
}

// Reset resets the authenticator state (useful for testing or manual retry reset)
func (a *Authenticator) Reset() {
	a.failureTracker.RecordSuccess()

	// Drain any pending auth results
	select {
	case <-a.authResult:
	default:
	}

	a.logger.Debug("Authenticator state reset")
}
