// Package websocket provides mTLS-enabled WebSocket client functionality
package websocket

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/security"
	"pulseup-agent-go/internal/websocket/client"
	"pulseup-agent-go/pkg/logger"
)

// MTLSClient wraps the WebSocket client with mTLS certificate management
type MTLSClient struct {
	*client.WebSocketClient
	certManager *security.CertificateManager
	logger      *logger.Logger
	config      *config.Config
}

// NewMTLSClient creates a new WebSocket client with mTLS support
func NewMTLSClient(appConfig *config.Config, certManager *security.CertificateManager, logger *logger.Logger) *MTLSClient {
	// Create base WebSocket client
	baseClient := client.NewWebSocketClient(appConfig, logger)

	// Provide certificate PEM and signer for challenge-based authentication up front
	baseClient.SetCertificateProvider(func() (string, error) {
		cert, err := certManager.LoadCertificate()
		if err != nil {
			return "", err
		}
		if len(cert.Certificate) == 0 {
			return "", fmt.Errorf("no certificate loaded")
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}
		return string(pem.EncodeToMemory(block)), nil
	})

	if authenticator := baseClient.GetAuthenticator(); authenticator != nil {
		authenticator.SetSignProvider(func(data []byte) (string, error) {
			return certManager.Sign(data)
		})
	}

	return &MTLSClient{
		WebSocketClient: baseClient,
		certManager:     certManager,
		logger:          logger.With("component", "mtls_websocket_client"),
		config:          appConfig,
	}
}

// ConnectWithMTLS establishes a WebSocket connection using mTLS authentication
func (c *MTLSClient) ConnectWithMTLS(ctx context.Context) error {
	// Check if we have a valid certificate
	if !c.certManager.HasCertificate() {
		return fmt.Errorf("no valid certificate found for mTLS authentication")
	}

	// Load client certificate
	cert, err := c.certManager.LoadCertificate()
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCertPool, err := c.certManager.LoadCACertificate()
	if err != nil {
		return fmt.Errorf("failed to load CA certificate: %w", err)
	}

	// Create TLS configuration for mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS13,
	}

	// Update the client configuration to use mTLS
	clientConfig := c.GetConfig()
	clientConfig.Connection.TLSConfig = tlsConfig
	clientConfig.Auth.Method = "mtls"

	// Provide certificate PEM for application-layer auth message as a fallback when
	// TLS termination is out-of-process (e.g., behind a proxy)
	c.SetCertificateProvider(func() (string, error) {
		cert2, err := c.certManager.LoadCertificate()
		if err != nil {
			return "", err
		}
		if len(cert2.Certificate) == 0 {
			return "", fmt.Errorf("no certificate loaded")
		}
		block := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Certificate[0]}
		return string(pem.EncodeToMemory(block)), nil
	})

	// Connect using the base client with mTLS config
	return c.WebSocketClient.ConnectWithReconnect(ctx)
}

// CheckCertificateRenewal checks if the certificate needs renewal and handles it
func (c *MTLSClient) CheckCertificateRenewal(ctx context.Context) error {
	if !c.certManager.HasCertificate() {
		return fmt.Errorf("no certificate to check for renewal")
	}

	shouldRenew, err := c.certManager.ShouldRenew()
	if err != nil {
		return fmt.Errorf("failed to check certificate renewal status: %w", err)
	}

	if !shouldRenew {
		c.logger.Debug("Certificate does not need renewal yet")
		return nil
	}

	c.logger.Info("Certificate needs renewal - disconnecting for renewal process")

	// Disconnect current connection
	if c.IsConnected() {
		if err := c.Disconnect(); err != nil {
			c.logger.Error("Failed to disconnect for renewal", "error", err)
		}
	}

	c.logger.Info("Certificate renewal needed - please restart agent with valid join token or renew certificate externally")
	return fmt.Errorf("certificate renewal required")
}

// StartWithAutoRenewal starts the WebSocket client with automatic certificate renewal checking
func (c *MTLSClient) StartWithAutoRenewal(ctx context.Context) error {
	c.logger.Info("Starting mTLS WebSocket client with auto-renewal")

	if err := c.ConnectWithMTLS(ctx); err != nil {
		return fmt.Errorf("initial connection failed: %w", err)
	}

	go c.renewalCheckLoop(ctx)

	return nil
}

// renewalCheckLoop periodically checks if certificate renewal is needed
func (c *MTLSClient) renewalCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour) // Check every hour
	defer ticker.Stop()

	c.logger.Debug("Starting certificate renewal check loop")

	for {
		select {
		case <-ctx.Done():
			c.logger.Debug("Certificate renewal check loop stopped")
			return
		case <-ticker.C:
			if err := c.CheckCertificateRenewal(ctx); err != nil {
				c.logger.Error("Certificate renewal check failed", "error", err)
				// Don't return here - keep checking
			}
		}
	}
}

// GetCertificateInfo returns information about the current certificate
func (c *MTLSClient) GetCertificateInfo() (*security.CertificateInfo, error) {
	return c.certManager.GetCertificateInfo()
}

// HasValidCertificate checks if a valid certificate is available
func (c *MTLSClient) HasValidCertificate() bool {
	if !c.certManager.HasCertificate() {
		return false
	}

	// Check if renewal is needed
	shouldRenew, err := c.certManager.ShouldRenew()
	if err != nil {
		return false
	}

	// Certificate is valid if it doesn't need immediate renewal
	return !shouldRenew
}

// GetAuthenticationMethod returns the current authentication method being used
func (c *MTLSClient) GetAuthenticationMethod() string {
	return c.GetConfig().Auth.Method
}
