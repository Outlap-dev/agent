// Package types defines core types and interfaces for the WebSocket client
package types

import "fmt"

// AuthErrorType represents the type of authentication error
type AuthErrorType int

const (
	// AuthErrorUnknown indicates an unknown or unclassified error
	AuthErrorUnknown AuthErrorType = iota
	
	// AuthErrorInvalidToken indicates the token is invalid or has been used
	AuthErrorInvalidToken
	
	// AuthErrorExpiredToken indicates the token has expired
	AuthErrorExpiredToken
	
	// AuthErrorNetworkIssue indicates a network-related failure
	AuthErrorNetworkIssue
	
	// AuthErrorServerIssue indicates a server-side problem
	AuthErrorServerIssue
	
	// AuthErrorTimeout indicates the authentication timed out
	AuthErrorTimeout
)

// String returns a human-readable string representation of the auth error type
func (t AuthErrorType) String() string {
	switch t {
	case AuthErrorInvalidToken:
		return "invalid_token"
	case AuthErrorExpiredToken:
		return "expired_token"
	case AuthErrorNetworkIssue:
		return "network_issue"
	case AuthErrorServerIssue:
		return "server_issue"
	case AuthErrorTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

// IsPermanent returns true if the error is permanent and retrying won't help
func (t AuthErrorType) IsPermanent() bool {
	switch t {
	case AuthErrorInvalidToken, AuthErrorExpiredToken:
		return true
	default:
		return false
	}
}

// AuthError represents an authentication error with type information
type AuthError struct {
	Type    AuthErrorType
	Message string
	Err     error
}

// Error implements the error interface
func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("auth error [%s]: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("auth error [%s]: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *AuthError) Unwrap() error {
	return e.Err
}

// NewAuthError creates a new authentication error
func NewAuthError(errorType AuthErrorType, message string, err error) *AuthError {
	return &AuthError{
		Type:    errorType,
		Message: message,
		Err:     err,
	}
}

// ClassifyAuthError attempts to classify an authentication error based on the error message
func ClassifyAuthError(errorMsg string) AuthErrorType {
	// Common patterns for different error types
	switch {
	case errorMsg == "Invalid or used token":
		return AuthErrorInvalidToken
	case errorMsg == "Token expired":
		return AuthErrorExpiredToken
	case errorMsg == "Authentication timeout":
		return AuthErrorTimeout
	default:
		return AuthErrorUnknown
	}
}