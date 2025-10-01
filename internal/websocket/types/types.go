// Package types defines core types and interfaces for the WebSocket client
package types

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"time"
)

// ConnectionState represents the current state of the WebSocket connection
type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateAuthenticating
	StateConnected
	StateDisconnecting
)

// String returns a human-readable string representation of the connection state
func (s ConnectionState) String() string {
	switch s {
	case StateDisconnected:
		return "disconnected"
	case StateConnecting:
		return "connecting"
	case StateAuthenticating:
		return "authenticating"
	case StateConnected:
		return "connected"
	case StateDisconnecting:
		return "disconnecting"
	default:
		return "unknown"
	}
}

// Message represents a WebSocket message with type and data
type Message struct {
	Type   string      `json:"type"`
	Data   interface{} `json:"data,omitempty"`
	CallID string      `json:"call_id,omitempty"`
	Event  string      `json:"event,omitempty"`
}

// AuthResult represents the result of an authentication attempt
type AuthResult struct {
	Success   bool   `json:"success"`
	ServerUID string `json:"server_uid,omitempty"`
	Error     string `json:"error,omitempty"`
}

// CallResponse represents a response to an RPC call
type CallResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// PendingCall represents a pending RPC call waiting for response
type PendingCall struct {
	ID       string
	Response chan CallResponse
	Timeout  *time.Timer
	Created  time.Time
}

// CommandResponse represents a response to a command (for compatibility)
type CommandResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// EventHandler is a function that handles incoming events
type EventHandler func(data json.RawMessage) (*CommandResponse, error)

// ConnectionConfig holds configuration for WebSocket connections
type ConnectionConfig struct {
	URL                     string
	HandshakeTimeout        time.Duration
	ReadTimeout             time.Duration
	WriteTimeout            time.Duration
	PingInterval            time.Duration
	AuthTimeout             time.Duration
	CallTimeout             time.Duration
	MessageBufferSize       int
	EnableCompression       bool
	AuthWaitForConfirmation bool
	TLSConfig               *tls.Config // For mTLS authentication
}

// DefaultConnectionConfig returns a configuration with sensible defaults
func DefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		HandshakeTimeout:        30 * time.Second,
		ReadTimeout:             2 * time.Minute,
		WriteTimeout:            30 * time.Second,
		PingInterval:            30 * time.Second,
		AuthTimeout:             30 * time.Second,
		CallTimeout:             30 * time.Second,
		MessageBufferSize:       100,
		EnableCompression:       true,
		AuthWaitForConfirmation: true,
	}
}

// Client defines the interface for a WebSocket client
type Client interface {
	// Connection management
	Connect(ctx context.Context) error
	Disconnect() error
	IsConnected() bool
	GetConnectionState() ConnectionState

	// Authentication
	Authenticate(ctx context.Context) error

	// Message handling
	Send(event string, data interface{}) error
	Emit(event string, data interface{}) error
	Call(event string, data interface{}) (map[string]interface{}, error)
	RegisterHandler(event string, handler EventHandler)

	// Compatibility methods
	SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error
	GetLastPongTime() time.Time
}

// Authenticator defines the interface for authentication handling
type Authenticator interface {
	Authenticate(ctx context.Context, sender MessageSender) (*AuthResult, error)
	HandleAuthResponse(msg map[string]interface{}) (*AuthResult, error)
}

// MessageSender defines the interface for sending messages
type MessageSender interface {
	SendMessage(msg interface{}) error
}

// MessageProcessor defines the interface for processing incoming messages
type MessageProcessor interface {
	ProcessMessage(msg map[string]interface{})
	RegisterHandler(event string, handler EventHandler)
	HandleCall(msg map[string]interface{})
	HandleResponse(msg map[string]interface{})
}

// ConnectionManager defines the interface for managing connections
type ConnectionManager interface {
	Connect(ctx context.Context, config *ConnectionConfig) error
	Disconnect() error
	IsConnected() bool
	GetState() ConnectionState
	Send(msg interface{}) error
	StartReading(ctx context.Context, msgChan chan<- map[string]interface{}) error
	StartPinging(ctx context.Context) error
}
