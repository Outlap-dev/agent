// Package websocket provides a modern WebSocket client for agent communication
//
// This package provides a clean, modular WebSocket client implementation
// with proper connection management, authentication, and message routing.
package websocket

import (
	"context"
	"encoding/json"
	"time"

	"outlap-agent-go/internal/config"
	"outlap-agent-go/internal/websocket/client"
	"outlap-agent-go/internal/websocket/types"
	"outlap-agent-go/pkg/logger"
	pkgTypes "outlap-agent-go/pkg/types"
)

// Manager provides a high-level interface to the modular WebSocket client
type Manager struct {
	client *client.WebSocketClient
	logger *logger.Logger
}

// NewManager creates a new WebSocket manager using the modular client
func NewManager(config *config.Config, logger *logger.Logger) *Manager {
	return &Manager{
		client: client.NewWebSocketClient(config, logger),
		logger: logger.With("component", "websocket_manager"),
	}
}

// Start starts the WebSocket client with automatic reconnection
func (m *Manager) Start(ctx context.Context) error {
	return m.client.Start(ctx)
}

// ConnectWithReconnect is an alias for Start
func (m *Manager) ConnectWithReconnect(ctx context.Context) error {
	return m.Start(ctx)
}

// Connect establishes a single connection without auto-reconnect
func (m *Manager) Connect(ctx context.Context) error {
	m.logger.Info("Connecting to WebSocket server (single connection)")
	return m.client.Connect(ctx)
}

// Disconnect closes the WebSocket connection and shuts down the client
func (m *Manager) Disconnect() error {
	m.logger.Info("Disconnecting WebSocket manager")
	return m.client.Disconnect()
}

// Send sends an event message via WebSocket
func (m *Manager) Send(event string, data interface{}) error {
	return m.client.Send(event, data)
}

// Emit sends an event message via WebSocket (alias for Send)
func (m *Manager) Emit(event string, data interface{}) error {
	return m.client.Emit(event, data)
}

// Call makes a synchronous RPC call and waits for a response
func (m *Manager) Call(event string, data interface{}) (map[string]interface{}, error) {
	return m.client.Call(event, data)
}

// SendCallResponse sends a response to an incoming RPC call
func (m *Manager) SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error {
	return m.client.SendCallResponse(callID, success, data, errorMsg)
}

// IsConnected returns true if the WebSocket is connected and authenticated
func (m *Manager) IsConnected() bool {
	return m.client.IsConnected()
}

// GetConnectionState returns the current connection state as a string
func (m *Manager) GetConnectionState() string {
	return m.client.GetConnectionState().String()
}

// GetLastPongTime returns the timestamp of the last received pong message
func (m *Manager) GetLastPongTime() time.Time {
	return m.client.GetLastPongTime()
}

// RegisterHandler registers an event handler for incoming messages
//
// The handler function will be called when a message with the specified event name is received.
// For RPC calls (messages with call_id), the handler's response will be sent back automatically.
func (m *Manager) RegisterHandler(event string, handler func(data json.RawMessage) (*pkgTypes.CommandResponse, error)) {
	// Wrap the handler to match the new interface
	wrappedHandler := func(data json.RawMessage) (*types.CommandResponse, error) {
		response, err := handler(data)
		if err != nil {
			return nil, err
		}

		if response == nil {
			return nil, nil
		}

		return &types.CommandResponse{
			Success: response.Success,
			Data:    response.Data,
			Error:   response.Error,
		}, nil
	}

	m.client.RegisterHandler(event, wrappedHandler)
}

// Advanced methods for monitoring and debugging

// GetClient returns the underlying modular client for advanced usage
func (m *Manager) GetClient() *client.WebSocketClient {
	return m.client
}

// SetCertificateProvider wires a certificate provider for auth
func (m *Manager) SetCertificateProvider(provider func() (string, error)) {
	m.client.SetCertificateProvider(provider)
}

// SetSigner wires a signer function for challenge-based auth
func (m *Manager) SetSigner(provider func([]byte) (string, error)) {
	if m.client != nil {
		// Extend client to support signer provider
		// Expose through authenticator
		m.client.GetAuthenticator().SetSignProvider(provider)
	}
}

// GetStats returns detailed statistics about the connection and client
func (m *Manager) GetStats() map[string]interface{} {
	return m.client.GetStats()
}

// IsHealthy checks if the connection is healthy based on recent pong responses
func (m *Manager) IsHealthy() bool {
	return m.client.IsHealthy()
}

// GetConfig returns the current client configuration
func (m *Manager) GetConfig() *client.ClientConfig {
	return m.client.GetConfig()
}

// Connection state constants for convenience
const (
	StateDisconnected   = types.StateDisconnected
	StateConnecting     = types.StateConnecting
	StateAuthenticating = types.StateAuthenticating
	StateConnected      = types.StateConnected
	StateDisconnecting  = types.StateDisconnecting
)

// Type aliases for convenience
type (
	ConnectionState = types.ConnectionState
	AuthResult      = types.AuthResult
	CallResponse    = types.CallResponse
	Message         = types.Message
)
