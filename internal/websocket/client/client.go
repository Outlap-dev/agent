// Package client provides a clean, modular WebSocket client implementation
package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/websocket/auth"
	"pulseup-agent-go/internal/websocket/message"
	"pulseup-agent-go/internal/websocket/retry"
	"pulseup-agent-go/internal/websocket/types"
	"pulseup-agent-go/pkg/logger"
)

// WebSocketClient is a modular WebSocket client with clean separation of concerns
type WebSocketClient struct {
	logger *logger.Logger
	config *ClientConfig

	// Core components
	connection          *Connection
	authenticator       *auth.Authenticator
	processor           *message.Processor
	retryManager        *retry.RetryManager
	onConnectedHandlers []func(context.Context, *WebSocketClient) error

	// Lifecycle management
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	closed    chan struct{}

	// Message channels
	incomingMsgs chan map[string]interface{}
}

// ClientConfig holds complete configuration for the WebSocket client
type ClientConfig struct {
	// Connection configuration
	Connection *types.ConnectionConfig `json:"connection" yaml:"connection"`

	// Authentication configuration
	Auth *auth.AuthConfig `json:"auth" yaml:"auth"`

	// Message processing configuration
	Message *message.ProcessorConfig `json:"message" yaml:"message"`

	// Retry configuration for connections
	ConnectionRetry *retry.ConnectionRetryConfig `json:"connection_retry" yaml:"connection_retry"`

	// Whether to enable automatic reconnection
	EnableAutoReconnect bool `json:"enable_auto_reconnect" yaml:"enable_auto_reconnect"`
}

// DefaultClientConfig returns a client configuration with sensible defaults
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Connection:          types.DefaultConnectionConfig(),
		Auth:                auth.DefaultAuthConfig(),
		Message:             message.DefaultProcessorConfig(),
		ConnectionRetry:     retry.DefaultConnectionRetryConfig(),
		EnableAutoReconnect: true,
	}
}

// NewWebSocketClient creates a new modular WebSocket client
func NewWebSocketClient(appConfig *config.Config, logger *logger.Logger) *WebSocketClient {
	clientConfig := DefaultClientConfig()

	// Override with app config values
	if appConfig != nil {
		clientConfig.Connection.URL = appConfig.WebSocketURL
		clientConfig.Auth.WaitForConfirmation = appConfig.AuthWaitForConfirmation
		clientConfig.Auth.RetryConfig.PermanentFailureCooldown = time.Duration(appConfig.AuthPermanentFailureCooldown) * time.Second
		clientConfig.EnableAutoReconnect = appConfig.ReconnectEnabled
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &WebSocketClient{
		logger:              logger.With("component", "websocket_client"),
		config:              clientConfig,
		ctx:                 ctx,
		cancel:              cancel,
		closed:              make(chan struct{}),
		incomingMsgs:        make(chan map[string]interface{}, clientConfig.Message.MaxPendingCalls),
		onConnectedHandlers: make([]func(context.Context, *WebSocketClient) error, 0),
	}

	// Initialize components
	client.connection = NewConnection(logger, clientConfig.Connection)
	client.authenticator = auth.NewAuthenticator(logger, clientConfig.Auth)
	client.processor = message.NewProcessor(logger, client.connection, clientConfig.Message)
	client.retryManager = retry.NewRetryManager(clientConfig.ConnectionRetry.Config)

	// Set up message processor callbacks
	client.setupMessageCallbacks()

	return client
}

// setupMessageCallbacks configures callbacks for different message types
func (c *WebSocketClient) setupMessageCallbacks() {
	// Authentication response handler
	c.processor.SetAuthResponseHandler(func(msg map[string]interface{}) error {
		_, err := c.authenticator.HandleAuthResponse(msg)
		return err
	})

	// Server message handler (connected, init_response)
	c.processor.SetServerMessageHandler(func(msg map[string]interface{}) error {
		msgType, _ := msg["type"].(string)
		data, _ := msg["data"].(map[string]interface{})

		switch msgType {
		case "connected":
			if serverUID, ok := data["server_uid"].(string); ok {
				c.logger.Info("Server connection confirmed", "server_uid", serverUID)
				c.connection.SetState(types.StateConnected)
			}

		case "init_response":
			if status, ok := data["status"].(string); ok {
				if status == "success" || status == "registered" {
					c.connection.SetState(types.StateConnected)
				}
			}
		}

		return nil
	})

	// Auth challenge handler
	c.processor.SetAuthChallengeHandler(func(msg map[string]interface{}) error {
		return c.authenticator.HandleAuthChallenge(msg, c.connection)
	})

	// Error message handler
	c.processor.SetErrorHandler(func(msg map[string]interface{}) error {
		data, ok := msg["data"].(map[string]interface{})
		if !ok {
			return nil
		}

		message, _ := data["message"].(string)
		c.logger.Error("Server error", "message", message)

		return nil
	})
}

// Connect establishes a WebSocket connection and authenticates
func (c *WebSocketClient) Connect(ctx context.Context) error {
	// Establish connection
	if err := c.connection.Connect(ctx, c.config.Connection); err != nil {
		return fmt.Errorf("failed to establish connection: %w", err)
	}

	// Start message processing
	if err := c.startMessageProcessing(ctx); err != nil {
		c.connection.Disconnect()
		return fmt.Errorf("failed to start message processing: %w", err)
	}

	// Authenticate
	if err := c.authenticate(ctx); err != nil {
		c.connection.Disconnect()
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.runOnConnectedHandlers(ctx)

	return nil
}

// Start begins the WebSocket client with optional auto-reconnect
func (c *WebSocketClient) Start(ctx context.Context) error {
	if c.config.EnableAutoReconnect {
		go c.connectionLoop(ctx)
		return nil
	} else {
		return c.Connect(ctx)
	}
}

// connectionLoop handles automatic reconnection with retry logic
func (c *WebSocketClient) connectionLoop(ctx context.Context) {
	defer close(c.closed)

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("Connection loop stopping due to context cancellation")
			return
		case <-c.ctx.Done():
			c.logger.Info("Connection loop stopping due to client shutdown")
			return
		default:
		}

		// Check if we should retry
		if !c.retryManager.ShouldRetry() {
			c.logger.Error("Maximum retry attempts reached, stopping connection loop")
			return
		}

		// Attempt connection
		err := c.Connect(ctx)
		if err == nil {
			// Connected successfully, reset retry manager
			c.retryManager.Reset()

			// Wait for connection to close, reconnection signal, or context to be done
			select {
			case <-ctx.Done():
				return
			case <-c.ctx.Done():
				return
			case <-c.connection.GetReconnectChannel():
				// Check if client is shutting down before attempting reconnect
				select {
				case <-c.ctx.Done():
					c.logger.Info("Client shutting down, ignoring reconnection signal")
					return
				default:
					c.logger.Info("Received reconnection signal due to connection failure")
					// Connection failed, will retry in next loop iteration
					continue
				}
			}
		} else {
			c.logger.Warn("WebSocket connection attempt failed", "error", err)
		}

		// Connection failed, wait before retry
		delay := c.retryManager.NextDelay()
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		case <-time.After(delay):
			continue
		}
	}
}

// startMessageProcessing begins reading and processing messages
func (c *WebSocketClient) startMessageProcessing(ctx context.Context) error {
	// Start reading messages from connection
	if err := c.connection.StartReading(ctx, c.incomingMsgs); err != nil {
		return fmt.Errorf("failed to start reading: %w", err)
	}

	// Start processing messages
	go c.messageProcessingLoop(ctx)

	// Start ping routine
	if err := c.connection.StartPinging(ctx); err != nil {
		return fmt.Errorf("failed to start pinging: %w", err)
	}

	return nil
}

// messageProcessingLoop processes incoming messages
func (c *WebSocketClient) messageProcessingLoop(ctx context.Context) {
	defer c.logger.Debug("Message processing loop stopped")

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.ctx.Done():
			return
		case msg := <-c.incomingMsgs:
			c.processor.ProcessMessage(msg)
		}
	}
}

// authenticate performs the authentication handshake
func (c *WebSocketClient) authenticate(ctx context.Context) error {
	c.connection.SetState(types.StateAuthenticating)

	result, err := c.authenticator.Authenticate(ctx, c.connection)
	if err != nil {
		return err
	}

	if result.Success {
		c.connection.SetState(types.StateConnected)
		return nil
	}

	// Create typed error for better handling
	errorType := types.ClassifyAuthError(result.Error)
	authErr := types.NewAuthError(errorType, result.Error, nil)

	// Log permanent failures more prominently
	if errorType.IsPermanent() {
		c.logger.Error("Permanent authentication failure - check your token configuration",
			"error", result.Error,
			"error_type", errorType,
			"next_retry", "1 hour")
	}

	return authErr
}

// Disconnect closes the WebSocket connection and shuts down the client
func (c *WebSocketClient) Disconnect() error {
	c.logger.Info("Disconnecting WebSocket client")

	c.closeOnce.Do(func() {
		c.cancel()
		c.connection.Disconnect()

		// Wait for shutdown with timeout
		select {
		case <-c.closed:
			c.logger.Info("WebSocket client shut down successfully")
		case <-time.After(5 * time.Second):
			c.logger.Warn("Client shutdown timeout")
		}
	})

	return nil
}

// Public API methods implementing the types.Client interface

// IsConnected returns true if the client is connected and authenticated
func (c *WebSocketClient) IsConnected() bool {
	return c.connection.IsConnected()
}

// GetConnectionState returns the current connection state
func (c *WebSocketClient) GetConnectionState() types.ConnectionState {
	return c.connection.GetState()
}

// Authenticate re-authenticates the connection (for manual retry)
func (c *WebSocketClient) Authenticate(ctx context.Context) error {
	return c.authenticate(ctx)
}

// Send sends an event message
func (c *WebSocketClient) Send(event string, data interface{}) error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected")
	}

	msg := types.Message{
		Type:  "event",
		Event: event,
		Data:  data,
	}

	return c.connection.Send(msg)
}

// Emit sends an event message (alias for Send)
func (c *WebSocketClient) Emit(event string, data interface{}) error {
	return c.Send(event, data)
}

// Call makes an RPC call and waits for response
func (c *WebSocketClient) Call(event string, data interface{}) (map[string]interface{}, error) {
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}

	// Generate call ID
	callID := fmt.Sprintf("call_%d", time.Now().UnixNano())

	// Create pending call
	call := &types.PendingCall{
		ID:       callID,
		Response: make(chan types.CallResponse, 1),
		Timeout:  time.NewTimer(c.config.Connection.CallTimeout),
		Created:  time.Now(),
	}

	// Register pending call
	if err := c.processor.RegisterPendingCall(callID, call); err != nil {
		return nil, fmt.Errorf("failed to register call: %w", err)
	}

	// Cleanup on exit
	defer func() {
		c.processor.UnregisterPendingCall(callID)
		call.Timeout.Stop()
	}()

	// Send call message
	msg := types.Message{
		Type:   "call",
		CallID: callID,
		Event:  event,
		Data:   data,
	}

	if err := c.connection.Send(msg); err != nil {
		return nil, fmt.Errorf("failed to send call: %w", err)
	}

	// Wait for response
	select {
	case response := <-call.Response:
		if response.Success {
			if response.Data == nil {
				return map[string]interface{}{}, nil
			}
			if result, ok := response.Data.(map[string]interface{}); ok {
				return result, nil
			}
			return nil, fmt.Errorf("unexpected call response type %T", response.Data)
		}
		return nil, fmt.Errorf("call failed: %s", response.Error)

	case <-call.Timeout.C:
		return nil, fmt.Errorf("call timeout after %v", c.config.Connection.CallTimeout)

	case <-c.ctx.Done():
		return nil, fmt.Errorf("client shutting down")
	}
}

// RegisterHandler registers an event handler
func (c *WebSocketClient) RegisterHandler(event string, handler types.EventHandler) {
	c.processor.RegisterHandler(event, handler)
}

// SendCallResponse sends a response to an incoming call (compatibility method)
func (c *WebSocketClient) SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error {
	response := types.Message{
		Type:   "response",
		CallID: callID,
		Data: map[string]interface{}{
			"success": success,
			"data":    data,
			"error":   errorMsg,
		},
	}

	return c.connection.Send(response)
}

// GetLastPongTime returns the timestamp of the last received pong
func (c *WebSocketClient) GetLastPongTime() time.Time {
	return c.connection.GetLastPongTime()
}

// Additional utility methods

// GetConfig returns the current client configuration
func (c *WebSocketClient) GetConfig() *ClientConfig {
	return c.config
}

// GetAuthenticator exposes the authenticator for wiring providers
func (c *WebSocketClient) GetAuthenticator() *auth.Authenticator {
	return c.authenticator
}

// GetStats returns connection and processing statistics
func (c *WebSocketClient) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"connection_state":    c.GetConnectionState().String(),
		"is_connected":        c.IsConnected(),
		"last_pong_time":      c.GetLastPongTime(),
		"pending_calls":       c.processor.GetPendingCallCount(),
		"registered_handlers": c.processor.GetRegisteredHandlers(),
		"retry_attempts":      c.retryManager.Attempts(),
		"auth_failure_count":  func() int { count, _ := c.authenticator.GetFailureInfo(); return count }(),
	}
}

// IsHealthy checks if the connection is healthy
func (c *WebSocketClient) IsHealthy() bool {
	if !c.IsConnected() {
		return false
	}

	// Check if connection is healthy (received pong recently)
	maxPongAge := c.config.Connection.PingInterval * 3
	return c.connection.IsHealthy(maxPongAge)
}

// SetCertificateProvider exposes a way to provide a certificate PEM for mTLS auth messages
// without leaking internal fields from the client package.
func (c *WebSocketClient) SetCertificateProvider(provider func() (string, error)) {
	if c.authenticator != nil {
		c.authenticator.SetCertificateProvider(provider)
	}
}

// Compatibility methods for backward compatibility

// ConnectWithReconnect is an alias for Start
func (c *WebSocketClient) ConnectWithReconnect(ctx context.Context) error {
	return c.Start(ctx)
}

func (c *WebSocketClient) RegisterOnConnected(handler func(context.Context, *WebSocketClient) error) {
	if handler == nil {
		return
	}
	c.onConnectedHandlers = append(c.onConnectedHandlers, handler)
}

func (c *WebSocketClient) runOnConnectedHandlers(ctx context.Context) {
	if len(c.onConnectedHandlers) == 0 {
		return
	}

	for _, handler := range c.onConnectedHandlers {
		h := handler
		go func() {
			if err := h(ctx, c); err != nil && c.logger != nil {
				c.logger.Error("OnConnected handler error", "error", err)
			}
		}()
	}
}

// GetConnectionStateString returns connection state as string (compatibility)
func (c *WebSocketClient) GetConnectionStateString() string {
	return c.connection.GetState().String()
}
