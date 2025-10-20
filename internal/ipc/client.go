// Package ipc provides the Unix socket client for the worker process
package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"pulseup-agent-go/pkg/logger"
)

// Client represents the IPC client running in the worker process
type Client struct {
	config *SocketConfig
	logger *logger.Logger
	conn   net.Conn
	connMu sync.RWMutex

	// Request tracking
	pendingMu       sync.RWMutex
	pendingRequests map[string]chan *PrivilegedResponse

	// Connection management
	connected    bool
	shutdown     chan struct{}
	shutdownOnce sync.Once
	wg           sync.WaitGroup

	// Reconnection
	reconnectDelay time.Duration
	maxRetries     int
}

// NewClient creates a new IPC client
func NewClient(config *SocketConfig, logger *logger.Logger) *Client {
	return &Client{
		config:          config,
		logger:          logger.With("component", "ipc_client"),
		pendingRequests: make(map[string]chan *PrivilegedResponse),
		shutdown:        make(chan struct{}),
		reconnectDelay:  5 * time.Second,
		maxRetries:      10,
	}
}

// Connect connects to the supervisor IPC server
func (c *Client) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to supervisor", "socket_path", c.config.SocketPath)

	// Connect to Unix socket
	conn, err := net.DialTimeout("unix", c.config.SocketPath, c.config.Timeout)
	if err != nil {
		return fmt.Errorf("failed to connect to supervisor socket: %w", err)
	}

	c.connMu.Lock()
	c.conn = conn
	c.connected = true
	c.connMu.Unlock()

	c.logger.Info("Connected to supervisor")

	// Start message handling
	c.wg.Add(1)
	go c.messageLoop(ctx)

	// Start heartbeat
	c.wg.Add(1)
	go c.heartbeatLoop(ctx)

	return nil
}

// ConnectWithRetry connects to the supervisor with automatic retry
func (c *Client) ConnectWithRetry(ctx context.Context) error {
	var lastErr error

	for attempt := 0; attempt < c.maxRetries; attempt++ {
		if err := c.Connect(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}

		c.logger.Warn("Failed to connect to supervisor, retrying",
			"attempt", attempt+1,
			"max_retries", c.maxRetries,
			"error", lastErr,
			"retry_delay", c.reconnectDelay,
		)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.reconnectDelay):
			continue
		}
	}

	return fmt.Errorf("failed to connect after %d attempts: %w", c.maxRetries, lastErr)
}

// Disconnect disconnects from the supervisor
func (c *Client) Disconnect() error {
	c.logger.Info("Disconnecting from supervisor")

	c.shutdownOnce.Do(func() {
		close(c.shutdown)
	})

	c.connMu.Lock()
	if c.conn != nil {
		// Send shutdown message
		shutdownMsg := Message{
			Type: string(MessageTypeShutdown),
			Data: json.RawMessage(`{}`),
		}
		json.NewEncoder(c.conn).Encode(shutdownMsg)

		c.conn.Close()
		c.conn = nil
		c.connected = false
	}
	c.connMu.Unlock()

	// Cancel all pending requests
	c.pendingMu.Lock()
	for id, ch := range c.pendingRequests {
		close(ch)
		delete(c.pendingRequests, id)
	}
	c.pendingMu.Unlock()

	// Wait for goroutines to finish
	c.wg.Wait()

	c.logger.Info("Disconnected from supervisor")
	return nil
}

// reconnect attempts to reconnect to the supervisor
func (c *Client) reconnect(ctx context.Context) error {
	c.connMu.Lock()
	// Close existing connection if any
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
		c.connected = false
	}
	c.connMu.Unlock()

	// Attempt to reconnect
	return c.Connect(ctx)
}

// IsConnected returns true if connected to the supervisor
func (c *Client) IsConnected() bool {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.connected
}

// SendPrivilegedRequest sends a privileged request to the supervisor
func (c *Client) SendPrivilegedRequest(ctx context.Context, operation OperationType, args map[string]interface{}) (*PrivilegedResponse, error) {
	// Check if connected
	if !c.IsConnected() {
		return nil, fmt.Errorf("not connected to supervisor")
	}

	// Generate request ID
	requestID := fmt.Sprintf("req_%d_%d", os.Getpid(), time.Now().UnixNano())

	// Create request
	request := &PrivilegedRequest{
		ID:        requestID,
		Operation: string(operation),
		Args:      args,
		Timestamp: time.Now(),
		WorkerPID: os.Getpid(),
	}

	c.logger.Debug("Sending privileged request",
		"request_id", requestID,
		"operation", operation,
	)

	// Create response channel
	responseCh := make(chan *PrivilegedResponse, 1)

	// Register pending request
	c.pendingMu.Lock()
	c.pendingRequests[requestID] = responseCh
	c.pendingMu.Unlock()

	// Clean up when done
	defer func() {
		c.pendingMu.Lock()
		delete(c.pendingRequests, requestID)
		c.pendingMu.Unlock()
	}()

	// Send request
	msg := Message{
		Type: string(MessageTypeRequest),
		Data: c.encodeRequest(request),
	}

	if err := c.sendMessage(&msg); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Wait for response
	select {
	case response := <-responseCh:
		if response == nil {
			return nil, fmt.Errorf("connection closed while waiting for response")
		}

		c.logger.Debug("Received privileged response",
			"request_id", requestID,
			"success", response.Success,
			"took", response.Took,
		)

		return response, nil

	case <-ctx.Done():
		return nil, fmt.Errorf("request cancelled: %w", ctx.Err())

	case <-c.shutdown:
		return nil, fmt.Errorf("client shutting down")
	}
}

// SendHeartbeat sends a heartbeat to the supervisor
func (c *Client) SendHeartbeat() error {
	if !c.IsConnected() {
		return fmt.Errorf("not connected to supervisor")
	}

	heartbeat := HeartbeatMessage{
		ProcessType: "worker",
		PID:         os.Getpid(),
		Timestamp:   time.Now(),
		Status:      "healthy",
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat: %w", err)
	}

	msg := Message{
		Type: string(MessageTypeHeartbeat),
		Data: data,
	}

	return c.sendMessage(&msg)
}

// sendMessage sends a message to the supervisor
func (c *Client) sendMessage(msg *Message) error {
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	// Set write timeout
	conn.SetWriteDeadline(time.Now().Add(c.config.Timeout))

	// Send message
	encoder := json.NewEncoder(conn)
	return encoder.Encode(msg)
}

// messageLoop handles incoming messages from the supervisor
func (c *Client) messageLoop(ctx context.Context) {
	defer c.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.shutdown:
			return
		default:
		}

		c.connMu.RLock()
		conn := c.conn
		c.connMu.RUnlock()

		if conn == nil {
			return
		}

		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(c.config.Timeout))

		// Read message
		var msg Message
		decoder := json.NewDecoder(conn)
		if err := decoder.Decode(&msg); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // timeout is expected for keep-alive
			}

			c.logger.Debug("Connection closed or read error", "error", err)

			// Mark as disconnected
			c.connMu.Lock()
			c.connected = false
			c.connMu.Unlock()

			return
		}

		// Handle message
		c.handleMessage(&msg)
	}
}

// handleMessage handles an incoming message from the supervisor
func (c *Client) handleMessage(msg *Message) {
	switch MessageType(msg.Type) {
	case MessageTypeResponse:
		c.handleResponse(msg.Data)
	case MessageTypeHeartbeat:
		c.handleHeartbeatResponse(msg.Data)
	default:
		c.logger.Warn("Unknown message type from supervisor", "type", msg.Type)
	}
}

// handleResponse handles a response message
func (c *Client) handleResponse(data json.RawMessage) {
	var response PrivilegedResponse
	if err := json.Unmarshal(data, &response); err != nil {
		c.logger.Error("Failed to parse response", "error", err)
		return
	}

	// Find pending request
	c.pendingMu.RLock()
	responseCh, exists := c.pendingRequests[response.ID]
	c.pendingMu.RUnlock()

	if !exists {
		c.logger.Warn("Received response for unknown request", "request_id", response.ID)
		return
	}

	// Send response to waiting goroutine
	select {
	case responseCh <- &response:
	default:
		c.logger.Warn("Response channel full", "request_id", response.ID)
	}
}

// handleHeartbeatResponse handles a heartbeat response
func (c *Client) handleHeartbeatResponse(data json.RawMessage) {
	var heartbeat HeartbeatMessage
	if err := json.Unmarshal(data, &heartbeat); err != nil {
		c.logger.Warn("Failed to parse heartbeat response", "error", err)
		return
	}

	c.logger.Debug("Received heartbeat response",
		"supervisor_pid", heartbeat.PID,
		"status", heartbeat.Status,
	)
}

// heartbeatLoop sends periodic heartbeats to the supervisor
func (c *Client) heartbeatLoop(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.shutdown:
			return
		case <-ticker.C:
			if err := c.SendHeartbeat(); err != nil {
				c.logger.Warn("Failed to send heartbeat", "error", err)

				// If not connected, attempt to reconnect
				if !c.IsConnected() {
					c.logger.Info("Attempting to reconnect to supervisor")
					if reconnectErr := c.reconnect(ctx); reconnectErr != nil {
						c.logger.Error("Failed to reconnect to supervisor", "error", reconnectErr)
					}
				}
			}
		}
	}
}

// encodeRequest encodes a request to JSON
func (c *Client) encodeRequest(request *PrivilegedRequest) json.RawMessage {
	data, err := json.Marshal(request)
	if err != nil {
		c.logger.Error("Failed to encode request", "error", err)
		return json.RawMessage(`{}`)
	}
	return data
}

// Convenience methods for common operations

// AgentUpdate requests updating the agent
func (c *Client) AgentUpdate(ctx context.Context, updateFilePath string, signature string) (*PrivilegedResponse, error) {
	args := map[string]interface{}{
		"update_file_path": updateFilePath,
	}
	if signature != "" {
		args["signature"] = signature
	}
	return c.SendPrivilegedRequest(ctx, OpAgentUpdate, args)
}

// GetStats returns client statistics
func (c *Client) GetStats() map[string]interface{} {
	c.pendingMu.RLock()
	pendingCount := len(c.pendingRequests)
	c.pendingMu.RUnlock()

	return map[string]interface{}{
		"connected":        c.IsConnected(),
		"pending_requests": pendingCount,
		"socket_path":      c.config.SocketPath,
	}
}
