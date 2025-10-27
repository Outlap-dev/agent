// Package client provides WebSocket connection management
package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"outlap-agent-go/internal/websocket/types"
	"outlap-agent-go/pkg/logger"

	"github.com/gorilla/websocket"
)

// Connection manages a single WebSocket connection
type Connection struct {
	logger  *logger.Logger
	config  *types.ConnectionConfig
	conn    *websocket.Conn
	connMu  sync.RWMutex
	state   types.ConnectionState
	stateMu sync.RWMutex
	writeMu sync.Mutex

	// Connection health tracking
	lastPongTime time.Time
	pongMu       sync.RWMutex

	// Lifecycle management
	closeOnce sync.Once
	closed    chan struct{}

	// Reconnection signaling
	reconnectCh chan struct{}
}

// NewConnection creates a new WebSocket connection manager
func NewConnection(logger *logger.Logger, config *types.ConnectionConfig) *Connection {
	if config == nil {
		config = types.DefaultConnectionConfig()
	}

	return &Connection{
		logger:       logger.With("component", "websocket_connection"),
		config:       config,
		state:        types.StateDisconnected,
		lastPongTime: time.Now(),
		closed:       make(chan struct{}),
		reconnectCh:  make(chan struct{}, 1),
	}
}

// Connect establishes a WebSocket connection
func (c *Connection) Connect(ctx context.Context, config *types.ConnectionConfig) error {
	if config != nil {
		c.config = config
	}

	c.setState(types.StateConnecting)

	// Configure dialer
	dialer := websocket.Dialer{
		HandshakeTimeout:  c.config.HandshakeTimeout,
		EnableCompression: c.config.EnableCompression,
		ReadBufferSize:    4096,
		WriteBufferSize:   4096,
	}

	// Configure TLS if certificate is provided
	if c.config.TLSConfig != nil {
		dialer.TLSClientConfig = c.config.TLSConfig
	}

	// Establish connection
	conn, _, err := dialer.Dial(c.config.URL, nil)
	if err != nil {
		c.setState(types.StateDisconnected)
		return fmt.Errorf("failed to dial WebSocket: %w", err)
	}

	// Set up connection handlers
	c.setupConnectionHandlers(conn)

	// Store connection
	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	c.updatePongTime()
	c.setState(types.StateConnected)

	return nil
}

// setupConnectionHandlers configures WebSocket connection event handlers
func (c *Connection) setupConnectionHandlers(conn *websocket.Conn) {
	// Pong handler for keepalive
	conn.SetPongHandler(func(string) error {
		c.updatePongTime()
		return nil
	})

	// Close handler
	conn.SetCloseHandler(func(code int, text string) error {
		c.logger.Info("WebSocket connection closed by sFerver", "code", code, "text", text)
		return nil
	})
}

// Disconnect closes the WebSocket connection
func (c *Connection) Disconnect() error {
	c.logger.Info("Disconnecting WebSocket connection")

	c.closeOnce.Do(func() {
		c.setState(types.StateDisconnecting)

		c.connMu.Lock()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.connMu.Unlock()

		c.setState(types.StateDisconnected)
		close(c.closed)
	})

	return nil
}

// IsConnected returns true if the connection is established and healthy
func (c *Connection) IsConnected() bool {
	return c.getState() == types.StateConnected
}

// GetState returns the current connection state
func (c *Connection) GetState() types.ConnectionState {
	return c.getState()
}

// Send sends a message over the WebSocket connection
func (c *Connection) Send(msg interface{}) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	conn := c.getConnection()
	if conn == nil {
		return fmt.Errorf("connection not available")
	}

	// Set write deadline
	conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))

	return conn.WriteJSON(msg)
}

// SendMessage implements the MessageSender interface
func (c *Connection) SendMessage(msg interface{}) error {
	return c.Send(msg)
}

// StartReading begins reading messages from the WebSocket connection
func (c *Connection) StartReading(ctx context.Context, msgChan chan<- map[string]interface{}) error {
	go func() {
		defer c.logger.Debug("WebSocket message reader stopped")

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.closed:
				return
			default:
			}

			conn := c.getConnection()
			if conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Set read deadline
			conn.SetReadDeadline(time.Now().Add(c.config.ReadTimeout))

			var msg map[string]interface{}
			if err := conn.ReadJSON(&msg); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.logger.Error("WebSocket read error", "error", err)
				} else {
					c.logger.Debug("WebSocket connection closed", "error", err)
				}
				// Connection failed - trigger reconnection
				c.setState(types.StateDisconnected)
				c.triggerReconnection()
				return
			}

			// Send message to processor
			select {
			case msgChan <- msg:
			case <-ctx.Done():
				return
			case <-c.closed:
				return
			default:
				c.logger.Warn("Message channel full, dropping message")
			}
		}
	}()

	return nil
}

// StartPinging begins sending periodic ping messages
func (c *Connection) StartPinging(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(c.config.PingInterval)
		defer ticker.Stop()
		defer c.logger.Debug("WebSocket ping routine stopped")

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.closed:
				return
			case <-ticker.C:
				if c.getState() != types.StateConnected {
					continue
				}

				conn := c.getConnection()
				if conn == nil {
					continue
				}

				// Use write mutex to prevent concurrent writes
				c.writeMu.Lock()
				if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
					c.writeMu.Unlock()
					c.logger.Error("Failed to set write deadline", "error", err)
					continue
				}
				if err := conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
					c.writeMu.Unlock()
					c.logger.Error("Failed to send ping", "error", err)
					// Ping failure indicates connection is broken - trigger disconnection
					c.setState(types.StateDisconnected)
					c.triggerReconnection()
					return
				}
				c.writeMu.Unlock()
			}
		}
	}()

	return nil
}

// GetLastPongTime returns the timestamp of the last received pong
func (c *Connection) GetLastPongTime() time.Time {
	c.pongMu.RLock()
	defer c.pongMu.RUnlock()
	return c.lastPongTime
}

// IsHealthy checks if the connection is healthy based on recent pong responses
func (c *Connection) IsHealthy(maxPongAge time.Duration) bool {
	if !c.IsConnected() {
		return false
	}

	return time.Since(c.GetLastPongTime()) <= maxPongAge
}

// SetState sets the connection state (used by the client)
func (c *Connection) SetState(state types.ConnectionState) {
	c.setState(state)
}

// Helper methods

func (c *Connection) getConnection() *websocket.Conn {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.conn
}

func (c *Connection) setState(state types.ConnectionState) {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	if c.state != state {
		oldState := c.state
		c.state = state
		c.logger.Debug("Connection state changed", "from", oldState.String(), "to", state.String())
	}
}

func (c *Connection) getState() types.ConnectionState {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.state
}

func (c *Connection) updatePongTime() {
	c.pongMu.Lock()
	defer c.pongMu.Unlock()
	c.lastPongTime = time.Now()
}

// triggerReconnection signals that a reconnection should be attempted
func (c *Connection) triggerReconnection() {
	select {
	case c.reconnectCh <- struct{}{}:
		c.logger.Info("Reconnection triggered due to connection failure")
	default:
		// Channel already has a signal, no need to add another
	}
}

// GetReconnectChannel returns the channel for listening to reconnection signals
func (c *Connection) GetReconnectChannel() <-chan struct{} {
	return c.reconnectCh
}
