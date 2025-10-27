package testws

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"outlap-agent-go/pkg/logger"

	"github.com/gorilla/websocket"
)

// TestWebSocketServer is a simple websocket server for testing
type TestWebSocketServer struct {
	addr       string
	actualAddr string // The actual listening address after binding
	logger     *logger.Logger
	server     *http.Server
	listener   net.Listener
	upgrader   websocket.Upgrader
	clients    map[*websocket.Conn]*Client
	clientMu   sync.RWMutex

	// Authentication (mTLS challenge/response)
	authTimeout time.Duration     // Time to wait for auth before dropping connection
	authNonces  map[string]string // client -> nonce mapping for auth challenges

	// Message handlers
	handlers      map[string]func(*Client, json.RawMessage) error
	eventHandlers map[string]func(*Client, map[string]interface{}) error

	// Shutdown
	shutdown chan struct{}
	done     chan struct{}
	// Ensures shutdown channel only closed once
	shutdownOnce sync.Once
}

// Client represents a connected websocket client
type Client struct {
	conn          *websocket.Conn
	server        *TestWebSocketServer
	authenticated bool
	clientID      string
	sendCh        chan []byte
	done          chan struct{}
	authTimer     *time.Timer
}

// AuthProofMessage represents an mTLS authentication proof
type AuthProofMessage struct {
	Type string                 `json:"type"`
	Data map[string]interface{} `json:"data"`
}

// CallMessage represents a call-based message
type CallMessage struct {
	Type   string          `json:"type"`
	CallID string          `json:"call_id"`
	Event  string          `json:"event"`
	Data   json.RawMessage `json:"data"`
}

// ResponseMessage represents a response message
type ResponseMessage struct {
	Type    string      `json:"type"`
	CallID  string      `json:"call_id,omitempty"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// ServerMessage represents server status messages
type ServerMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// NewTestWebSocketServer creates a new test websocket server
func NewTestWebSocketServer(addr string, logger *logger.Logger) *TestWebSocketServer {
	return NewTestWebSocketServerWithTimeout(addr, 10*time.Second, logger)
}

// NewTestWebSocketServerWithTimeout creates a new test websocket server with custom auth timeout
func NewTestWebSocketServerWithTimeout(addr string, authTimeout time.Duration, logger *logger.Logger) *TestWebSocketServer {
	return &TestWebSocketServer{
		addr:        addr,
		logger:      logger.With("component", "test_websocket_server"),
		authTimeout: authTimeout,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for testing
			},
		},
		clients:       make(map[*websocket.Conn]*Client),
		authNonces:    make(map[string]string),
		handlers:      make(map[string]func(*Client, json.RawMessage) error),
		eventHandlers: make(map[string]func(*Client, map[string]interface{}) error),
		shutdown:      make(chan struct{}),
		done:          make(chan struct{}),
	}
}

// RegisterHandler registers a message handler for an event
func (s *TestWebSocketServer) RegisterHandler(event string, handler func(*Client, json.RawMessage) error) {
	s.handlers[event] = handler
}

// RegisterEventHandler registers a handler for fire-and-forget events
func (s *TestWebSocketServer) RegisterEventHandler(event string, handler func(*Client, map[string]interface{}) error) {
	s.eventHandlers[event] = handler
}

// Start starts the websocket server
func (s *TestWebSocketServer) Start(ctx context.Context) error {
	// Create a listener to get the actual port
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	s.listener = listener
	s.actualAddr = listener.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleWebSocket)

	s.server = &http.Server{
		Handler: mux,
	}

	s.logger.Info("Starting test WebSocket server", "addr", s.addr, "actual_addr", s.actualAddr)

	go func() {
		defer close(s.done)
		if err := s.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Server error", "error", err)
		}
	}()

	// Wait for shutdown signal
	go func() {
		select {
		case <-ctx.Done():
			s.logger.Info("Context cancelled, shutting down server")
			s.Stop()
		case <-s.shutdown:
			s.logger.Info("Shutdown signal received")
		}
	}()

	return nil
}

// Stop stops the websocket server
func (s *TestWebSocketServer) Stop() error {
	s.logger.Info("Stopping test WebSocket server")

	// Close all client connections
	s.clientMu.Lock()
	for conn, client := range s.clients {
		select {
		case <-client.done:
			// Channel already closed
		default:
			close(client.done)
		}
		conn.Close()
	}
	s.clients = make(map[*websocket.Conn]*Client)
	s.clientMu.Unlock()

	// Shutdown HTTP server
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.server.Shutdown(ctx); err != nil {
			s.logger.Error("Error shutting down server", "error", err)
			return err
		}
	}

	// Close listener if still open
	if s.listener != nil {
		s.listener.Close()
	}

	s.shutdownOnce.Do(func() {
		close(s.shutdown)
	})
	return nil
}

// Wait waits for the server to finish
func (s *TestWebSocketServer) Wait() {
	<-s.done
}

// GetURL returns the WebSocket URL for this server
func (s *TestWebSocketServer) GetURL() string {
	if s.actualAddr != "" {
		return fmt.Sprintf("ws://%s/", s.actualAddr)
	}
	return fmt.Sprintf("ws://%s/", s.addr)
}

// BroadcastToAll broadcasts a message to all authenticated clients
func (s *TestWebSocketServer) BroadcastToAll(msgType string, data interface{}) {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()

	message := ServerMessage{
		Type: msgType,
		Data: data,
	}

	msgBytes, err := json.Marshal(message)
	if err != nil {
		s.logger.Error("Failed to marshal broadcast message", "error", err)
		return
	}

	for _, client := range s.clients {
		if client.authenticated {
			select {
			case client.sendCh <- msgBytes:
			default:
				s.logger.Warn("Client send channel full, skipping message", "client", client.clientID)
			}
		}
	}
}

// BroadcastRawMessage broadcasts a raw JSON message to all authenticated clients
func (s *TestWebSocketServer) BroadcastRawMessage(message interface{}) {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()

	msgBytes, err := json.Marshal(message)
	if err != nil {
		s.logger.Error("Failed to marshal raw broadcast message", "error", err)
		return
	}

	for _, client := range s.clients {
		if client.authenticated {
			select {
			case client.sendCh <- msgBytes:
			default:
				s.logger.Warn("Client send channel full, skipping message", "client", client.clientID)
			}
		}
	}
}

// SendToClient sends a message to a specific client
func (s *TestWebSocketServer) SendToClient(clientID string, msgType string, data interface{}) error {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()

	for _, client := range s.clients {
		if client.clientID == clientID && client.authenticated {
			message := ServerMessage{
				Type: msgType,
				Data: data,
			}

			msgBytes, err := json.Marshal(message)
			if err != nil {
				return fmt.Errorf("failed to marshal message: %w", err)
			}

			select {
			case client.sendCh <- msgBytes:
				return nil
			default:
				return fmt.Errorf("client send channel full")
			}
		}
	}

	return fmt.Errorf("client not found: %s", clientID)
}

// handleWebSocket handles incoming websocket connections
func (s *TestWebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error("Failed to upgrade connection", "error", err)
		return
	}

	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())
	client := &Client{
		conn:     conn,
		server:   s,
		clientID: clientID,
		sendCh:   make(chan []byte, 256),
		done:     make(chan struct{}),
	}

	// Set up auth timeout timer
	client.authTimer = time.AfterFunc(s.authTimeout, func() {
		if !client.authenticated {
			s.logger.Warn("Client failed to authenticate within timeout, disconnecting",
				"client_id", clientID, "timeout", s.authTimeout)
			client.forceDisconnect()
		}
	})

	s.clientMu.Lock()
	s.clients[conn] = client
	s.clientMu.Unlock()

	// Send auth challenge immediately
	client.sendAuthChallenge()

	// Start client goroutines
	go client.writePump()
	go client.readPump()
}

// readPump handles reading messages from the websocket connection
func (c *Client) readPump() {
	defer func() {
		// Stop auth timer if still running
		if c.authTimer != nil {
			c.authTimer.Stop()
		}
		c.server.removeClient(c.conn)
		c.conn.Close()
		select {
		case <-c.done:
			// Channel already closed
		default:
			close(c.done)
		}
	}()

	c.conn.SetReadLimit(512 * 1024) // 512KB
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		select {
		case <-c.done:
			return
		default:
			_, message, err := c.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					c.server.logger.Error("WebSocket read error", "error", err, "client", c.clientID)
				}
				return
			}

			if err := c.handleMessage(message); err != nil {
				c.server.logger.Error("Failed to handle message", "error", err, "client", c.clientID)
			}
		}
	}
}

// writePump handles writing messages to the websocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case <-c.done:
			return
		case message, ok := <-c.sendCh:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				c.server.logger.Error("Failed to write message", "error", err, "client", c.clientID)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage handles incoming messages from the client
func (c *Client) handleMessage(message []byte) error {
	c.server.logger.Debug("Received message", "client", c.clientID, "message", string(message))

	// Parse message to determine type
	var rawMsg map[string]interface{}
	if err := json.Unmarshal(message, &rawMsg); err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	msgType, hasType := rawMsg["type"].(string)
	if !hasType {
		return fmt.Errorf("message missing type field")
	}

	switch msgType {
	case "auth_proof":
		return c.handleAuthProof(message)
	case "call":
		if !c.authenticated {
			return fmt.Errorf("client not authenticated")
		}
		return c.handleCall(message)
	case "event":
		if !c.authenticated {
			return fmt.Errorf("client not authenticated")
		}
		eventName, _ := rawMsg["event"].(string)
		payload := map[string]interface{}{}
		if data, ok := rawMsg["data"].(map[string]interface{}); ok {
			payload = data
		}
		return c.handleEvent(eventName, payload)
	default:
		return fmt.Errorf("unknown message type: %s", msgType)
	}
}

// sendAuthChallenge sends an mTLS authentication challenge
func (c *Client) sendAuthChallenge() {
	// Generate a random nonce
	nonce := fmt.Sprintf("nonce_%d_%s", time.Now().UnixNano(), c.clientID)

	// Store nonce for validation
	c.server.clientMu.Lock()
	c.server.authNonces[c.clientID] = nonce
	c.server.clientMu.Unlock()

	// Send auth challenge
	challenge := ServerMessage{
		Type: "auth_challenge",
		Data: map[string]interface{}{
			"nonce": nonce,
		},
	}

	respBytes, err := json.Marshal(challenge)
	if err != nil {
		c.server.logger.Error("Failed to marshal auth challenge", "error", err, "client", c.clientID)
		return
	}

	select {
	case c.sendCh <- respBytes:
		c.server.logger.Debug("Sent auth challenge", "client", c.clientID, "nonce", nonce)
	default:
		c.server.logger.Error("Failed to send auth challenge: channel full", "client", c.clientID)
	}
}

// handleAuthProof handles mTLS authentication proof messages
func (c *Client) handleAuthProof(message []byte) error {
	var authMsg AuthProofMessage
	if err := json.Unmarshal(message, &authMsg); err != nil {
		return fmt.Errorf("failed to parse auth proof message: %w", err)
	}

	// Extract data fields
	data, ok := authMsg.Data["data"].(map[string]interface{})
	if !ok {
		data = authMsg.Data
	}

	method, _ := data["method"].(string)
	certificate, _ := data["certificate"].(string)
	signature, _ := data["signature"].(string)
	nonce, _ := data["nonce"].(string)

	// Validate method
	if method != "mtls" {
		return c.sendAuthResponse(false, "", "unsupported auth method")
	}

	// Validate nonce
	c.server.clientMu.RLock()
	expectedNonce, exists := c.server.authNonces[c.clientID]
	c.server.clientMu.RUnlock()

	if !exists || nonce != expectedNonce {
		return c.sendAuthResponse(false, "", "invalid nonce")
	}

	// Basic validation (in real implementation, verify certificate and signature)
	if certificate == "" || signature == "" {
		return c.sendAuthResponse(false, "", "missing certificate or signature")
	}

	// Mark as authenticated
	c.authenticated = true

	// Stop the auth timeout timer
	if c.authTimer != nil {
		c.authTimer.Stop()
		c.authTimer = nil
	}

	// Clean up nonce
	c.server.clientMu.Lock()
	delete(c.server.authNonces, c.clientID)
	c.server.clientMu.Unlock()

	c.server.logger.Info("Client authenticated successfully via mTLS", "client", c.clientID)

	// Send auth response
	return c.sendAuthResponse(true, "test-server-123", "")
}

// sendAuthResponse sends an authentication response
func (c *Client) sendAuthResponse(success bool, serverUID, errorMsg string) error {
	response := ServerMessage{
		Type: "auth_response",
		Data: map[string]interface{}{
			"success": success,
		},
	}

	if success {
		response.Data.(map[string]interface{})["server_uid"] = serverUID
	} else {
		response.Data.(map[string]interface{})["error"] = errorMsg
	}

	respBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal auth response: %w", err)
	}

	select {
	case c.sendCh <- respBytes:
		if success {
			// Also send connected message for compatibility
			connected := ServerMessage{
				Type: "connected",
				Data: map[string]interface{}{
					"server_uid": serverUID,
					"status":     "connected",
				},
			}
			if connBytes, err := json.Marshal(connected); err == nil {
				select {
				case c.sendCh <- connBytes:
				default:
				}
			}
		}
		return nil
	default:
		return fmt.Errorf("failed to send auth response: channel full")
	}
}

// handleCall handles call-based messages
func (c *Client) handleCall(message []byte) error {
	var callMsg CallMessage
	if err := json.Unmarshal(message, &callMsg); err != nil {
		return fmt.Errorf("failed to parse call message: %w", err)
	}

	c.server.logger.Debug("Handling call", "event", callMsg.Event, "call_id", callMsg.CallID, "client", c.clientID)

	// Check if we have a handler for this event
	handler, exists := c.server.handlers[callMsg.Event]
	if !exists {
		// Send error response
		response := ResponseMessage{
			Type:    "response",
			CallID:  callMsg.CallID,
			Success: false,
			Error:   fmt.Sprintf("unknown event: %s", callMsg.Event),
		}
		return c.sendResponse(response)
	}

	// Call the handler
	if err := handler(c, callMsg.Data); err != nil {
		response := ResponseMessage{
			Type:    "response",
			CallID:  callMsg.CallID,
			Success: false,
			Error:   err.Error(),
		}
		return c.sendResponse(response)
	}

	// Send success response (handlers can override by sending their own response)
	response := ResponseMessage{
		Type:    "response",
		CallID:  callMsg.CallID,
		Success: true,
		Data:    map[string]interface{}{"status": "ok"},
	}
	return c.sendResponse(response)
}

func (c *Client) handleEvent(event string, data map[string]interface{}) error {
	if event == "" {
		return fmt.Errorf("event message missing event name")
	}

	if handler, exists := c.server.eventHandlers[event]; exists {
		if err := handler(c, data); err != nil {
			resp := ResponseMessage{
				Type:    "response",
				Success: false,
				Error:   err.Error(),
			}
			_ = c.sendResponse(resp)
			return nil
		}
	}

	resp := ResponseMessage{
		Type:    "response",
		Success: true,
		Data: map[string]interface{}{
			"event":  event,
			"status": "ok",
		},
	}
	_ = c.sendResponse(resp)
	return nil
}

// sendResponse sends a response message to the client
func (c *Client) sendResponse(response ResponseMessage) error {
	respBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	select {
	case c.sendCh <- respBytes:
		return nil
	default:
		return fmt.Errorf("failed to send response: channel full")
	}
}

// SendResponse sends a response message to the client (public method for tests)
func (c *Client) SendResponse(response ResponseMessage) error {
	return c.sendResponse(response)
}

// removeClient removes a client from the server's client list
func (s *TestWebSocketServer) removeClient(conn *websocket.Conn) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()

	if client, exists := s.clients[conn]; exists {
		s.logger.Info("Client disconnected", "client_id", client.clientID)
		delete(s.clients, conn)
	}
}

// GetConnectedClients returns the number of connected and authenticated clients
func (s *TestWebSocketServer) GetConnectedClients() int {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()

	count := 0
	for _, client := range s.clients {
		if client.authenticated {
			count++
		}
	}
	return count
}

// ForceDisconnectAll forcefully disconnects all clients (for testing)
func (s *TestWebSocketServer) ForceDisconnectAll() {
	s.clientMu.RLock()
	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.clientMu.RUnlock()

	for _, client := range clients {
		client.forceDisconnect()
	}

	s.logger.Info("Forcefully disconnected all clients", "count", len(clients))
}

// ForceDisconnectClient forcefully disconnects a specific client by ID (for testing)
func (s *TestWebSocketServer) ForceDisconnectClient(clientID string) bool {
	s.clientMu.RLock()
	defer s.clientMu.RUnlock()

	for _, client := range s.clients {
		if client.clientID == clientID {
			client.forceDisconnect()
			s.logger.Info("Forcefully disconnected client", "client_id", clientID)
			return true
		}
	}

	return false
}

// forceDisconnect forcefully closes the client connection
func (c *Client) forceDisconnect() {
	c.server.logger.Info("Force disconnecting client", "client_id", c.clientID)

	// Stop auth timer if running
	if c.authTimer != nil {
		c.authTimer.Stop()
		c.authTimer = nil
	}

	// Close the connection
	c.conn.Close()

	// Signal done (non-blocking)
	select {
	case <-c.done:
		// Channel already closed
	default:
		close(c.done)
	}
}
