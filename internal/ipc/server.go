// Package ipc provides the Unix socket server for the supervisor process
package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pulseup-agent-go/pkg/logger"
)

// Server represents the IPC server running in the supervisor process
type Server struct {
	config    *SocketConfig
	logger    *logger.Logger
	validator *RequestValidator
	handler   RequestHandler
	listener  net.Listener
	
	// Connection management
	mu          sync.RWMutex
	connections map[string]*Connection
	shutdown    chan struct{}
	wg          sync.WaitGroup
	
	// Request tracking
	requestsMu     sync.RWMutex
	activeRequests map[string]*ActiveRequest
}

// Connection represents a client connection to the IPC server
type Connection struct {
	ID       string
	Conn     net.Conn
	ClientInfo ClientInfo
	LastSeen time.Time
	mu       sync.Mutex
}

// ActiveRequest represents an ongoing privileged request
type ActiveRequest struct {
	ID        string
	Request   *PrivilegedRequest
	StartTime time.Time
	ClientID  string
	Context   context.Context
	Cancel    context.CancelFunc
}

// RequestHandler interface for handling privileged requests
type RequestHandler interface {
	HandlePrivilegedRequest(ctx context.Context, req *PrivilegedRequest) (*PrivilegedResponse, error)
}

// AuditLoggerImpl implements audit logging
type AuditLoggerImpl struct {
	logger *logger.Logger
}

// LogSecurityEvent logs a security event
func (a *AuditLoggerImpl) LogSecurityEvent(event SecurityEvent) {
	a.logger.Info("security_event",
		"event_type", event.EventType,
		"operation", string(event.Operation),
		"worker_pid", event.WorkerPID,
		"allowed", event.Allowed,
		"reason", event.Reason,
		"timestamp", event.Timestamp,
	)
}

// NewServer creates a new IPC server
func NewServer(config *SocketConfig, logger *logger.Logger, handler RequestHandler) *Server {
	auditLogger := &AuditLoggerImpl{logger: logger.With("component", "audit")}
	validator := NewRequestValidator(auditLogger)
	
	return &Server{
		config:         config,
		logger:         logger.With("component", "ipc_server"),
		validator:      validator,
		handler:        handler,
		connections:    make(map[string]*Connection),
		activeRequests: make(map[string]*ActiveRequest),
		shutdown:       make(chan struct{}),
	}
}

// Start starts the IPC server
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting IPC server", "socket_path", s.config.SocketPath)

	// Ensure the socket directory exists
	socketDir := filepath.Dir(s.config.SocketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file if it exists
	if err := os.RemoveAll(s.config.SocketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix domain socket listener
	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("failed to create Unix socket listener: %w", err)
	}
	s.listener = listener

	// Set socket permissions
	if err := os.Chmod(s.config.SocketPath, os.FileMode(s.config.SocketMode)); err != nil {
		s.logger.Warn("Failed to set socket permissions", "error", err)
	}

	// Set socket ownership (if running as root)
	if os.Getuid() == 0 {
		if err := os.Chown(s.config.SocketPath, s.config.SocketUID, s.config.SocketGID); err != nil {
			s.logger.Warn("Failed to set socket ownership", "error", err)
		}
	}

	s.logger.Info("IPC server listening", "socket_path", s.config.SocketPath)

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptLoop(ctx)

	// Start cleanup routine
	s.wg.Add(1)
	go s.cleanupLoop(ctx)

	return nil
}

// Stop stops the IPC server
func (s *Server) Stop() error {
	s.logger.Info("Stopping IPC server")
	
	close(s.shutdown)
	
	// Close listener
	if s.listener != nil {
		s.listener.Close()
	}
	
	// Close all connections
	s.mu.RLock()
	for _, conn := range s.connections {
		conn.Conn.Close()
	}
	s.mu.RUnlock()
	
	// Cancel all active requests
	s.requestsMu.RLock()
	for _, req := range s.activeRequests {
		req.Cancel()
	}
	s.requestsMu.RUnlock()
	
	// Wait for goroutines to finish
	s.wg.Wait()
	
	// Remove socket file
	if err := os.RemoveAll(s.config.SocketPath); err != nil {
		s.logger.Warn("Failed to remove socket file", "error", err)
	}
	
	s.logger.Info("IPC server stopped")
	return nil
}

// acceptLoop accepts incoming connections
func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		default:
		}
		
		// Set accept timeout
		if tcpListener, ok := s.listener.(*net.UnixListener); ok {
			tcpListener.SetDeadline(time.Now().Add(time.Second))
		}
		
		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // timeout is expected
			}
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				s.logger.Warn("Temporary accept error", "error", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			// Check if we're shutting down
			select {
			case <-s.shutdown:
				return
			default:
				s.logger.Error("Accept error", "error", err)
				return
			}
		}
		
		// Handle new connection
		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

// handleConnection handles a client connection
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	
	// Get client info
	clientInfo, err := GetClientInfo(conn)
	if err != nil {
		s.logger.Error("Failed to get client info", "error", err)
		return
	}
	
	// Create connection object
	connectionID := fmt.Sprintf("conn_%d_%d", clientInfo.PID, time.Now().UnixNano())
	connection := &Connection{
		ID:         connectionID,
		Conn:       conn,
		ClientInfo: clientInfo,
		LastSeen:   time.Now(),
	}
	
	// Register connection
	s.mu.Lock()
	s.connections[connectionID] = connection
	s.mu.Unlock()
	
	// Clean up connection when done
	defer func() {
		s.mu.Lock()
		delete(s.connections, connectionID)
		s.mu.Unlock()
	}()
	
	s.logger.Info("New client connected", 
		"connection_id", connectionID,
		"client_pid", clientInfo.PID,
		"client_uid", clientInfo.UID,
	)
	
	// Handle messages
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		default:
		}
		
		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(s.config.Timeout))
		
		// Read message
		var msg Message
		decoder := json.NewDecoder(conn)
		if err := decoder.Decode(&msg); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // timeout is expected for keep-alive
			}
			s.logger.Debug("Connection closed or read error", "error", err)
			return
		}
		
		// Update last seen
		connection.mu.Lock()
		connection.LastSeen = time.Now()
		connection.mu.Unlock()
		
		// Handle message
		response := s.handleMessage(ctx, &msg, connection)
		
		// Send response
		if response != nil {
			conn.SetWriteDeadline(time.Now().Add(s.config.Timeout))
			encoder := json.NewEncoder(conn)
			if err := encoder.Encode(response); err != nil {
				s.logger.Error("Failed to send response", "error", err)
				return
			}
		}
	}
}

// handleMessage handles an incoming message
func (s *Server) handleMessage(ctx context.Context, msg *Message, conn *Connection) *Message {
	switch MessageType(msg.Type) {
	case MessageTypeRequest:
		return s.handleRequest(ctx, msg.Data, conn)
	case MessageTypeHeartbeat:
		return s.handleHeartbeat(msg.Data, conn)
	case MessageTypeShutdown:
		s.logger.Info("Received shutdown message from client", "client_pid", conn.ClientInfo.PID)
		return nil
	default:
		s.logger.Warn("Unknown message type", "type", msg.Type)
		return &Message{
			Type: string(MessageTypeResponse),
			Data: s.encodeResponse(&PrivilegedResponse{
				Success: false,
				Error:   fmt.Sprintf("unknown message type: %s", msg.Type),
			}),
		}
	}
}

// handleRequest handles a privileged request
func (s *Server) handleRequest(ctx context.Context, data json.RawMessage, conn *Connection) *Message {
	// Parse request
	var req PrivilegedRequest
	if err := json.Unmarshal(data, &req); err != nil {
		s.logger.Error("Failed to parse request", "error", err)
		return &Message{
			Type: string(MessageTypeResponse),
			Data: s.encodeResponse(&PrivilegedResponse{
				ID:      "unknown",
				Success: false,
				Error:   fmt.Sprintf("failed to parse request: %v", err),
			}),
		}
	}
	
	startTime := time.Now()
	
	// Validate request
	if err := s.validator.ValidateRequest(&req, conn.ClientInfo); err != nil {
		s.logger.Error("Request validation failed", 
			"request_id", req.ID,
			"operation", req.Operation,
			"client_pid", conn.ClientInfo.PID,
			"error", err,
		)
		return &Message{
			Type: string(MessageTypeResponse),
			Data: s.encodeResponse(&PrivilegedResponse{
				ID:      req.ID,
				Success: false,
				Error:   fmt.Sprintf("request validation failed: %v", err),
				Took:    time.Since(startTime),
			}),
		}
	}
	
	// Create request context with timeout
	config, _ := GetOperationConfig(OperationType(req.Operation))
	requestCtx, cancel := context.WithTimeout(ctx, config.MaxTimeout)
	
	// Track active request
	activeReq := &ActiveRequest{
		ID:        req.ID,
		Request:   &req,
		StartTime: startTime,
		ClientID:  conn.ID,
		Context:   requestCtx,
		Cancel:    cancel,
	}
	
	s.requestsMu.Lock()
	s.activeRequests[req.ID] = activeReq
	s.requestsMu.Unlock()
	
	// Clean up when done
	defer func() {
		cancel()
		s.requestsMu.Lock()
		delete(s.activeRequests, req.ID)
		s.requestsMu.Unlock()
	}()
	
	s.logger.Info("Processing privileged request",
		"request_id", req.ID,
		"operation", req.Operation,
		"client_pid", conn.ClientInfo.PID,
	)
	
	// Handle the request
	response, err := s.handler.HandlePrivilegedRequest(requestCtx, &req)
	if err != nil {
		s.logger.Error("Request handling failed",
			"request_id", req.ID,
			"operation", req.Operation,
			"error", err,
		)
		response = &PrivilegedResponse{
			ID:      req.ID,
			Success: false,
			Error:   fmt.Sprintf("request handling failed: %v", err),
			Took:    time.Since(startTime),
		}
	} else {
		response.ID = req.ID
		response.Took = time.Since(startTime)
		s.logger.Info("Request completed successfully",
			"request_id", req.ID,
			"operation", req.Operation,
			"took", response.Took,
		)
	}
	
	return &Message{
		Type: string(MessageTypeResponse),
		Data: s.encodeResponse(response),
	}
}

// handleHeartbeat handles a heartbeat message
func (s *Server) handleHeartbeat(data json.RawMessage, conn *Connection) *Message {
	var heartbeat HeartbeatMessage
	if err := json.Unmarshal(data, &heartbeat); err != nil {
		s.logger.Warn("Failed to parse heartbeat", "error", err)
		return nil
	}
	
	s.logger.Debug("Received heartbeat",
		"client_pid", heartbeat.PID,
		"status", heartbeat.Status,
	)
	
	// Send heartbeat response
	response := HeartbeatMessage{
		ProcessType: "supervisor",
		PID:         os.Getpid(),
		Timestamp:   time.Now(),
		Status:      "healthy",
	}
	
	responseData, _ := json.Marshal(response)
	return &Message{
		Type: string(MessageTypeHeartbeat),
		Data: responseData,
	}
}

// cleanupLoop periodically cleans up stale connections and requests
func (s *Server) cleanupLoop(ctx context.Context) {
	defer s.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

// cleanup removes stale connections and requests
func (s *Server) cleanup() {
	now := time.Now()
	staleThreshold := 5 * time.Minute
	
	// Clean up stale connections
	s.mu.Lock()
	for id, conn := range s.connections {
		conn.mu.Lock()
		if now.Sub(conn.LastSeen) > staleThreshold {
			s.logger.Info("Closing stale connection", "connection_id", id)
			conn.Conn.Close()
			delete(s.connections, id)
		}
		conn.mu.Unlock()
	}
	s.mu.Unlock()
	
	// Clean up long-running requests
	s.requestsMu.Lock()
	for id, req := range s.activeRequests {
		if now.Sub(req.StartTime) > 30*time.Minute {
			s.logger.Warn("Canceling long-running request", "request_id", id)
			req.Cancel()
			delete(s.activeRequests, id)
		}
	}
	s.requestsMu.Unlock()
}

// encodeResponse encodes a response to JSON
func (s *Server) encodeResponse(response *PrivilegedResponse) json.RawMessage {
	data, err := json.Marshal(response)
	if err != nil {
		s.logger.Error("Failed to encode response", "error", err)
		fallback := &PrivilegedResponse{
			ID:      response.ID,
			Success: false,
			Error:   "failed to encode response",
		}
		data, _ = json.Marshal(fallback)
	}
	return data
}

// GetActiveRequests returns information about active requests
func (s *Server) GetActiveRequests() map[string]*ActiveRequest {
	s.requestsMu.RLock()
	defer s.requestsMu.RUnlock()
	
	result := make(map[string]*ActiveRequest)
	for id, req := range s.activeRequests {
		result[id] = req
	}
	return result
}

// GetConnections returns information about active connections
func (s *Server) GetConnections() map[string]*Connection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	result := make(map[string]*Connection)
	for id, conn := range s.connections {
		result[id] = conn
	}
	return result
}

// GetStats returns server statistics
func (s *Server) GetStats() map[string]interface{} {
	s.mu.RLock()
	connectionCount := len(s.connections)
	s.mu.RUnlock()
	
	s.requestsMu.RLock()
	activeRequestCount := len(s.activeRequests)
	s.requestsMu.RUnlock()
	
	return map[string]interface{}{
		"active_connections": connectionCount,
		"active_requests":    activeRequestCount,
		"socket_path":        s.config.SocketPath,
	}
}