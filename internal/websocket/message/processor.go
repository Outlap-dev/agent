// Package message provides message processing functionality for WebSocket connections
package message

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"outlap-agent-go/internal/websocket/types"
	"outlap-agent-go/pkg/logger"
)

// Processor handles incoming WebSocket messages and routing
type Processor struct {
	logger       *logger.Logger
	config       *ProcessorConfig
	handlers     map[string]types.EventHandler
	handlersMu   sync.RWMutex
	pendingCalls map[string]*types.PendingCall
	callsMu      sync.RWMutex
	sender       types.MessageSender

	// Callback functions for different message types
	onAuthResponse  func(msg map[string]interface{}) error
	onServerMessage func(msg map[string]interface{}) error
	onError         func(msg map[string]interface{}) error
	onAuthChallenge func(msg map[string]interface{}) error
}

// ProcessorConfig holds configuration for the message processor
type ProcessorConfig struct {
	// Default timeout for RPC calls
	DefaultCallTimeout time.Duration `json:"default_call_timeout" yaml:"default_call_timeout"`

	// Maximum number of concurrent pending calls
	MaxPendingCalls int `json:"max_pending_calls" yaml:"max_pending_calls"`

	// Whether to enable panic recovery in handlers
	EnablePanicRecovery bool `json:"enable_panic_recovery" yaml:"enable_panic_recovery"`
}

// DefaultProcessorConfig returns processor configuration with sensible defaults
func DefaultProcessorConfig() *ProcessorConfig {
	return &ProcessorConfig{
		DefaultCallTimeout:  30 * time.Second,
		MaxPendingCalls:     1000,
		EnablePanicRecovery: true,
	}
}

// NewProcessor creates a new message processor
func NewProcessor(logger *logger.Logger, sender types.MessageSender, config *ProcessorConfig) *Processor {
	if config == nil {
		config = DefaultProcessorConfig()
	}

	return &Processor{
		logger:       logger.With("component", "websocket_message"),
		config:       config,
		handlers:     make(map[string]types.EventHandler),
		pendingCalls: make(map[string]*types.PendingCall),
		sender:       sender,
	}
}

// SetAuthResponseHandler sets the callback for authentication response messages
func (p *Processor) SetAuthResponseHandler(handler func(msg map[string]interface{}) error) {
	p.onAuthResponse = handler
}

// SetServerMessageHandler sets the callback for server status messages
func (p *Processor) SetServerMessageHandler(handler func(msg map[string]interface{}) error) {
	p.onServerMessage = handler
}

// SetErrorHandler sets the callback for error messages
func (p *Processor) SetErrorHandler(handler func(msg map[string]interface{}) error) {
	p.onError = handler
}

// SetAuthChallengeHandler sets the callback for auth challenge messages
func (p *Processor) SetAuthChallengeHandler(handler func(msg map[string]interface{}) error) {
	p.onAuthChallenge = handler
}

// ProcessMessage routes an incoming message to the appropriate handler
func (p *Processor) ProcessMessage(msg map[string]interface{}) {
	msgType, ok := msg["type"].(string)
	if !ok {
		p.logger.Warn("Message without type field", "msg", msg)
		return
	}

	switch msgType {
	case "auth_response":
		if p.onAuthResponse != nil {
			if err := p.onAuthResponse(msg); err != nil {
				p.logger.Error("Error handling auth response", "error", err)
			}
		}

	case "connected", "init_response":
		if p.onServerMessage != nil {
			if err := p.onServerMessage(msg); err != nil {
				p.logger.Error("Error handling server message", "error", err)
			}
		}

	case "auth_challenge":
		if p.onAuthChallenge != nil {
			if err := p.onAuthChallenge(msg); err != nil {
				p.logger.Error("Error handling auth challenge", "error", err)
			}
		}

	case "response":
		p.handleCallResponse(msg)

	case "call":
		p.handleIncomingCall(msg)

	case "event":
		p.handleEvent(msg)

	case "ping":
		p.handlePing(msg)

	case "error":
		if p.onError != nil {
			if err := p.onError(msg); err != nil {
				p.logger.Error("Error handling error message", "error", err)
			}
		}

	default:
		p.logger.Warn("Unknown message type", "type", msgType)
	}
}

// RegisterHandler registers an event handler for a specific event type
func (p *Processor) RegisterHandler(event string, handler types.EventHandler) {
	p.handlersMu.Lock()
	defer p.handlersMu.Unlock()

	p.handlers[event] = handler
}

// UnregisterHandler removes an event handler
func (p *Processor) UnregisterHandler(event string) {
	p.handlersMu.Lock()
	defer p.handlersMu.Unlock()

	delete(p.handlers, event)
}

// RegisterPendingCall registers a pending RPC call
func (p *Processor) RegisterPendingCall(callID string, call *types.PendingCall) error {
	p.callsMu.Lock()
	defer p.callsMu.Unlock()

	// Check if we're at capacity
	if len(p.pendingCalls) >= p.config.MaxPendingCalls {
		return fmt.Errorf("too many pending calls")
	}

	p.pendingCalls[callID] = call
	p.logger.Debug("Registered pending call", "call_id", callID)
	return nil
}

// UnregisterPendingCall removes a pending RPC call
func (p *Processor) UnregisterPendingCall(callID string) *types.PendingCall {
	p.callsMu.Lock()
	defer p.callsMu.Unlock()

	call, exists := p.pendingCalls[callID]
	if exists {
		delete(p.pendingCalls, callID)
		p.logger.Debug("Unregistered pending call", "call_id", callID)
	}

	return call
}

// handleCallResponse processes RPC call responses
func (p *Processor) handleCallResponse(msg map[string]interface{}) {
	callID, ok := msg["call_id"].(string)
	if !ok {
		// This is normal for event messages that are not responses to specific calls
		p.logger.Debug("Response message without call_id (likely an event message)")
		return
	}

	// Find and remove pending call
	call := p.UnregisterPendingCall(callID)
	if call == nil {
		p.logger.Warn("Received response for unknown call", "call_id", callID)
		return
	}

	// Parse response
	data := msg["data"]
	success, _ := msg["success"].(bool)
	errorMsg, _ := msg["error"].(string)

	response := types.CallResponse{
		Success: success,
		Data:    data,
		Error:   errorMsg,
	}

	// Send response and cleanup
	call.Timeout.Stop()
	select {
	case call.Response <- response:
		// Do nothing, response sent successfully
	default:
		p.logger.Warn("Call response channel full", "call_id", callID)
	}
	close(call.Response)
}

// handlePing processes ping messages and responds with pong
func (p *Processor) handlePing(msg map[string]interface{}) {
	pongMsg := types.Message{
		Type: "pong",
		Data: msg["data"], // Echo back any data that came with the ping
	}

	if err := p.sender.SendMessage(pongMsg); err != nil {
		p.logger.Error("Failed to send pong response", "error", err)
	}
}

// handleIncomingCall processes incoming RPC calls from the server
func (p *Processor) handleIncomingCall(msg map[string]interface{}) {
	callID, hasCallID := msg["call_id"].(string)
	event, hasEvent := msg["event"].(string)

	if !hasEvent {
		p.logger.Error("Call message without event")
		if hasCallID {
			p.sendCallResponse(callID, false, nil, "missing event")
		}
		return
	}

	// Extract data payload
	var dataBytes []byte
	if data, hasData := msg["data"]; hasData {
		var err error
		dataBytes, err = json.Marshal(data)
		if err != nil {
			p.logger.Error("Failed to marshal call data", "error", err)
			if hasCallID {
				p.sendCallResponse(callID, false, nil, "invalid data format")
			}
			return
		}
	} else {
		dataBytes = []byte("{}")
	}

	// Find handler
	p.handlersMu.RLock()
	handler, exists := p.handlers[event]
	p.handlersMu.RUnlock()

	if !exists {
		p.logger.Warn("No handler for event", "event", event)
		if hasCallID {
			p.sendCallResponse(callID, false, nil, "unknown event: "+event)
		}
		return
	}

	// Execute handler in goroutine
	go p.executeHandler(event, handler, dataBytes, callID, hasCallID)
}

// handleEvent processes fire-and-forget events
func (p *Processor) handleEvent(msg map[string]interface{}) {
	event, hasEvent := msg["event"].(string)
	if !hasEvent {
		p.logger.Warn("Event message without event name")
		return
	}

	var dataBytes []byte
	if data, hasData := msg["data"]; hasData {
		var err error
		dataBytes, err = json.Marshal(data)
		if err != nil {
			p.logger.Error("Failed to marshal event data", "event", event, "error", err)
			return
		}
	} else {
		dataBytes = []byte("{}")
	}

	p.handlersMu.RLock()
	handler, exists := p.handlers[event]
	p.handlersMu.RUnlock()

	if !exists {
		p.logger.Warn("No handler for event", "event", event)
		return
	}

	go p.executeHandler(event, handler, dataBytes, "", false)
}

// executeHandler executes an event handler with proper error handling
func (p *Processor) executeHandler(event string, handler types.EventHandler, dataBytes []byte, callID string, hasCallID bool) {
	// Panic recovery if enabled
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("Handler panic", "event", event, "panic", r)
			if hasCallID {
				p.sendCallResponse(callID, false, nil, fmt.Sprintf("handler panic: %v", r))
			}
		}
	}()

	// Execute handler
	response, err := handler(json.RawMessage(dataBytes))
	if err != nil {
		p.logger.Error("Handler error", "event", event, "error", err)
		if hasCallID {
			p.sendCallResponse(callID, false, nil, err.Error())
		}
		return
	}

	// Send response if this is a call (has call_id) and handler returned a response
	if hasCallID && response != nil {
		errorMsg := ""
		if !response.Success {
			errorMsg = response.Error
		}
		p.sendCallResponse(callID, response.Success, response.Data, errorMsg)
	}
}

// sendCallResponse sends a response to an RPC call
func (p *Processor) sendCallResponse(callID string, success bool, data interface{}, errorMsg string) {
	response := types.Message{
		Type:   "response",
		CallID: callID,
		Data: map[string]interface{}{
			"success": success,
			"data":    data,
			"error":   errorMsg,
		},
	}

	p.logger.Debug("Sending call response", "call_id", callID, "success", success)

	if err := p.sender.SendMessage(response); err != nil {
		p.logger.Error("Failed to send call response", "call_id", callID, "error", err)
	}
}

// GetPendingCallCount returns the number of pending calls
func (p *Processor) GetPendingCallCount() int {
	p.callsMu.RLock()
	defer p.callsMu.RUnlock()
	return len(p.pendingCalls)
}

// GetRegisteredHandlers returns a list of registered event handlers
func (p *Processor) GetRegisteredHandlers() []string {
	p.handlersMu.RLock()
	defer p.handlersMu.RUnlock()

	handlers := make([]string, 0, len(p.handlers))
	for event := range p.handlers {
		handlers = append(handlers, event)
	}
	return handlers
}

// CleanupExpiredCalls removes calls that have been pending too long
func (p *Processor) CleanupExpiredCalls(maxAge time.Duration) int {
	p.callsMu.Lock()
	defer p.callsMu.Unlock()

	now := time.Now()
	var expired []string

	for callID, call := range p.pendingCalls {
		if now.Sub(call.Created) > maxAge {
			expired = append(expired, callID)
		}
	}

	// Remove expired calls
	for _, callID := range expired {
		call := p.pendingCalls[callID]
		delete(p.pendingCalls, callID)

		// Send timeout response
		call.Timeout.Stop()
		select {
		case call.Response <- types.CallResponse{
			Success: false,
			Error:   "call expired",
		}:
		default:
		}
		close(call.Response)
	}

	if len(expired) > 0 {
		p.logger.Info("Cleaned up expired calls", "count", len(expired))
	}

	return len(expired)
}
