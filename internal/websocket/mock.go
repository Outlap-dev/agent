package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"outlap-agent-go/pkg/types"
)

// MockWebSocketConnection implements WebSocketConnection for testing
type MockWebSocketConnection struct {
	connected bool
	mu        sync.RWMutex

	// Message storage for testing
	sentMessages     []MockMessage
	receivedMessages []MockMessage
	messagesMu       sync.RWMutex

	// Handlers
	handlers map[string]func(data json.RawMessage) (*types.CommandResponse, error)

	// Configuration for testing
	shouldFailConnect bool
	shouldFailSend    bool
	connectDelay      time.Duration

	// Channels for testing message flow
	sendCh    chan MockMessage
	receiveCh chan MockMessage

	// Callbacks for testing
	onConnect    func() error
	onDisconnect func() error
	onSend       func(event string, data interface{}) error
}

// MockMessage represents a message sent/received in testing
type MockMessage struct {
	Type      string      `json:"type"`
	Event     string      `json:"event,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	CallID    string      `json:"call_id,omitempty"`
	Success   bool        `json:"success,omitempty"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// NewMockWebSocketConnection creates a new mock websocket connection
func NewMockWebSocketConnection() *MockWebSocketConnection {
	return &MockWebSocketConnection{
		handlers:         make(map[string]func(data json.RawMessage) (*types.CommandResponse, error)),
		sendCh:           make(chan MockMessage, 100),
		receiveCh:        make(chan MockMessage, 100),
		sentMessages:     make([]MockMessage, 0),
		receivedMessages: make([]MockMessage, 0),
	}
}

// Connect simulates connecting to a websocket server
func (m *MockWebSocketConnection) Connect(ctx context.Context) error {
	if m.shouldFailConnect {
		return fmt.Errorf("mock connection failed")
	}

	if m.connectDelay > 0 {
		time.Sleep(m.connectDelay)
	}

	m.mu.Lock()
	m.connected = true
	m.mu.Unlock()

	if m.onConnect != nil {
		return m.onConnect()
	}

	return nil
}

// Disconnect simulates disconnecting from a websocket server
func (m *MockWebSocketConnection) Disconnect() error {
	m.mu.Lock()
	m.connected = false
	m.mu.Unlock()

	if m.onDisconnect != nil {
		return m.onDisconnect()
	}

	return nil
}

// IsConnected returns the connection status
func (m *MockWebSocketConnection) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

// Send simulates sending a message
func (m *MockWebSocketConnection) Send(event string, data interface{}) error {
	if !m.IsConnected() {
		return fmt.Errorf("not connected")
	}

	if m.shouldFailSend {
		return fmt.Errorf("mock send failed")
	}

	message := MockMessage{
		Type:      "send",
		Event:     event,
		Data:      data,
		Timestamp: time.Now(),
	}

	m.messagesMu.Lock()
	m.sentMessages = append(m.sentMessages, message)
	m.messagesMu.Unlock()

	select {
	case m.sendCh <- message:
	default:
		return fmt.Errorf("send channel full")
	}

	if m.onSend != nil {
		return m.onSend(event, data)
	}

	return nil
}

// Emit simulates emitting an event
func (m *MockWebSocketConnection) Emit(event string, data interface{}) error {
	if !m.IsConnected() {
		return fmt.Errorf("not connected")
	}

	message := MockMessage{
		Type:      "emit",
		Event:     event,
		Data:      data,
		Timestamp: time.Now(),
	}

	m.messagesMu.Lock()
	m.sentMessages = append(m.sentMessages, message)
	m.messagesMu.Unlock()

	select {
	case m.sendCh <- message:
	default:
		return fmt.Errorf("send channel full")
	}

	return nil
}

// Call simulates making a call and waiting for response
func (m *MockWebSocketConnection) Call(event string, data interface{}) (map[string]interface{}, error) {
	if !m.IsConnected() {
		return nil, fmt.Errorf("not connected")
	}

	callID := fmt.Sprintf("call_%d", time.Now().UnixNano())

	message := MockMessage{
		Type:      "call",
		Event:     event,
		Data:      data,
		CallID:    callID,
		Timestamp: time.Now(),
	}

	m.messagesMu.Lock()
	m.sentMessages = append(m.sentMessages, message)
	m.messagesMu.Unlock()

	select {
	case m.sendCh <- message:
	default:
		return nil, fmt.Errorf("send channel full")
	}

	// For mock testing, return a simple response
	return map[string]interface{}{
		"status":  "success",
		"call_id": callID,
	}, nil
}

// SendCallResponse simulates sending a call response
func (m *MockWebSocketConnection) SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error {
	if !m.IsConnected() {
		return fmt.Errorf("not connected")
	}

	message := MockMessage{
		Type:      "response",
		CallID:    callID,
		Success:   success,
		Data:      data,
		Error:     errorMsg,
		Timestamp: time.Now(),
	}

	m.messagesMu.Lock()
	m.sentMessages = append(m.sentMessages, message)
	m.messagesMu.Unlock()

	select {
	case m.sendCh <- message:
	default:
		return fmt.Errorf("send channel full")
	}

	return nil
}

// RegisterHandler registers a message handler
func (m *MockWebSocketConnection) RegisterHandler(event string, handler func(data json.RawMessage) (*types.CommandResponse, error)) {
	m.handlers[event] = handler
}

// Simulate receiving a message (for testing)
func (m *MockWebSocketConnection) SimulateReceive(event string, data interface{}) error {
	if !m.IsConnected() {
		return fmt.Errorf("not connected")
	}

	message := MockMessage{
		Type:      "receive",
		Event:     event,
		Data:      data,
		Timestamp: time.Now(),
	}

	m.messagesMu.Lock()
	m.receivedMessages = append(m.receivedMessages, message)
	m.messagesMu.Unlock()

	// Call handler if registered
	if handler, exists := m.handlers[event]; exists {
		dataBytes, err := json.Marshal(data)
		if err != nil {
			return fmt.Errorf("failed to marshal data: %w", err)
		}

		go func() {
			_, err := handler(json.RawMessage(dataBytes))
			if err != nil {
				// Log error in real implementation
			}
		}()
	}

	select {
	case m.receiveCh <- message:
	default:
		return fmt.Errorf("receive channel full")
	}

	return nil
}

// Test helper methods

// SetShouldFailConnect sets whether Connect should fail
func (m *MockWebSocketConnection) SetShouldFailConnect(shouldFail bool) {
	m.shouldFailConnect = shouldFail
}

// SetShouldFailSend sets whether Send should fail
func (m *MockWebSocketConnection) SetShouldFailSend(shouldFail bool) {
	m.shouldFailSend = shouldFail
}

// SetConnectDelay sets a delay for Connect operations
func (m *MockWebSocketConnection) SetConnectDelay(delay time.Duration) {
	m.connectDelay = delay
}

// GetSentMessages returns all sent messages
func (m *MockWebSocketConnection) GetSentMessages() []MockMessage {
	m.messagesMu.RLock()
	defer m.messagesMu.RUnlock()

	messages := make([]MockMessage, len(m.sentMessages))
	copy(messages, m.sentMessages)
	return messages
}

// GetReceivedMessages returns all received messages
func (m *MockWebSocketConnection) GetReceivedMessages() []MockMessage {
	m.messagesMu.RLock()
	defer m.messagesMu.RUnlock()

	messages := make([]MockMessage, len(m.receivedMessages))
	copy(messages, m.receivedMessages)
	return messages
}

// ClearMessages clears all stored messages
func (m *MockWebSocketConnection) ClearMessages() {
	m.messagesMu.Lock()
	m.sentMessages = m.sentMessages[:0]
	m.receivedMessages = m.receivedMessages[:0]
	m.messagesMu.Unlock()
}

// GetLastSentMessage returns the last sent message
func (m *MockWebSocketConnection) GetLastSentMessage() *MockMessage {
	m.messagesMu.RLock()
	defer m.messagesMu.RUnlock()

	if len(m.sentMessages) == 0 {
		return nil
	}

	return &m.sentMessages[len(m.sentMessages)-1]
}

// GetSentMessagesByEvent returns all sent messages for a specific event
func (m *MockWebSocketConnection) GetSentMessagesByEvent(event string) []MockMessage {
	m.messagesMu.RLock()
	defer m.messagesMu.RUnlock()

	var filtered []MockMessage
	for _, msg := range m.sentMessages {
		if msg.Event == event {
			filtered = append(filtered, msg)
		}
	}
	return filtered
}

// GetSentMessagesByType returns all sent messages for a specific type
func (m *MockWebSocketConnection) GetSentMessagesByType(msgType string) []MockMessage {
	m.messagesMu.RLock()
	defer m.messagesMu.RUnlock()

	var filtered []MockMessage
	for _, msg := range m.sentMessages {
		if msg.Type == msgType {
			filtered = append(filtered, msg)
		}
	}
	return filtered
}

// SetOnConnect sets a callback for connect events
func (m *MockWebSocketConnection) SetOnConnect(callback func() error) {
	m.onConnect = callback
}

// SetOnDisconnect sets a callback for disconnect events
func (m *MockWebSocketConnection) SetOnDisconnect(callback func() error) {
	m.onDisconnect = callback
}

// SetOnSend sets a callback for send events
func (m *MockWebSocketConnection) SetOnSend(callback func(event string, data interface{}) error) {
	m.onSend = callback
}
