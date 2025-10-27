package websocket

import (
	"context"
	"encoding/json"
	"time"

	"outlap-agent-go/pkg/types"
)

// WebSocketConnection represents a websocket connection interface for dependency injection
type WebSocketConnection interface {
	// Connection management
	Connect(ctx context.Context) error
	Disconnect() error
	IsConnected() bool

	// Message sending
	Send(event string, data interface{}) error
	Emit(event string, data interface{}) error
	Call(event string, data interface{}) (map[string]interface{}, error)
	SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error

	// Handler registration
	RegisterHandler(event string, handler func(data json.RawMessage) (*types.CommandResponse, error))
}

// WebSocketDialer represents a websocket dialer interface for dependency injection
type WebSocketDialer interface {
	Dial(url string, headers map[string][]string) (WebSocketConn, error)
}

// WebSocketConn represents a websocket connection interface for testing
type WebSocketConn interface {
	WriteJSON(v interface{}) error
	ReadJSON(v interface{}) error
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (messageType int, p []byte, err error)
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetPongHandler(h func(appData string) error)
	Close() error
}

// ConnectionFactory creates websocket connections with dependency injection support
type ConnectionFactory interface {
	CreateConnection(url string, dialer WebSocketDialer) (WebSocketConn, error)
}
