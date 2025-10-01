package websocket

import (
	"encoding/json"

	"pulseup-agent-go/pkg/types"
)

// Emitter represents the ability to emit events over the websocket connection.
type Emitter interface {
	Emit(event string, data interface{}) error
}

// Connector reports whether the websocket connection is currently established.
type Connector interface {
	IsConnected() bool
}

// StatefulEmitter combines event emission with connection state awareness.
type StatefulEmitter interface {
	Emitter
	Connector
}

// Caller executes request/response style websocket calls that return structured payloads.
type Caller interface {
	Call(event string, data interface{}) (map[string]interface{}, error)
}

// Sender represents the ability to push raw websocket events.
type Sender interface {
	Send(event string, data interface{}) error
}

// Responder reports results for previously received websocket calls.
type Responder interface {
	SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error
}

// HandlerRegistrar registers websocket event handlers.
type HandlerRegistrar interface {
	RegisterHandler(event string, handler func(json.RawMessage) (*types.CommandResponse, error))
}

// Manager represents the full contract exposed by the websocket adapter used inside services.
type Manager interface {
	Sender
	Emitter
	Caller
	Responder
	Connector
	HandlerRegistrar
}
