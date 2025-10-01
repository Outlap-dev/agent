package bootstrap

import (
	"encoding/json"
	"fmt"

	"pulseup-agent-go/internal/websocket"
	wsTypes "pulseup-agent-go/internal/websocket/types"
	wscontracts "pulseup-agent-go/pkg/contracts/websocket"
	"pulseup-agent-go/pkg/types"
)

// Bundle groups the mTLS WebSocket client with its lightweight adapter.
type Bundle struct {
	Client  *websocket.MTLSClient
	Adapter *Adapter
}

// NewBundle creates a new bundle from an mTLS client instance.
func NewBundle(client *websocket.MTLSClient) *Bundle {
	if client == nil {
		return &Bundle{}
	}

	return &Bundle{
		Client:  client,
		Adapter: NewAdapter(client),
	}
}

// Adapter exposes a minimal, typed interface for services that interact with the websocket client.
type Adapter struct {
	client *websocket.MTLSClient
}

// NewAdapter wraps the provided client in an Adapter instance.
func NewAdapter(client *websocket.MTLSClient) *Adapter {
	return &Adapter{client: client}
}

func (a *Adapter) ensureClient() (*websocket.MTLSClient, error) {
	if a == nil || a.client == nil {
		return nil, fmt.Errorf("websocket client unavailable")
	}
	return a.client, nil
}

// Send forwards events to the websocket client.
func (a *Adapter) Send(event string, data interface{}) error {
	client, err := a.ensureClient()
	if err != nil {
		return err
	}
	return client.Send(event, data)
}

// Emit forwards events to the websocket client.
func (a *Adapter) Emit(event string, data interface{}) error {
	client, err := a.ensureClient()
	if err != nil {
		return err
	}
	return client.Emit(event, data)
}

// Call executes a request/response style interaction with the websocket backend.
func (a *Adapter) Call(event string, data interface{}) (map[string]interface{}, error) {
	client, err := a.ensureClient()
	if err != nil {
		return nil, err
	}
	return client.Call(event, data)
}

// SendCallResponse reports the outcome of a previously received call.
func (a *Adapter) SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error {
	client, err := a.ensureClient()
	if err != nil {
		return err
	}
	return client.SendCallResponse(callID, success, data, errorMsg)
}

// IsConnected reports the current connection status of the websocket client.
func (a *Adapter) IsConnected() bool {
	if a == nil || a.client == nil {
		return false
	}
	return a.client.IsConnected()
}

// RegisterHandler wires an event handler through to the websocket client.
func (a *Adapter) RegisterHandler(event string, handler func(json.RawMessage) (*types.CommandResponse, error)) {
	if a == nil || a.client == nil {
		return
	}

	a.client.RegisterHandler(event, func(payload json.RawMessage) (*wsTypes.CommandResponse, error) {
		resp, err := handler(payload)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, nil
		}

		return &wsTypes.CommandResponse{
			Success: resp.Success,
			Data:    resp.Data,
			Error:   resp.Error,
		}, nil
	})
}

var (
	_ wscontracts.Manager         = (*Adapter)(nil)
	_ wscontracts.StatefulEmitter = (*Adapter)(nil)
	_ types.WebSocketEmitter      = (*Adapter)(nil)
)
