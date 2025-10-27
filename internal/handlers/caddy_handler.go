package handlers

import (
	"context"
	"encoding/json"

	"outlap-agent-go/pkg/types"
)

// CaddyHandler handles Caddy-related commands
type CaddyHandler struct {
	*BaseHandler
	caddyService CaddyService
}

// NewCaddyHandler creates a new Caddy handler
func NewCaddyHandler(base *BaseHandler, caddyService CaddyService) *CaddyHandler {
	return &CaddyHandler{
		BaseHandler:  base,
		caddyService: caddyService,
	}
}

// InstallCaddy handles the caddy.install command
func (h *CaddyHandler) InstallCaddy(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	if h.caddyService == nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "Caddy service not available",
		}, nil
	}

	// Trigger Caddy installation
	installer, ok := h.caddyService.(interface {
		InstallCaddy(context.Context) error
	})
	if !ok {
		return &types.CommandResponse{
			Success: false,
			Error:   "Caddy installation not supported by service",
		}, nil
	}

	if err := installer.InstallCaddy(ctx); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "Caddy installed successfully",
		},
	}, nil
}
