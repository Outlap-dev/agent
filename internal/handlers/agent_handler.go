package handlers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

const (
	// DefaultUninstallFlagFile is the default path to the uninstall flag file
	DefaultUninstallFlagFile = "/var/run/outlap-agent/delete-needed"
)

// UninstallFlagFile holds the path to the uninstall flag file. It can be overridden for
// testing purposes.
var UninstallFlagFile = DefaultUninstallFlagFile

// AgentHandler bundles agent-specific commands such as log retrieval and uninstall operations.
type AgentHandler struct {
	*BaseHandler
}

// NewAgentHandler constructs an AgentHandler with shared dependencies.
func NewAgentHandler(logger *logger.Logger, services ServiceProvider) *AgentHandler {
	return &AgentHandler{
		BaseHandler: NewBaseHandler(logger.With("controller", "agent"), services),
	}
}

// Base exposes the embedded base handler for routing helpers.
func (h *AgentHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// FetchLogs streams the most recent agent logs, defaulting to 100 lines when unspecified.
func (h *AgentHandler) FetchLogs(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request struct {
		Lines int `json:"lines,omitempty"`
	}

	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format",
		}, nil
	}

	if request.Lines <= 0 {
		request.Lines = 100
	}

	h.logger.Info("Getting agent logs", "lines", request.Lines)

	logs, err := h.services.GetAgentLogService().GetAgentLogs(ctx, request.Lines)
	if err != nil {
		h.logger.Error("Failed to get agent logs", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "failed to get agent logs: " + err.Error(),
		}, nil
	}

	h.logger.Info("Retrieved agent logs", "total_logs", len(logs))

	return &types.CommandResponse{
		Success: true,
		Data:    map[string]interface{}{"logs": logs},
	}, nil
}

// HardwareInfo returns hardware metrics gathered via the system service.
func (h *AgentHandler) HardwareInfo(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Debug("Getting hardware information")

	systemService := h.services.GetSystemService()
	if systemService == nil {
		h.logger.Error("System service not available")
		return &types.CommandResponse{
			Success: false,
			Error:   "system service not available",
		}, nil
	}

	hardwareInfo, err := systemService.GetHardwareInfo(ctx)
	if err != nil {
		h.logger.Error("Failed to get hardware info", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	h.logger.Debug("Successfully retrieved hardware information")

	return &types.CommandResponse{
		Success: true,
		Data:    hardwareInfo,
	}, nil
}

// Uninstall creates a flag file that signals the supervisor to remove the agent.
func (h *AgentHandler) Uninstall(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Handling agent uninstallation request")

	flagDir := filepath.Dir(UninstallFlagFile)
	if err := os.MkdirAll(flagDir, 0o755); err != nil {
		h.logger.Error("Failed to create flag file directory", "error", err, "dir", flagDir)
		return &types.CommandResponse{
			Success: false,
			Error:   "Failed to create flag file directory: " + err.Error(),
		}, nil
	}

	if err := os.WriteFile(UninstallFlagFile, []byte(""), 0o644); err != nil {
		h.logger.Error("Failed to create uninstall flag file", "error", err, "file", UninstallFlagFile)
		return &types.CommandResponse{
			Success: false,
			Error:   "Failed to create uninstall flag file: " + err.Error(),
		}, nil
	}

	h.logger.Info("Agent uninstallation requested via flag file", "file", UninstallFlagFile)

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"success": true,
			"message": "Agent uninstallation requested successfully",
		},
	}, nil
}
