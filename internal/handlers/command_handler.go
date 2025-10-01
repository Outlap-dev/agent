package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// CommandHandler aggregates list and execution of whitelisted commands.
type CommandHandler struct {
	*BaseHandler
}

// NewCommandHandler constructs a command controller backed by the provided services.
func NewCommandHandler(logger *logger.Logger, services ServiceProvider) *CommandHandler {
	return &CommandHandler{
		BaseHandler: NewBaseHandler(logger.With("controller", "agent.command"), services),
	}
}

// Base exposes the embedded base handler for router helpers.
func (h *CommandHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// ExecuteCommandRequest captures payload for executing a whitelisted command.
type ExecuteCommandRequest struct {
	CommandID string            `json:"command_id"`
	Args      map[string]string `json:"args"`
}

// Execute runs a whitelisted command via the command service.
func (h *CommandHandler) Execute(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req ExecuteCommandRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "Invalid request data: " + err.Error()}, nil
	}

	h.logger.Info("Executing whitelisted command", "command_id", req.CommandID)

	commandService := h.services.GetCommandService()
	if commandService == nil {
		return &types.CommandResponse{Success: false, Error: "Command service not available"}, nil
	}

	if !commandService.IsCommandWhitelisted(req.CommandID) {
		return &types.CommandResponse{Success: false, Error: fmt.Sprintf("Command '%s' is not whitelisted", req.CommandID)}, nil
	}

	result, err := commandService.ExecuteWhitelistedCommand(ctx, req.CommandID, req.Args)
	if err != nil {
		h.logger.Error("Command execution failed", "command_id", req.CommandID, "error", err)
		return &types.CommandResponse{Success: false, Error: fmt.Sprintf("Command execution failed: %v", err)}, nil
	}

	return &types.CommandResponse{
		Success: result.Success,
		Data: map[string]interface{}{
			"output":    result.Output,
			"error":     result.Error,
			"timestamp": result.Timestamp,
		},
	}, nil
}

// List enumerates the available whitelisted commands.
func (h *CommandHandler) List(ctx context.Context, _ json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Listing whitelisted commands")

	commandService := h.services.GetCommandService()
	if commandService == nil {
		return &types.CommandResponse{Success: false, Error: "Command service not available"}, nil
	}

	commands := commandService.GetAvailableCommands()

	commandsByCategory := make(map[string][]map[string]interface{})
	for _, cmd := range commands {
		category := cmd.Category
		if category == "" {
			category = "other"
		}

		commandInfo := map[string]interface{}{
			"id":                    cmd.ID,
			"name":                  cmd.Name,
			"description":           cmd.Description,
			"requires_confirmation": cmd.RequiresConfirmation,
		}

		if len(cmd.Args) > 0 {
			commandInfo["args"] = cmd.Args
		}

		commandsByCategory[category] = append(commandsByCategory[category], commandInfo)
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"commands":             commands,
			"commands_by_category": commandsByCategory,
			"total_commands":       len(commands),
		},
	}, nil
}
