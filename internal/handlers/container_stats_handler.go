package handlers

import (
	"context"
	"encoding/json"
	"strings"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// ContainerStatsHandler handles requests to retrieve live statistics for a specific container.
type ContainerStatsHandler struct {
	*BaseHandler
}

// NewContainerStatsHandler creates a new container stats handler.
func NewContainerStatsHandler(logger *logger.Logger, services ServiceProvider) *ContainerStatsHandler {
	return &ContainerStatsHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "service.container.stats.live"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *ContainerStatsHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Fetch retrieves live container statistics for the requested service or container ID.
func (h *ContainerStatsHandler) Fetch(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Debug("Getting live stats for container")

	// Parse request
	var request types.ContainerStatsRequest
	if err := json.Unmarshal(data, &request); err != nil {
		h.logger.Error("Failed to parse container stats request", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format: " + err.Error(),
		}, nil
	}

	// Validate request
	if strings.TrimSpace(request.ContainerID) == "" && strings.TrimSpace(request.ServiceUID) == "" {
		h.logger.Error("Container identifier required")
		return &types.CommandResponse{
			Success: false,
			Error:   "either container_id or service_uid is required",
		}, nil
	}

	// Get Docker service
	dockerService := h.services.GetDockerService()
	if dockerService == nil {
		h.logger.Error("Docker service not available")
		return &types.CommandResponse{
			Success: false,
			Error:   "docker service not available",
		}, nil
	}

	containerID := strings.TrimSpace(request.ContainerID)
	if containerID == "" && request.ServiceUID != "" {
		resolved, err := h.resolveActiveContainer(ctx, request.ServiceUID)
		if err != nil {
			h.logger.Error("Failed to resolve active container", "service_uid", request.ServiceUID, "error", err)
			return &types.CommandResponse{
				Success: false,
				Error:   err.Error(),
			}, nil
		}

		containerID = resolved.ID
		if containerID == "" {
			containerID = resolved.Name
		}
	}

	// Get container stats using Docker API
	stats, err := dockerService.GetContainerStats(ctx, containerID)
	if err != nil {
		h.logger.Error("Failed to get container stats", "container_id", containerID, "service_uid", request.ServiceUID, "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "failed to get container stats: " + err.Error(),
		}, nil
	}

	h.logger.Debug("Successfully retrieved live container stats",
		"container_id", containerID,
		"container_name", stats.ContainerName,
		"cpu_usage", stats.CPU.Usage,
		"memory_usage", stats.Memory.Percent,
		"status", stats.Status)

	return &types.CommandResponse{
		Success: true,
		Data:    stats,
	}, nil
}
