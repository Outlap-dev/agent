package handlers

import (
	"context"
	"encoding/json"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// ServiceStatusHandler handles requests to retrieve service status information.
type ServiceStatusHandler struct {
	*BaseHandler
}

// ServiceStatusRequest represents the request structure for service status retrieval.
type ServiceStatusRequest struct {
	ServiceUID string `json:"service_uid"`
}

// NewServiceStatusHandler creates a new service status handler.
func NewServiceStatusHandler(logger *logger.Logger, services ServiceProvider) *ServiceStatusHandler {
	return &ServiceStatusHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "service.status.get"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *ServiceStatusHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Get returns the status of the requested service.
func (h *ServiceStatusHandler) Get(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request ServiceStatusRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format: " + err.Error(),
		}, nil
	}

	if request.ServiceUID == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "service_uid is required",
		}, nil
	}

	h.logger.Info("Getting service status", "service_uid", request.ServiceUID)

	// Get container status from Docker service
	status, err := h.services.GetDockerService().GetContainerStatus(ctx, request.ServiceUID)
	if err != nil {
		h.logger.Error("Failed to get container status", "service_uid", request.ServiceUID, "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "failed to get container status: " + err.Error(),
		}, nil
	}

	// Get deployment status from Build service
	deploymentStatus, err := h.services.GetBuildService().GetDeploymentStatus(ctx, request.ServiceUID)
	if err != nil {
		h.logger.Warn("Failed to get deployment status", "service_uid", request.ServiceUID, "error", err)
		// Don't fail the request if deployment status is not available
		deploymentStatus = nil
	}

	h.logger.Info("Successfully retrieved service status",
		"service_uid", request.ServiceUID,
		"status", status)

	responseData := map[string]interface{}{
		"service_uid": request.ServiceUID,
		"status":      status,
	}

	// Add deployment information if available
	if deploymentStatus != nil {
		responseData["deployment"] = map[string]interface{}{
			"name":       deploymentStatus.Name,
			"status":     deploymentStatus.Status,
			"port":       deploymentStatus.Port,
			"updated_at": deploymentStatus.UpdatedAt,
			"error":      deploymentStatus.Error,
		}
	}

	return &types.CommandResponse{
		Success: true,
		Data:    responseData,
	}, nil
}
