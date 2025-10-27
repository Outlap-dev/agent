package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"

	"github.com/docker/docker/errdefs"
)

// ServiceStatusHandler handles requests to retrieve service status information.
type ServiceStatusHandler struct {
	*BaseHandler
}

func (h *ServiceStatusHandler) resolveContainerStatus(ctx context.Context, dockerSvc DockerService, serviceUID string) (types.ServiceStatus, error) {
	if dockerSvc == nil {
		return types.ServiceStatusStopped, fmt.Errorf("docker service not available")
	}

	status, err := dockerSvc.GetContainerStatus(ctx, serviceUID)
	if err == nil {
		return status, nil
	}
	lastErr := err

	trimmedUID := strings.TrimSpace(serviceUID)
	if trimmedUID == "" {
		if err != nil && errdefs.IsNotFound(err) {
			return types.ServiceStatusStopped, nil
		}
		return types.ServiceStatusStopped, err
	}

	matches, lookupErr := dockerSvc.FindContainersByLabel(ctx, serviceUIDLabelKey, trimmedUID)
	if lookupErr != nil {
		h.logger.Warn("label lookup failed", "service_uid", trimmedUID, "error", lookupErr)
		return types.ServiceStatusStopped, lookupErr
	}
	if len(matches) == 0 {
		if lastErr != nil && errdefs.IsNotFound(lastErr) {
			return types.ServiceStatusStopped, nil
		}
		return types.ServiceStatusStopped, lastErr
	}

	for _, candidate := range matches {
		name := strings.TrimSpace(strings.TrimPrefix(candidate, "/"))
		if name == "" {
			continue
		}
		status, inspectErr := dockerSvc.GetContainerStatus(ctx, name)
		if inspectErr == nil {
			return status, nil
		}
		lastErr = inspectErr
		h.logger.Warn("failed to inspect container from label", "service_uid", trimmedUID, "container", name, "error", inspectErr)
	}

	if lastErr != nil && errdefs.IsNotFound(lastErr) {
		return types.ServiceStatusStopped, nil
	}
	return types.ServiceStatusStopped, lastErr
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

	dockerSvc := h.services.GetDockerService()
	status, err := h.resolveContainerStatus(ctx, dockerSvc, request.ServiceUID)
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
