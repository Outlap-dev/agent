package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

const serviceUIDLabelKey = "outlap.service_uid"

// serviceControlRequest represents the shared request payload for service lifecycle commands.
type serviceControlRequest struct {
	ServiceUID string `json:"service_uid"`
}

// ============================================================================
// ServiceLifecycleHandler - Single handler for all lifecycle operations
// ============================================================================

// ServiceLifecycleHandler handles all service lifecycle operations (start, stop, restart, delete).
type ServiceLifecycleHandler struct {
	*BaseHandler
}

// NewServiceLifecycleHandler creates a new service lifecycle handler.
func NewServiceLifecycleHandler(logger *logger.Logger, services ServiceProvider) *ServiceLifecycleHandler {
	return &ServiceLifecycleHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "service.lifecycle"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *ServiceLifecycleHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Start processes the start service command.
func (h *ServiceLifecycleHandler) Start(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req serviceControlRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}

	req.ServiceUID = strings.TrimSpace(req.ServiceUID)
	if req.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}

	dockerSvc := h.services.GetDockerService()
	if dockerSvc == nil {
		return &types.CommandResponse{Success: false, Error: "docker service not available"}, nil
	}

	h.logger.Info("received start service request", "service_uid", req.ServiceUID)

	containers, lookupErrs := findServiceContainers(ctx, dockerSvc, h.services.GetDeploymentService(), req.ServiceUID, h.logger)
	if len(lookupErrs) > 0 {
		for _, err := range lookupErrs {
			h.logger.Warn("container lookup issue", "service_uid", req.ServiceUID, "error", err)
		}
	}

	if len(containers) == 0 {
		errMsg := fmt.Sprintf("no containers found for service %s", req.ServiceUID)
		if len(lookupErrs) > 0 {
			errMsg = fmt.Sprintf("%s (%s)", errMsg, flattenErrors(lookupErrs))
		}
		h.logger.Error("unable to locate containers for service", "service_uid", req.ServiceUID)
		return &types.CommandResponse{Success: false, Error: errMsg}, nil
	}

	var started string
	for _, name := range containers {
		h.logger.Info("attempting to start container", "service_uid", req.ServiceUID, "container", name)
		if err := dockerSvc.StartContainerByName(ctx, name); err != nil {
			h.logger.Error("failed to start container", "service_uid", req.ServiceUID, "container", name, "error", err)
			return &types.CommandResponse{Success: false, Error: fmt.Sprintf("failed to start container %s: %v", name, err)}, nil
		}
		started = name
		break
	}

	if started == "" {
		errMsg := fmt.Sprintf("no containers could be started for service %s", req.ServiceUID)
		h.logger.Error("no containers started", "service_uid", req.ServiceUID)
		return &types.CommandResponse{Success: false, Error: errMsg}, nil
	}

	h.logger.Info("service container started", "service_uid", req.ServiceUID, "container", started)

	if statusSvc := h.services.GetStatusService(); statusSvc != nil {
		if err := statusSvc.UpdateServiceStatus(ctx, req.ServiceUID, types.ServiceStatusRunning, ""); err != nil {
			h.logger.Warn("failed to update service status", "service_uid", req.ServiceUID, "error", err)
		}
	}

	payload := map[string]interface{}{
		"service_uid": req.ServiceUID,
		"container":   started,
		"message":     fmt.Sprintf("service %s started successfully", req.ServiceUID),
	}

	return &types.CommandResponse{Success: true, Data: payload}, nil
}

// Stop processes the stop service command.
func (h *ServiceLifecycleHandler) Stop(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req serviceControlRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}

	req.ServiceUID = strings.TrimSpace(req.ServiceUID)
	if req.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}

	dockerSvc := h.services.GetDockerService()
	if dockerSvc == nil {
		return &types.CommandResponse{Success: false, Error: "docker service not available"}, nil
	}

	h.logger.Info("received stop service request", "service_uid", req.ServiceUID)

	containers, lookupErrs := findServiceContainers(ctx, dockerSvc, h.services.GetDeploymentService(), req.ServiceUID, h.logger)
	stopped := make([]string, 0)
	errorMessages := make([]string, 0, len(lookupErrs))

	for _, err := range lookupErrs {
		h.logger.Warn("container lookup issue", "service_uid", req.ServiceUID, "error", err)
		errorMessages = append(errorMessages, err.Error())
	}

	for _, name := range containers {
		h.logger.Info("attempting to stop container", "service_uid", req.ServiceUID, "container", name)
		if err := dockerSvc.StopContainerByName(ctx, name); err != nil {
			h.logger.Error("failed to stop container", "service_uid", req.ServiceUID, "container", name, "error", err)
			errorMessages = append(errorMessages, fmt.Sprintf("failed to stop container %s: %v", name, err))
			continue
		}
		stopped = append(stopped, name)
	}

	if statusSvc := h.services.GetStatusService(); statusSvc != nil {
		if err := statusSvc.UpdateServiceStatus(ctx, req.ServiceUID, types.ServiceStatusStopped, ""); err != nil {
			h.logger.Warn("failed to update service status", "service_uid", req.ServiceUID, "error", err)
			errorMessages = append(errorMessages, fmt.Sprintf("failed to update service status: %v", err))
		}
	}

	payload := map[string]interface{}{
		"service_uid":        req.ServiceUID,
		"stopped_containers": stopped,
	}

	if len(errorMessages) > 0 {
		payload["errors"] = errorMessages
		return &types.CommandResponse{Success: false, Data: payload, Error: strings.Join(errorMessages, "; ")}, nil
	}

	if len(stopped) == 0 {
		payload["message"] = fmt.Sprintf("no running containers found for service %s", req.ServiceUID)
		return &types.CommandResponse{Success: true, Data: payload}, nil
	}

	payload["message"] = fmt.Sprintf("stopped %d container(s) for service %s", len(stopped), req.ServiceUID)
	return &types.CommandResponse{Success: true, Data: payload}, nil
}

// Restart processes the restart service command.
func (h *ServiceLifecycleHandler) Restart(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req serviceControlRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.CommandResponse{Success: false, Error: "invalid request format: " + err.Error()}, nil
	}

	req.ServiceUID = strings.TrimSpace(req.ServiceUID)
	if req.ServiceUID == "" {
		return &types.CommandResponse{Success: false, Error: "service_uid is required"}, nil
	}

	dockerSvc := h.services.GetDockerService()
	if dockerSvc == nil {
		return &types.CommandResponse{Success: false, Error: "docker service not available"}, nil
	}

	h.logger.Info("received restart service request", "service_uid", req.ServiceUID)

	containers, lookupErrs := findServiceContainers(ctx, dockerSvc, h.services.GetDeploymentService(), req.ServiceUID, h.logger)
	if len(lookupErrs) > 0 {
		for _, err := range lookupErrs {
			h.logger.Warn("container lookup issue", "service_uid", req.ServiceUID, "error", err)
		}
	}

	if len(containers) == 0 {
		errMsg := fmt.Sprintf("no containers found for service %s", req.ServiceUID)
		if len(lookupErrs) > 0 {
			errMsg = fmt.Sprintf("%s (%s)", errMsg, flattenErrors(lookupErrs))
		}
		h.logger.Error("unable to locate containers for restart", "service_uid", req.ServiceUID)
		return &types.CommandResponse{Success: false, Error: errMsg}, nil
	}

	target := containers[0]

	if err := dockerSvc.StopContainerByName(ctx, target); err != nil {
		h.logger.Warn("failed to stop container during restart", "service_uid", req.ServiceUID, "container", target, "error", err)
	}

	if err := dockerSvc.StartContainerByName(ctx, target); err != nil {
		h.logger.Error("failed to start container during restart", "service_uid", req.ServiceUID, "container", target, "error", err)
		return &types.CommandResponse{Success: false, Error: fmt.Sprintf("failed to restart container %s: %v", target, err)}, nil
	}

	h.logger.Info("service container restarted", "service_uid", req.ServiceUID, "container", target)

	if statusSvc := h.services.GetStatusService(); statusSvc != nil {
		if err := statusSvc.UpdateServiceStatus(ctx, req.ServiceUID, types.ServiceStatusRunning, ""); err != nil {
			h.logger.Warn("failed to update service status", "service_uid", req.ServiceUID, "error", err)
		}
	}

	payload := map[string]interface{}{
		"service_uid": req.ServiceUID,
		"container":   target,
		"message":     fmt.Sprintf("service %s restarted successfully", req.ServiceUID),
	}

	return &types.CommandResponse{Success: true, Data: payload}, nil
}

// ServiceDeletionRequest represents the request structure for service deletion.
type ServiceDeletionRequest struct {
	ServiceUID string `json:"service_uid"`
}

// Delete processes the service deletion command.
func (h *ServiceLifecycleHandler) Delete(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request ServiceDeletionRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format: " + err.Error(),
		}, nil
	}

	// Validate required fields
	if request.ServiceUID == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "Missing required field: service_uid",
		}, nil
	}

	dockerService := h.services.GetDockerService()
	if dockerService == nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "Docker service not available",
		}, nil
	}

	var (
		containersDeleted []string
		errors            []string
	)

	containerSet := make(map[string]struct{})

	if deploymentSvc := h.services.GetDeploymentService(); deploymentSvc != nil {
		instances, err := deploymentSvc.ListServiceContainers(ctx, request.ServiceUID)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to list managed containers: %v", err))
			h.logger.Warn("failed to list service containers", "service_uid", request.ServiceUID, "error", err)
		} else {
			for _, inst := range instances {
				name := strings.TrimSpace(inst.Name)
				if name != "" {
					containerSet[name] = struct{}{}
				}
			}
		}
	}

	if labelMatches, err := dockerService.FindContainersByLabel(ctx, serviceUIDLabelKey, request.ServiceUID); err != nil {
		errors = append(errors, fmt.Sprintf("Failed to lookup containers by label: %v", err))
		h.logger.Warn("label lookup failed", "service_uid", request.ServiceUID, "error", err)
	} else {
		for _, match := range labelMatches {
			name := strings.TrimSpace(strings.TrimPrefix(match, "/"))
			if name != "" {
				containerSet[name] = struct{}{}
			}
		}
	}

	// Include legacy and database container names as fallbacks
	containerSet[fmt.Sprintf("outlap-app-%s", request.ServiceUID)] = struct{}{}
	containerSet[fmt.Sprintf("outlap-db-%s", request.ServiceUID)] = struct{}{}

	// Delete containers
	for containerName := range containerSet {
		h.logger.Info("attempting to remove container", "service_uid", request.ServiceUID, "container_name", containerName)
		if err := dockerService.RemoveContainer(ctx, containerName); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to remove container %s", containerName))
			h.logger.Error("Error removing container", "container", containerName, "error", err)
		} else {
			containersDeleted = append(containersDeleted, containerName)
		}
	}

	// Clean up any deployment images for this service
	if err := dockerService.CleanupOldDeploymentImages(ctx, request.ServiceUID); err != nil {
		errors = append(errors, fmt.Sprintf("Error cleaning up deployment images: %v", err))
		h.logger.Error("Error cleaning up deployment images", "service_uid", request.ServiceUID, "error", err)
	}

	responseData := map[string]interface{}{
		"service_uid":        request.ServiceUID,
		"containers_deleted": containersDeleted,
		"deletion_count":     len(containersDeleted),
	}

	if len(errors) > 0 {
		responseData["warnings"] = errors
	}

	if len(containersDeleted) == 0 && len(errors) > 0 {
		return &types.CommandResponse{
			Success: false,
			Error:   "Failed to delete any containers for service " + request.ServiceUID,
			Data:    responseData,
		}, nil
	}

	responseData["message"] = fmt.Sprintf("Successfully deleted %d container(s) for service %s", len(containersDeleted), request.ServiceUID)

	return &types.CommandResponse{
		Success: true,
		Data:    responseData,
	}, nil
}

// ============================================================================
// Shared Helper Functions
// ============================================================================

func findServiceContainers(ctx context.Context, dockerSvc DockerService, deploymentSvc DeploymentService, serviceUID string, log *logger.Logger) ([]string, []error) {
	var (
		names  []string
		errors []error
	)

	if deploymentSvc != nil {
		instances, err := deploymentSvc.ListServiceContainers(ctx, serviceUID)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to list containers from deployment service: %w", err))
		} else {
			names = make([]string, 0, len(instances))
			for _, inst := range instances {
				names = append(names, inst.Name)
			}
			if log != nil {
				log.Debug("deployment service reported containers", "service_uid", serviceUID, "containers", names)
			}
		}
	}

	seen := make(map[string]struct{}, len(names))
	for _, name := range names {
		seen[name] = struct{}{}
	}

	labelMatches, err := dockerSvc.FindContainersByLabel(ctx, serviceUIDLabelKey, serviceUID)
	if err != nil {
		errors = append(errors, fmt.Errorf("failed to list containers by label: %w", err))
	} else if log != nil {
		log.Debug("label lookup returned containers", "service_uid", serviceUID, "containers", labelMatches)
	}
	for _, name := range labelMatches {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		names = append(names, trimmed)
		seen[trimmed] = struct{}{}
	}

	if log != nil {
		log.Debug("resolved service containers", "service_uid", serviceUID, "containers", names)
	}

	return names, errors
}

func flattenErrors(errs []error) string {
	if len(errs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}
