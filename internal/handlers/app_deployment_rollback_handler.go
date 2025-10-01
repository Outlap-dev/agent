package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// AppDeploymentRollbackHandler handles application rollback requests
type AppDeploymentRollbackHandler struct {
	*BaseHandler
}

// AppDeploymentRollbackRequest represents the request structure for app rollback
type AppDeploymentRollbackRequest struct {
	ServiceUID    string `json:"service_uid"`
	DeploymentUID string `json:"deployment_uid,omitempty"`
	TargetVersion string `json:"target_version,omitempty"` // If empty, rollback to previous
	CommitSHA     string `json:"commit_sha,omitempty"`
	Force         bool   `json:"force,omitempty"` // Force rollback even if risky
}

// NewAppDeploymentRollbackHandler creates a new app deployment rollback handler
func NewAppDeploymentRollbackHandler(logger *logger.Logger, services ServiceProvider) *AppDeploymentRollbackHandler {
	return &AppDeploymentRollbackHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "service.deploy.rollback"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *AppDeploymentRollbackHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Rollback processes the app deployment rollback command
func (h *AppDeploymentRollbackHandler) Rollback(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request AppDeploymentRollbackRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format: " + err.Error(),
		}, nil
	}

	request.TargetVersion = strings.TrimSpace(request.TargetVersion)
	request.CommitSHA = strings.TrimSpace(request.CommitSHA)
	request.DeploymentUID = strings.TrimSpace(request.DeploymentUID)

	// Validate required fields
	if request.ServiceUID == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "service_uid is required",
		}, nil
	}

	h.logger.Info("Starting app deployment rollback",
		"service_uid", request.ServiceUID,
		"target_version", request.TargetVersion,
		"force", request.Force)

	// Send initial status update
	h.updateStatus(request.ServiceUID, "rolling_back", "Starting deployment rollback")

	// Step 1: Get current deployment status
	currentStatus, err := h.services.GetBuildService().GetDeploymentStatus(ctx, request.ServiceUID)
	if err != nil {
		h.logger.Error("Failed to get current deployment status", "error", err)
		h.updateStatus(request.ServiceUID, "failed", fmt.Sprintf("Failed to get deployment status: %v", err))
		return &types.CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get deployment status: %v", err),
		}, nil
	}

	if currentStatus == nil {
		h.updateStatus(request.ServiceUID, "failed", "No deployment found for service")
		return &types.CommandResponse{
			Success: false,
			Error:   "no deployment found for service: " + request.ServiceUID,
		}, nil
	}

	// Step 2: Get build history to find rollback target
	h.updateStatus(request.ServiceUID, "rolling_back", "Finding rollback target")

	buildHistory, err := h.services.GetBuildService().GetBuildHistory(ctx, request.ServiceUID)
	if err != nil {
		h.logger.Error("Failed to get build history", "error", err)
		h.updateStatus(request.ServiceUID, "failed", fmt.Sprintf("Failed to get build history: %v", err))
		return &types.CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get build history: %v", err),
		}, nil
	}

	if len(buildHistory) == 0 {
		h.updateStatus(request.ServiceUID, "failed", "No deployment history recorded yet")
		return &types.CommandResponse{
			Success: false,
			Error:   "no deployment history recorded for this service",
		}, nil
	}

	findByVersion := func(version string) *types.BuildResult {
		trimmed := strings.TrimSpace(strings.ToLower(version))
		for i := range buildHistory {
			entry := buildHistory[i]
			if strings.ToLower(entry.ImageName) == trimmed {
				return &buildHistory[i]
			}
			if entry.CommitSHA != "" {
				sha := strings.ToLower(entry.CommitSHA)
				if sha == trimmed || (len(trimmed) >= 6 && strings.HasPrefix(sha, trimmed)) {
					return &buildHistory[i]
				}
			}
		}
		return nil
	}

	findByDeploymentUID := func(uid string) *types.BuildResult {
		trimmed := strings.TrimSpace(strings.ToLower(uid))
		if trimmed == "" {
			return nil
		}
		for i := range buildHistory {
			entry := buildHistory[i]
			if strings.ToLower(entry.DeploymentUID) == trimmed {
				return &buildHistory[i]
			}
		}
		return nil
	}

	// Find the target build for rollback
	var targetBuild *types.BuildResult

	if request.DeploymentUID != "" {
		targetBuild = findByDeploymentUID(request.DeploymentUID)
		if targetBuild == nil {
			h.logger.Warn("Requested rollback deployment not present in local history", "deployment_uid", request.DeploymentUID, "service_uid", request.ServiceUID)
		}
	}

	if targetBuild == nil && request.TargetVersion != "" {
		targetBuild = findByVersion(request.TargetVersion)
		if targetBuild == nil {
			h.updateStatus(request.ServiceUID, "failed", "Target version not found in build history")
			return &types.CommandResponse{
				Success: false,
				Error:   "target version not found in build history: " + request.TargetVersion,
			}, nil
		}
	}

	if targetBuild == nil && request.CommitSHA != "" {
		targetBuild = findByVersion(request.CommitSHA)
		if targetBuild == nil {
			h.updateStatus(request.ServiceUID, "failed", "Requested commit not available on this server")
			return &types.CommandResponse{
				Success: false,
				Error:   "commit not available in local build history: " + request.CommitSHA,
			}, nil
		}
	}

	if targetBuild == nil {
		if len(buildHistory) < 2 {
			h.updateStatus(request.ServiceUID, "failed", "No previous successful deployment to rollback to")
			return &types.CommandResponse{
				Success: false,
				Error:   "no previous successful deployment found; deploy at least twice before rolling back",
			}, nil
		}
		// Use previous build (second most recent)
		targetBuild = &buildHistory[1]
	}

	rollbackImage := strings.TrimSpace(targetBuild.ImageName)
	if rollbackImage == "" && targetBuild.CommitSHA != "" {
		short := targetBuild.CommitSHA
		if len(short) > 12 {
			short = short[:12]
		}
		rollbackImage = fmt.Sprintf("pulseup-app-%s:%s", request.ServiceUID, short)
	}

	if rollbackImage == "" {
		h.updateStatus(request.ServiceUID, "failed", "Rollback target is missing an image reference")
		return &types.CommandResponse{
			Success: false,
			Error:   "rollback target does not contain a usable image reference",
		}, nil
	}

	h.logger.Info("Found rollback target",
		"service_uid", request.ServiceUID,
		"target_image", rollbackImage,
		"commit_sha", targetBuild.CommitSHA)

	// Step 3: Stop current container
	h.updateStatus(request.ServiceUID, "rolling_back", "Stopping current deployment")

	if err := h.services.GetDockerService().StopContainer(ctx, request.ServiceUID); err != nil {
		h.logger.Warn("Failed to stop current container", "error", err)
		if !request.Force {
			h.updateStatus(request.ServiceUID, "failed", fmt.Sprintf("Failed to stop current container: %v", err))
			return &types.CommandResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to stop current container: %v", err),
			}, nil
		}
		h.logger.Info("Continuing rollback despite stop failure (force=true)")
	}

	// Step 4: Remove current container
	h.updateStatus(request.ServiceUID, "rolling_back", "Removing current container")

	if err := h.services.GetDockerService().RemoveContainer(ctx, request.ServiceUID); err != nil {
		h.logger.Warn("Failed to remove current container", "error", err)
		if !request.Force {
			h.updateStatus(request.ServiceUID, "failed", fmt.Sprintf("Failed to remove current container: %v", err))
			return &types.CommandResponse{
				Success: false,
				Error:   fmt.Sprintf("Failed to remove current container: %v", err),
			}, nil
		}
		h.logger.Info("Continuing rollback despite removal failure (force=true)")
	}

	// Step 5: Deploy the target version
	h.updateStatus(request.ServiceUID, "rolling_back", "Deploying rollback version")

	deployConfig := &types.DeployConfig{
		Name:      request.ServiceUID,
		ImageName: rollbackImage,
		Port:      currentStatus.Port,
	}

	deployResult, err := h.services.GetBuildService().DeployApplication(ctx, deployConfig)
	if err != nil {
		h.logger.Error("Failed to deploy rollback version", "error", err)
		h.updateStatus(request.ServiceUID, "failed", fmt.Sprintf("Failed to deploy rollback version: %v", err))
		return &types.CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to deploy rollback version: %v", err),
		}, nil
	}

	if !deployResult.Success {
		h.logger.Error("Rollback deployment failed", "error", deployResult.Error)
		h.updateStatus(request.ServiceUID, "failed", fmt.Sprintf("Rollback deployment failed: %s", deployResult.Error))
		return &types.CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Rollback deployment failed: %s", deployResult.Error),
		}, nil
	}

	h.logger.Info("Rollback completed successfully",
		"service_uid", request.ServiceUID,
		"rolled_back_to", targetBuild.ImageName,
		"container_id", deployResult.ContainerID)

	// Final status update
	h.updateStatus(request.ServiceUID, "running", "Rollback completed successfully")

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"service_uid":      request.ServiceUID,
			"rolled_back_to":   rollbackImage,
			"container_id":     deployResult.ContainerID,
			"port":             deployResult.Port,
			"rollback_time":    deployResult.DeployTime,
			"previous_version": currentStatus.Name,
			"status":           "running",
			"commit_sha":       targetBuild.CommitSHA,
			"commit_message":   targetBuild.CommitMessage,
		},
	}, nil
}

// updateStatus sends status updates via WebSocket
func (h *AppDeploymentRollbackHandler) updateStatus(serviceUID, status, message string) {
	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil {
		h.logger.Warn("WebSocket manager not available for status update")
		return
	}

	statusUpdate := map[string]interface{}{
		"service_uid": serviceUID,
		"status":      status,
		"message":     message,
		"timestamp":   h.getCurrentTimestamp(),
	}

	if err := wsManager.Emit("rollback_status_update", statusUpdate); err != nil {
		h.logger.Error("Failed to send status update", "error", err)
	}
}

// getCurrentTimestamp returns the current Unix timestamp
func (h *AppDeploymentRollbackHandler) getCurrentTimestamp() int64 {
	return h.getCurrentTime().Unix()
}

// getCurrentTime returns the current time (can be mocked for testing)
func (h *AppDeploymentRollbackHandler) getCurrentTime() interface{ Unix() int64 } {
	return timeProvider{}
}

type timeProvider struct{}

func (timeProvider) Unix() int64 {
	return time.Now().Unix()
}
