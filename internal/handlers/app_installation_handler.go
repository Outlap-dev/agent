package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
)

// AppInstallationHandler handles application installation requests
type AppInstallationHandler struct {
	*BaseHandler
}

// AppInstallationRequest represents the request structure for app installation
type AppInstallationRequest struct {
	ServiceUID  string                 `json:"service_uid"`
	AccessToken string                 `json:"access_token"`
	GitHubRepo  string                 `json:"github_repo"`
	Service     map[string]interface{} `json:"service,omitempty"`
}

// NewAppInstallationHandler creates a new app installation handler
func NewAppInstallationHandler(logger *logger.Logger, services ServiceProvider) *AppInstallationHandler {
	return &AppInstallationHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "app_installation"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *AppInstallationHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Install processes the app installation command - clones and prepares build without building
func (h *AppInstallationHandler) Install(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request AppInstallationRequest
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
			Error:   "service_uid is required",
		}, nil
	}

	if request.AccessToken == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "access_token is required",
		}, nil
	}

	if request.GitHubRepo == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "github_repo is required",
		}, nil
	}

	h.logger.Info("Installing app", "service_uid", request.ServiceUID, "github_repo", request.GitHubRepo)

	// Check if repo is already cloned
	baseCloneDir := "/opt/pulseup/apps"
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_CLONE_DIR"); debugDir != "" {
			baseCloneDir = debugDir
		}
	}
	clonePath := filepath.Join(baseCloneDir, request.ServiceUID)
	if _, err := os.Stat(clonePath); err == nil {
		h.logger.Info("Repository already exists", "service_uid", request.ServiceUID, "clone_path", clonePath)

		// Refresh the build setup - not an initial clone
		if err := h.services.GetBuildService().PrepareBuild(ctx, clonePath, request.ServiceUID, false); err != nil {
			h.logger.Error("Failed to prepare build", "error", err)
			return &types.CommandResponse{
				Success: false,
				Error:   "Failed to prepare build: " + err.Error(),
			}, nil
		}

		return &types.CommandResponse{
			Success: true,
			Data: map[string]interface{}{
				"success":    true,
				"clone_path": clonePath,
			},
		}, nil
	}

	// Repository doesn't exist, clone it directly using provided access token and repo
	cloneResult, err := h.cloneGitHubRepoWithToken(ctx, request.GitHubRepo, request.AccessToken, request.ServiceUID)
	if err != nil {
		h.logger.Error("Failed to clone GitHub repository", "service_uid", request.ServiceUID, "github_repo", request.GitHubRepo, "error", err)
		h.updateServiceStatus(request.ServiceUID, types.ServiceStatusFailed, "Failed to clone repository: "+err.Error())
		return &types.CommandResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	if !cloneResult.Success {
		h.logger.Error("Clone failed", "service_uid", request.ServiceUID, "github_repo", request.GitHubRepo, "error", cloneResult.Error)
		h.updateServiceStatus(request.ServiceUID, types.ServiceStatusFailed, cloneResult.Error)
		return &types.CommandResponse{
			Success: false,
			Error:   cloneResult.Error,
		}, nil
	}

	h.logger.Info("Repository cloned successfully", "clone_path", cloneResult.ClonePath)

	// Prepare build setup - this is a fresh clone, so set is_initial_clone=true
	if err := h.services.GetBuildService().PrepareBuild(ctx, cloneResult.ClonePath, request.ServiceUID, true); err != nil {
		h.logger.Error("Failed to prepare build", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "Failed to prepare build: " + err.Error(),
		}, nil
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"success":    true,
			"clone_path": cloneResult.ClonePath,
		},
	}, nil
}

// cloneGitHubRepoWithToken clones a GitHub repository using the provided access token
func (h *AppInstallationHandler) cloneGitHubRepoWithToken(ctx context.Context, githubRepo, accessToken, serviceUID string) (*types.CloneResult, error) {
	h.logger.Info("Cloning GitHub repository with token", "github_repo", githubRepo, "service_uid", serviceUID)

	// Construct the clone path using the service UID
	baseCloneDir := "/opt/pulseup/apps"
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_CLONE_DIR"); debugDir != "" {
			baseCloneDir = debugDir
		}
	}
	clonePath := filepath.Join(baseCloneDir, serviceUID)

	// Check if directory already exists
	if _, err := os.Stat(clonePath); err == nil {
		h.logger.Info("Repository already exists", "clone_path", clonePath)
		return &types.CloneResult{
			Success:   true,
			ClonePath: clonePath,
		}, nil
	}

	// Construct the full GitHub URL from repo name
	repoURL := "https://github.com/" + githubRepo + ".git"

	// Clone the repository with token authentication
	if err := h.cloneWithToken(ctx, repoURL, accessToken, clonePath); err != nil {
		return &types.CloneResult{
			Success: false,
			Error:   "Failed to clone repository: " + err.Error(),
		}, nil
	}

	h.logger.Info("Repository cloned successfully", "clone_path", clonePath)
	return &types.CloneResult{
		Success:   true,
		ClonePath: clonePath,
	}, nil
}

// cloneWithToken clones a repository using token authentication
func (h *AppInstallationHandler) cloneWithToken(ctx context.Context, repoURL, accessToken, clonePath string) error {
	h.logger.Debug("Cloning repository with token", "repo_url", repoURL, "clone_path", clonePath)

	// Ensure the target directory exists
	if err := os.MkdirAll(clonePath, 0755); err != nil {
		return fmt.Errorf("failed to create clone directory: %w", err)
	}

	// Clone the repository with token authentication
	cloneOptions := &git.CloneOptions{
		URL: repoURL,
		Auth: &http.BasicAuth{
			Username: "oauth2",
			Password: accessToken,
		},
	}

	_, err := git.PlainCloneContext(ctx, clonePath, false, cloneOptions)
	if err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}

	return nil
}

// updateServiceStatus updates the service status using the status service
func (h *AppInstallationHandler) updateServiceStatus(serviceUID string, status types.ServiceStatus, errorMessage string) {
	statusService := h.services.GetStatusService()
	if statusService == nil {
		h.logger.Warn("Status service not available for status update", "service_uid", serviceUID)
		return
	}

	ctx := context.Background()
	if err := statusService.UpdateServiceStatus(ctx, serviceUID, status, errorMessage); err != nil {
		h.logger.Error("Failed to update service status", "service_uid", serviceUID, "status", status, "error", err)
	}
}

// updateStatus sends status updates via WebSocket (legacy method)
func (h *AppInstallationHandler) updateStatus(serviceUID, status, message string) {
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

	if err := wsManager.Emit("service_status_update", statusUpdate); err != nil {
		h.logger.Error("Failed to send status update", "error", err)
	}
}

// getCurrentTimestamp returns the current Unix timestamp
func (h *AppInstallationHandler) getCurrentTimestamp() int64 {
	return time.Now().Unix()
}
