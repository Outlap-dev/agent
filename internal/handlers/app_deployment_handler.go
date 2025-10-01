package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// DeployApplicationHandler handles application deployment requests
type DeployApplicationHandler struct {
	*BaseHandler
}

type appDeploymentStrategy interface {
	Deploy(ctx context.Context, opts *appDeploymentOptions) (*types.DeploymentResult, error)
}

type appDeploymentOptions struct {
	Request   *types.DeployApplicationRequest
	BuildInfo *types.BuildCommandInfo
	ClonePath string
	EnvVars   map[string]string
	Networks  []string
}

// NewDeployApplicationHandler creates a new deployment handler
func NewDeployApplicationHandler(logger *logger.Logger, services ServiceProvider) *DeployApplicationHandler {
	return &DeployApplicationHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "deploy_application"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *DeployApplicationHandler) Base() *BaseHandler {
	return h.BaseHandler
}

func (h *DeployApplicationHandler) selectDeploymentStrategy(method types.DeploymentMethod) (appDeploymentStrategy, error) {
	switch method {
	case types.DeploymentMethodDockerCompose:
		return &dockerComposeStrategy{handler: h}, nil
	case types.DeploymentMethodDockerfile:
		return &dockerfileStrategy{handler: h}, nil
	case types.DeploymentMethodNixpacks:
		return &nixpacksStrategy{handler: h}, nil
	default:
		return nil, fmt.Errorf("unsupported build type: %s", method)
	}
}

// Deploy processes the deployment request
func (h *DeployApplicationHandler) Deploy(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Handling deploy application request")

	// Parse deployment request
	var request types.DeployApplicationRequest
	if err := json.Unmarshal(data, &request); err != nil {
		h.logger.Error("Failed to parse deployment request", "error", err)
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

	if request.DeploymentUID == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "deployment_uid is required",
		}, nil
	}

	if request.GitHubRepo == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "github_repo is required",
		}, nil
	}

	if request.AccessToken == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "access_token is required",
		}, nil
	}

	h.logger.Info("Starting deployment",
		"service_uid", request.ServiceUID,
		"deployment_uid", request.DeploymentUID)

	// Update status to indicate deployment started
	if err := h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusInProgress, "", nil); err != nil {
		h.logger.Error("Failed to update deployment status to in progress", "error", err)
	}

	deploymentDir := "/opt/pulseup/apps"
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_DEPLOYMENT_DIR"); debugDir != "" {
			deploymentDir = debugDir
		}
	}

	// Use the standard app deployment path based on service UID
	clonePath := filepath.Join(deploymentDir, request.ServiceUID)
	isInitialClone := !h.pathExists(clonePath)

	var commitSHA string
	var commitMessage string
	var err error

	gitService := h.services.GetGitService()
	if gitService == nil {
		h.logger.Error("Git service not available for deployment")
		return &types.CommandResponse{
			Success: false,
			Error:   "git service not available",
		}, nil
	}

	// Clone or pull the repository using the GitHub repo URL and access token from the request
	if isInitialClone {
		h.logger.Info("Cloning repository for first deployment", "repo", request.GitHubRepo, "path", clonePath)

		// Use the new direct clone method that doesn't require server calls
		cloneResult, err := gitService.CloneGitHubRepoDirectly(ctx, request.GitHubRepo, request.AccessToken, clonePath, request.GitHubBranch)
		if err != nil || !cloneResult.Success {
			errorMsg := "Clone failed"
			if err != nil {
				errorMsg = fmt.Sprintf("Clone failed: %v", err)
			} else if cloneResult.Error != "" {
				errorMsg = fmt.Sprintf("Clone failed: %s", cloneResult.Error)
			}
			h.logger.Error(errorMsg)
			h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
			return &types.CommandResponse{
				Success: false,
				Error:   errorMsg,
			}, nil
		}

		h.logger.Info("Repository cloned successfully", "path", clonePath)
	} else {
		h.logger.Info("Pulling latest changes for existing repository", "path", clonePath)

		// Use the new direct pull method to get the latest commit
		if _, err := gitService.PullGitHubRepoDirectly(ctx, clonePath, request.AccessToken, request.GitHubBranch); err != nil {
			h.logger.Warn("Failed to pull latest changes", "error", err)
			// Don't fail the deployment if pull fails, continue with existing code
		}
	}

	commitSHA, err = gitService.GetCommitSHA(ctx, clonePath)
	if err != nil {
		h.logger.Error("Failed to determine commit SHA", "error", err)
		h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusFailed, fmt.Sprintf("Failed to determine commit SHA: %v", err), nil)
		return &types.CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to determine commit sha: %v", err),
		}, nil
	}

	commitMessage, err = gitService.GetCommitMessage(ctx, clonePath, commitSHA)
	if err != nil {
		h.logger.Warn("Failed to read commit message", "error", err)
		commitMessage = ""
	}

	deploymentMethod := h.extractDeploymentMethod(request.Service)

	var buildInfo *types.BuildCommandInfo
	if deploymentMethod != types.DeploymentMethodDockerCompose || deploymentMethod == "" {
		var resolveErr error
		buildInfo, resolveErr = h.resolveBuildCommandInfo(ctx, request.ServiceUID, clonePath, isInitialClone)
		if resolveErr != nil {
			errorMsg := resolveErr.Error()
			h.logger.Error("Failed to resolve build info", "error", resolveErr)
			h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
			return &types.CommandResponse{
				Success: false,
				Error:   errorMsg,
			}, nil
		}

		if deploymentMethod == "" {
			deploymentMethod = deploymentMethodFromBuildInfo(buildInfo)
		}
	}

	if deploymentMethod == "" {
		errorMsg := "Unable to determine deployment method"
		h.logger.Error(errorMsg)
		h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		return &types.CommandResponse{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	// Get environment variables from the server
	envVars := make(map[string]string)
	if envService := h.services.GetEnvironmentService(); envService != nil {
		envResult, err := envService.GetServiceEnvVars(ctx, request.ServiceUID)
		if err != nil {
			h.logger.Warn("Failed to get environment variables", "error", err)
		} else if envResult.Success {
			envVars = envResult.EnvVars
		}
	}

	// Merge/override with any environment variables provided directly in the request
	if request.EnvVars != nil {
		for k, v := range request.EnvVars {
			envVars[k] = v // Request vars override server vars
		}
	}

	// Use Caddy network for deployment to avoid having to connect it later
	networks := []string{"bridge"}
	if caddyService := h.services.GetCaddyService(); caddyService != nil {
		// Ensure Caddy is installed and running when deploying applications
		// This allows domains to be configured later without manual Caddy setup
		if err := h.ensureCaddyInstalled(ctx, caddyService); err != nil {
			h.logger.Warn("Failed to ensure Caddy is installed during deployment", "error", err)
			// Don't fail the deployment, just continue without Caddy network
		} else {
			networks = append(networks, "caddy_network") // Assuming caddy network name
			h.logger.Info("Adding container to Caddy network during deployment")
		}
	}

	var deploymentResult *types.DeploymentResult

	strategy, selectionErr := h.selectDeploymentStrategy(deploymentMethod)
	if selectionErr != nil {
		errorMsg := selectionErr.Error()
		if buildInfo != nil && buildInfo.Type != "" {
			errorMsg = fmt.Sprintf("Unsupported build type: %s", buildInfo.Type)
		}
		h.logger.Error(errorMsg)
		h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		return &types.CommandResponse{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	strategyOptions := &appDeploymentOptions{
		Request:   &request,
		BuildInfo: buildInfo,
		ClonePath: clonePath,
		EnvVars:   envVars,
		Networks:  networks,
	}

	deploymentResult, err = strategy.Deploy(ctx, strategyOptions)

	if err != nil || deploymentResult == nil || !deploymentResult.Success {
		errorMsg := "Deployment failed"
		if err != nil {
			errorMsg = fmt.Sprintf("Deployment failed: %v", err)
		} else if deploymentResult != nil && deploymentResult.Error != "" {
			errorMsg = fmt.Sprintf("Deployment failed: %s", deploymentResult.Error)
		}
		h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		return &types.CommandResponse{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	commitTag := ""
	if deploymentMethod != types.DeploymentMethodDockerCompose && commitSHA != "" && deploymentResult != nil && deploymentResult.ImageName != "" {
		shortSHA := commitSHA
		if len(shortSHA) > 12 {
			shortSHA = shortSHA[:12]
		}
		commitTag = fmt.Sprintf("pulseup-app-%s:%s", request.ServiceUID, shortSHA)
		if dockerService := h.services.GetDockerService(); dockerService != nil {
			if err := dockerService.TagImage(ctx, deploymentResult.ImageName, commitTag); err != nil {
				h.logger.Warn("Failed to tag image with commit", "source", deploymentResult.ImageName, "tag", commitTag, "error", err)
			} else {
				h.logger.Info("Tagged image with commit", "source", deploymentResult.ImageName, "tag", commitTag)
			}
		}
	}

	// Update status to indicate successful deployment
	metadata := map[string]interface{}{}
	if commitSHA != "" {
		metadata["commit_sha"] = commitSHA
	}
	if commitMessage != "" {
		metadata["commit_message"] = commitMessage
	}

	if err := h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusCompleted, "", metadata); err != nil {
		h.logger.Error("Failed to update deployment status to completed", "error", err)
	}

	// Additional safety check before accessing deploymentResult fields
	if deploymentResult == nil {
		errorMsg := "Deployment result is unexpectedly nil"
		h.logger.Error(errorMsg)
		h.updateDeploymentStatus(ctx, request.DeploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		return &types.CommandResponse{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	if deploymentMethod != types.DeploymentMethodDockerCompose {
		historyImage := deploymentResult.ImageName
		if commitTag != "" {
			historyImage = commitTag
		}

		if buildService := h.services.GetBuildService(); buildService != nil {
			record := &types.BuildResult{
				Success:       true,
				ImageName:     historyImage,
				BuildTime:     time.Now(),
				CommitSHA:     commitSHA,
				CommitMessage: commitMessage,
				DeploymentUID: request.DeploymentUID,
			}
			if err := buildService.RecordBuildResult(ctx, request.ServiceUID, record); err != nil {
				h.logger.Warn("Failed to record build history", "error", err)
			}
		}
	}

	// Return success response with deployment details
	responseData := map[string]interface{}{
		"success":           true,
		"deployment_method": deploymentMethod,
	}
	if deploymentResult.ImageName != "" {
		responseData["image"] = deploymentResult.ImageName
	}
	if deploymentResult.ContainerID != "" {
		responseData["container"] = deploymentResult.ContainerID
	}
	if deploymentResult.ContainerName != "" {
		responseData["container_name"] = deploymentResult.ContainerName
	}
	if deploymentResult.DeploymentColor != "" {
		responseData["deployment_color"] = deploymentResult.DeploymentColor
	}
	if commitSHA != "" {
		responseData["commit_sha"] = commitSHA
	}
	if commitMessage != "" {
		responseData["commit_message"] = commitMessage
	}

	return &types.CommandResponse{
		Success: true,
		Data:    responseData,
	}, nil
}

func (h *DeployApplicationHandler) resolveBuildCommandInfo(ctx context.Context, serviceUID, clonePath string, isInitialClone bool) (*types.BuildCommandInfo, error) {
	buildService := h.services.GetBuildService()
	if buildService == nil {
		return nil, fmt.Errorf("build service not available")
	}

	buildInfo, err := buildService.GetBuildCommandInfo(ctx, serviceUID)
	if err != nil || buildInfo == nil {
		if err := buildService.PrepareBuild(ctx, clonePath, serviceUID, isInitialClone); err != nil {
			return nil, fmt.Errorf("failed to prepare build: %w", err)
		}

		buildInfo, err = buildService.GetBuildCommandInfo(ctx, serviceUID)
		if err != nil {
			return nil, fmt.Errorf("no build info found for service %s: %w", serviceUID, err)
		}
		if buildInfo == nil {
			return nil, fmt.Errorf("no build info found for service %s", serviceUID)
		}
	}

	return buildInfo, nil
}

func (h *DeployApplicationHandler) extractDeploymentMethod(service map[string]interface{}) types.DeploymentMethod {
	if len(service) == 0 {
		return ""
	}

	if method := normalizeDeploymentMethodValue(service["deployment_method"]); method != "" {
		return method
	}
	if method := normalizeDeploymentMethodValue(service["DeploymentMethod"]); method != "" {
		return method
	}

	return ""
}

func normalizeDeploymentMethodValue(raw interface{}) types.DeploymentMethod {
	if raw == nil {
		return ""
	}
	value := strings.TrimSpace(strings.ToLower(fmt.Sprint(raw)))
	switch value {
	case string(types.DeploymentMethodDockerCompose):
		return types.DeploymentMethodDockerCompose
	case string(types.DeploymentMethodDockerfile):
		return types.DeploymentMethodDockerfile
	case "buildpack":
		return types.DeploymentMethodNixpacks
	case string(types.DeploymentMethodNixpacks):
		return types.DeploymentMethodNixpacks
	default:
		return ""
	}
}

func deploymentMethodFromBuildInfo(info *types.BuildCommandInfo) types.DeploymentMethod {
	if info == nil {
		return ""
	}
	switch strings.ToLower(info.Type) {
	case "docker":
		return types.DeploymentMethodDockerfile
	case "nixpacks":
		return types.DeploymentMethodNixpacks
	case "docker-compose":
		return types.DeploymentMethodDockerCompose
	default:
		return types.DeploymentMethod(strings.ToLower(info.Type))
	}
}

func (h *DeployApplicationHandler) buildDockerComposeRequest(opts *appDeploymentOptions) *types.DockerComposeDeploymentRequest {
	composeFile := ""
	serviceMode := "all"
	selectedServices := []string(nil)
	projectName := ""

	if opts != nil && opts.Request != nil && opts.Request.Service != nil {
		service := opts.Request.Service

		if value, ok := service["docker_compose_path"].(string); ok {
			composeFile = strings.TrimSpace(value)
		} else if value, ok := service["compose_file"].(string); ok {
			composeFile = strings.TrimSpace(value)
		}

		if value, ok := service["docker_compose_service_mode"].(string); ok && strings.TrimSpace(value) != "" {
			serviceMode = strings.TrimSpace(value)
		} else if value, ok := service["compose_service_mode"].(string); ok && strings.TrimSpace(value) != "" {
			serviceMode = strings.TrimSpace(value)
		}

		selectedServices = parseComposeSelectedServices(service["docker_compose_selected_services"])
		if len(selectedServices) == 0 {
			selectedServices = parseComposeSelectedServices(service["compose_selected_services"])
		}

		if value, ok := service["docker_compose_project_name"].(string); ok {
			projectName = strings.TrimSpace(value)
		} else if value, ok := service["compose_project_name"].(string); ok {
			projectName = strings.TrimSpace(value)
		}
	}

	if opts == nil || opts.Request == nil {
		return &types.DockerComposeDeploymentRequest{}
	}

	return &types.DockerComposeDeploymentRequest{
		DeploymentUID:    opts.Request.DeploymentUID,
		ServiceUID:       opts.Request.ServiceUID,
		SourcePath:       opts.ClonePath,
		ComposeFile:      composeFile,
		ServiceMode:      serviceMode,
		SelectedServices: selectedServices,
		ProjectName:      projectName,
		Environment:      opts.EnvVars,
	}
}

func (h *DeployApplicationHandler) buildDockerfileConfig(req *types.DeployApplicationRequest) map[string]interface{} {
	if req == nil {
		return map[string]interface{}{}
	}

	return map[string]interface{}{
		"cpu_limit":     req.CPULimit,
		"memory_limit":  req.MemoryLimit,
		"internal_port": req.InternalPort,
	}
}

func (h *DeployApplicationHandler) buildNixpacksPlanData(opts *appDeploymentOptions) map[string]interface{} {
	planData := make(map[string]interface{})

	if opts != nil && opts.BuildInfo != nil && opts.BuildInfo.Plan != nil {
		if planMap, ok := opts.BuildInfo.Plan.(map[string]interface{}); ok {
			for k, v := range planMap {
				planData[k] = v
			}
		}
	}

	if opts != nil && opts.Request != nil {
		req := opts.Request
		if req.NixpacksConfig != nil {
			for k, v := range req.NixpacksConfig {
				planData[k] = v
			}
		}

		if req.Service != nil {
			var phases map[string]interface{}
			if existing, ok := planData["phases"].(map[string]interface{}); ok && existing != nil {
				phases = make(map[string]interface{}, len(existing))
				for k, v := range existing {
					phases[k] = v
				}
			} else {
				phases = make(map[string]interface{})
			}

			if installCmd, ok := req.Service["install_command"].(string); ok && installCmd != "" {
				phases["setup"] = map[string]interface{}{"cmd": installCmd}
			}
			if buildCmd, ok := req.Service["build_command"].(string); ok && buildCmd != "" {
				phases["build"] = map[string]interface{}{"cmd": buildCmd}
			}
			if startCmd, ok := req.Service["start_command"].(string); ok && startCmd != "" {
				phases["start"] = map[string]interface{}{"cmd": startCmd}
			}

			if len(phases) > 0 {
				planData["phases"] = phases
			}
		}

		if req.CPULimit != "" || req.MemoryLimit != "" {
			resources := make(map[string]interface{})
			if req.CPULimit != "" {
				resources["cpu"] = req.CPULimit
			}
			if req.MemoryLimit != "" {
				resources["memory"] = req.MemoryLimit
			}
			planData["resources"] = resources
		}

		if req.InternalPort > 0 {
			planData["ports"] = []int{req.InternalPort}
		}
	}

	if opts != nil && len(opts.EnvVars) > 0 {
		planData["env"] = opts.EnvVars
	}

	return planData
}

func parseComposeSelectedServices(raw interface{}) []string {
	if raw == nil {
		return nil
	}

	switch value := raw.(type) {
	case []string:
		return value
	case []interface{}:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if str := strings.TrimSpace(fmt.Sprint(item)); str != "" {
				result = append(result, str)
			}
		}
		return result
	case interface{}:
		if str := strings.TrimSpace(fmt.Sprint(value)); str != "" {
			return []string{str}
		}
	}

	return nil
}

// updateDeploymentStatus updates the deployment status using the status service
func (h *DeployApplicationHandler) updateDeploymentStatus(ctx context.Context, deploymentUID string, status types.DeploymentStatus, errorMessage string, metadata map[string]interface{}) error {
	statusService := h.services.GetStatusService()
	if statusService == nil {
		h.logger.Warn("Status service not available for deployment status update", "deployment_uid", deploymentUID)
		return nil
	}

	return statusService.UpdateDeploymentStatus(ctx, deploymentUID, status, errorMessage, metadata)
}

// pathExists checks if a path exists
func (h *DeployApplicationHandler) pathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// ensureCaddyInstalled checks if Caddy is running and installs it if not
func (h *DeployApplicationHandler) ensureCaddyInstalled(ctx context.Context, caddyService CaddyService) error {
	// Check if it has the extended interface with IsCaddyRunning and InstallCaddy methods
	if extendedCaddy, ok := caddyService.(interface {
		IsCaddyRunning(ctx context.Context) (bool, error)
		InstallCaddy(ctx context.Context) error
	}); ok {
		// Check if Caddy is already running
		isRunning, err := extendedCaddy.IsCaddyRunning(ctx)
		if err != nil {
			h.logger.Error("Failed to check if Caddy is running", "error", err)
			return fmt.Errorf("failed to check Caddy status: %w", err)
		}

		if isRunning {
			h.logger.Debug("Caddy is already running")
			return nil
		}

		// Caddy is not running, install it
		h.logger.Info("Caddy is not running, installing Caddy")
		if err := extendedCaddy.InstallCaddy(ctx); err != nil {
			h.logger.Error("Failed to install Caddy", "error", err)
			return fmt.Errorf("failed to install Caddy: %w", err)
		}

		h.logger.Info("Caddy installed and started successfully")
		return nil
	}

	// Fallback: assume Caddy is available (for basic interface)
	h.logger.Warn("Caddy service does not support auto-installation, assuming it's available")
	return nil
}

type dockerComposeStrategy struct {
	handler *DeployApplicationHandler
}

func (s *dockerComposeStrategy) Deploy(ctx context.Context, opts *appDeploymentOptions) (*types.DeploymentResult, error) {
	composeService := s.handler.services.GetDockerComposeService()
	if composeService == nil {
		return nil, fmt.Errorf("Docker Compose service not available")
	}

	composeReq := s.handler.buildDockerComposeRequest(opts)
	return composeService.Deploy(ctx, composeReq)
}

type dockerfileStrategy struct {
	handler *DeployApplicationHandler
}

func (s *dockerfileStrategy) Deploy(ctx context.Context, opts *appDeploymentOptions) (*types.DeploymentResult, error) {
	if opts == nil || opts.Request == nil {
		return nil, fmt.Errorf("Dockerfile deployment requires a request")
	}
	if opts.BuildInfo == nil {
		return nil, fmt.Errorf("Build information unavailable for Dockerfile deployment")
	}

	dockerfileService := s.handler.services.GetDockerfileService()
	if dockerfileService == nil {
		return nil, fmt.Errorf("Dockerfile service not available")
	}

	config := s.handler.buildDockerfileConfig(opts.Request)
	return dockerfileService.Deploy(
		ctx,
		opts.Request.DeploymentUID,
		opts.BuildInfo.CWD,
		opts.Request.ServiceUID,
		config,
		opts.EnvVars,
		opts.Networks,
	)
}

type nixpacksStrategy struct {
	handler *DeployApplicationHandler
}

func (s *nixpacksStrategy) Deploy(ctx context.Context, opts *appDeploymentOptions) (*types.DeploymentResult, error) {
	if opts == nil || opts.Request == nil {
		return nil, fmt.Errorf("Nixpacks deployment requires a request")
	}
	if opts.BuildInfo == nil {
		return nil, fmt.Errorf("Build information unavailable for Nixpacks deployment")
	}

	nixpacksService := s.handler.services.GetNixpacksService()
	if nixpacksService == nil {
		return nil, fmt.Errorf("Nixpacks service not available")
	}

	planData := s.handler.buildNixpacksPlanData(opts)
	return nixpacksService.Deploy(
		ctx,
		opts.Request.DeploymentUID,
		opts.BuildInfo.CWD,
		opts.Request.ServiceUID,
		planData,
		opts.Networks,
	)
}
