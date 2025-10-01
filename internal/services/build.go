package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/go-connections/nat"

	wscontracts "pulseup-agent-go/pkg/contracts/websocket"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// BuildServiceImpl implements the BuildService interface
type BuildServiceImpl struct {
	logger        *logger.Logger
	dockerService DockerService
	deploymentDir string
	wsManager     wscontracts.Emitter         // WebSocket manager for sending status updates
	buildPlans    map[string]*types.BuildPlan // Store build information per service_uid
	planMu        sync.RWMutex
}

const buildHistoryLimit = 10

// NewBuildService creates a new build service
func NewBuildService(logger *logger.Logger, dockerService DockerService) *BuildServiceImpl {
	deploymentDir := "/opt/pulseup/deployments"

	// Check if we're in debug mode
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_DEPLOYMENT_DIR"); debugDir != "" {
			deploymentDir = debugDir
		}
	} else if dir := os.Getenv("DEPLOYMENT_DIR"); dir != "" {
		deploymentDir = dir
	}

	return &BuildServiceImpl{
		logger:        logger.With("service", "build"),
		dockerService: dockerService,
		deploymentDir: deploymentDir,
		buildPlans:    make(map[string]*types.BuildPlan),
	}
}

// BuildApplication builds an application using the specified build type
func (b *BuildServiceImpl) BuildApplication(ctx context.Context, config *types.BuildConfig) (*types.BuildResult, error) {
	b.logger.Info("Building application",
		"name", config.Name,
		"type", config.BuildType,
		"source", config.SourcePath)

	// Create deployment directory for this app
	appDir := filepath.Join(b.deploymentDir, config.Name)
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create app directory: %w", err)
	}

	switch config.BuildType {
	case types.BuildTypeNixpacks:
		return b.buildWithNixpacks(ctx, config, appDir)
	case types.BuildTypeDockerfile:
		return b.buildWithDockerfile(ctx, config, appDir)
	default:
		return nil, fmt.Errorf("unsupported build type: %s", config.BuildType)
	}
}

// buildWithNixpacks builds using Nixpacks
func (b *BuildServiceImpl) buildWithNixpacks(ctx context.Context, config *types.BuildConfig, appDir string) (*types.BuildResult, error) {
	b.logger.Info("Building with Nixpacks", "name", config.Name)

	imageName := fmt.Sprintf("%s:latest", strings.ToLower(config.Name))

	// Prepare nixpacks command
	args := []string{
		"build", config.SourcePath,
		"--name", imageName,
	}

	// Add environment variables if provided
	for key, value := range config.Environment {
		args = append(args, "--env", fmt.Sprintf("%s=%s", key, value))
	}

	// Add custom start command if provided
	if config.StartCommand != "" {
		args = append(args, "--start-cmd", config.StartCommand)
	}

	// Execute nixpacks build
	cmd := exec.CommandContext(ctx, "nixpacks", args...)
	cmd.Dir = appDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		b.logger.Error("Nixpacks build failed", "error", err, "output", string(output))
		return &types.BuildResult{
			Success:   false,
			ImageName: imageName,
			Error:     fmt.Sprintf("nixpacks build failed: %s", string(output)),
			BuildTime: time.Now(),
		}, err
	}

	b.logger.Info("Nixpacks build completed", "image", imageName)

	return &types.BuildResult{
		Success:   true,
		ImageName: imageName,
		BuildTime: time.Now(),
		BuildLogs: string(output),
	}, nil
}

// buildWithDockerfile builds using a Dockerfile
func (b *BuildServiceImpl) buildWithDockerfile(ctx context.Context, config *types.BuildConfig, appDir string) (*types.BuildResult, error) {
	b.logger.Info("Building with Dockerfile", "name", config.Name)

	imageName := fmt.Sprintf("%s:latest", strings.ToLower(config.Name))

	// Check if Dockerfile exists
	dockerfilePath := filepath.Join(config.SourcePath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		return &types.BuildResult{
			Success:   false,
			ImageName: imageName,
			Error:     "Dockerfile not found in source directory",
			BuildTime: time.Now(),
		}, fmt.Errorf("dockerfile not found")
	}

	// Use docker build command
	args := []string{
		"build",
		"-t", imageName,
		"-f", dockerfilePath,
	}

	// Add build args if provided
	for key, value := range config.Environment {
		args = append(args, "--build-arg", fmt.Sprintf("%s=%s", key, value))
	}

	args = append(args, config.SourcePath)

	// Execute docker build
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Dir = appDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		b.logger.Error("Docker build failed", "error", err, "output", string(output))
		return &types.BuildResult{
			Success:   false,
			ImageName: imageName,
			Error:     fmt.Sprintf("docker build failed: %s", string(output)),
			BuildTime: time.Now(),
		}, err
	}

	b.logger.Info("Docker build completed", "image", imageName)

	return &types.BuildResult{
		Success:   true,
		ImageName: imageName,
		BuildTime: time.Now(),
		BuildLogs: string(output),
	}, nil
}

// DeployApplication deploys a built application
func (b *BuildServiceImpl) DeployApplication(ctx context.Context, config *types.DeployConfig) (*types.DeployResult, error) {
	b.logger.Info("Deploying application",
		"name", config.Name,
		"image", config.ImageName,
		"port", config.Port)

	// Stop existing container if it exists
	if err := b.dockerService.StopContainer(ctx, config.Name); err != nil {
		b.logger.Debug("No existing container to stop", "name", config.Name)
	}

	// Remove existing container if it exists
	if err := b.dockerService.RemoveContainer(ctx, config.Name); err != nil {
		b.logger.Debug("No existing container to remove", "name", config.Name)
	}

	// Prepare container configuration
	exposedPorts := nat.PortSet{}
	exposedPorts[nat.Port(fmt.Sprintf("%d/tcp", config.Port))] = struct{}{}

	containerConfig := &container.Config{
		Image:        config.ImageName,
		Env:          make([]string, 0, len(config.Environment)),
		ExposedPorts: exposedPorts,
	}

	// Add environment variables
	for key, value := range config.Environment {
		containerConfig.Env = append(containerConfig.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Add custom command if provided
	if config.Command != "" {
		containerConfig.Cmd = strings.Fields(config.Command)
	}

	// Prepare host configuration
	portBindings := nat.PortMap{}
	portBindings[nat.Port(fmt.Sprintf("%d/tcp", config.Port))] = []nat.PortBinding{
		{
			HostIP:   "0.0.0.0",
			HostPort: fmt.Sprintf("%d", config.Port),
		},
	}

	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		RestartPolicy: container.RestartPolicy{
			Name: "unless-stopped",
		},
	}

	// Add volume mounts if specified
	if len(config.Volumes) > 0 {
		hostConfig.Mounts = make([]mount.Mount, 0, len(config.Volumes))
		for _, vol := range config.Volumes {
			parts := strings.Split(vol, ":")
			if len(parts) >= 2 {
				hostConfig.Mounts = append(hostConfig.Mounts, mount.Mount{
					Type:   mount.TypeBind,
					Source: parts[0],
					Target: parts[1],
				})
			}
		}
	}

	// Create container
	containerID, err := b.dockerService.CreateContainer(ctx, containerConfig, hostConfig, config.Name)
	if err != nil {
		return &types.DeployResult{
			Success:    false,
			Error:      fmt.Sprintf("failed to create container: %v", err),
			DeployTime: time.Now(),
		}, err
	}

	// Start container
	if err := b.dockerService.StartContainer(ctx, containerID); err != nil {
		return &types.DeployResult{
			Success:     false,
			ContainerID: containerID,
			Error:       fmt.Sprintf("failed to start container: %v", err),
			DeployTime:  time.Now(),
		}, err
	}

	b.logger.Info("Application deployed successfully",
		"name", config.Name,
		"container_id", containerID[:12],
		"port", config.Port)

	return &types.DeployResult{
		Success:     true,
		ContainerID: containerID,
		Port:        config.Port,
		DeployTime:  time.Now(),
	}, nil
}

// GetBuildHistory returns build history for an application
func (b *BuildServiceImpl) GetBuildHistory(ctx context.Context, appName string) ([]types.BuildResult, error) {
	b.logger.Debug("Getting build history", "app", appName)

	history, err := b.loadBuildHistory(appName)
	if err != nil {
		return nil, err
	}

	// Ensure newest first
	sort.SliceStable(history, func(i, j int) bool {
		return history[i].BuildTime.After(history[j].BuildTime)
	})

	return history, nil
}

func (b *BuildServiceImpl) RecordBuildResult(ctx context.Context, serviceUID string, result *types.BuildResult) error {
	if result == nil {
		return fmt.Errorf("build result is nil")
	}

	if result.BuildTime.IsZero() {
		result.BuildTime = time.Now()
	}

	history, err := b.loadBuildHistory(serviceUID)
	if err != nil {
		return err
	}

	filtered := make([]types.BuildResult, 0, buildHistoryLimit)
	filtered = append(filtered, *result)

	for _, entry := range history {
		if result.CommitSHA != "" && entry.CommitSHA == result.CommitSHA {
			continue
		}
		if entry.ImageName == result.ImageName {
			continue
		}
		filtered = append(filtered, entry)
		if len(filtered) >= buildHistoryLimit {
			break
		}
	}

	return b.saveBuildHistory(serviceUID, filtered)
}

func (b *BuildServiceImpl) historyFilePath(serviceUID string) string {
	return filepath.Join(b.deploymentDir, serviceUID, "build_history.json")
}

func (b *BuildServiceImpl) loadBuildHistory(serviceUID string) ([]types.BuildResult, error) {
	path := b.historyFilePath(serviceUID)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []types.BuildResult{}, nil
		}
		return nil, fmt.Errorf("failed to read build history: %w", err)
	}

	var history []types.BuildResult
	if len(data) == 0 {
		return []types.BuildResult{}, nil
	}

	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("failed to parse build history: %w", err)
	}

	return history, nil
}

func (b *BuildServiceImpl) saveBuildHistory(serviceUID string, history []types.BuildResult) error {
	path := b.historyFilePath(serviceUID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create history directory: %w", err)
	}

	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode build history: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write build history: %w", err)
	}

	return nil
}

// GetDeploymentStatus returns the status of a deployment
func (b *BuildServiceImpl) GetDeploymentStatus(ctx context.Context, appName string) (*types.AppDeploymentStatus, error) {
	b.logger.Debug("Getting deployment status", "app", appName)

	// Get container status
	status, err := b.dockerService.GetContainerStatus(ctx, appName)
	if err != nil {
		return &types.AppDeploymentStatus{
			Name:   appName,
			Status: types.ServiceStatusStopped,
			Error:  err.Error(),
		}, nil
	}

	// Get container info from Docker service
	containers, err := b.dockerService.ListContainers(ctx)
	if err != nil {
		return &types.AppDeploymentStatus{
			Name:   appName,
			Status: status,
			Error:  "failed to get container details",
		}, nil
	}

	// Find our container
	for _, container := range containers {
		if container.Name == appName {
			return &types.AppDeploymentStatus{
				Name:      appName,
				Status:    status,
				Port:      container.Port,
				UpdatedAt: container.UpdatedAt,
			}, nil
		}
	}

	return &types.AppDeploymentStatus{
		Name:   appName,
		Status: types.ServiceStatusStopped,
	}, nil
}

// SetWebSocketManager sets the WebSocket manager for sending status updates
func (b *BuildServiceImpl) SetWebSocketManager(wsManager wscontracts.Emitter) {
	b.wsManager = wsManager
	b.logger.Debug("WebSocket manager set for Build service")
}

// PrepareBuild checks for Dockerfile or prepares Nixpacks plan, but does not build
func (b *BuildServiceImpl) PrepareBuild(ctx context.Context, clonePath, serviceUID string, isInitialClone bool) error {
	b.logger.Debug("Preparing build setup", "clone_path", clonePath, "service_uid", serviceUID, "is_initial_clone", isInitialClone)

	// Clear any previous plan
	b.clearBuildPlan(serviceUID)

	// Find all Dockerfile paths in the repository
	dockerfilePaths := b.findDockerfilePaths(clonePath)

	// Send docker config even if we'll use Nixpacks
	if len(dockerfilePaths) > 0 {
		if err := b.sendDockerConfig(serviceUID, dockerfilePaths); err != nil {
			b.logger.Error("Failed to send Docker config", "error", err)
		}
	}

	// Check if there's a Dockerfile in the root
	dockerfilePath := filepath.Join(clonePath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); err == nil {
		// Use Docker build
		b.saveBuildPlan(serviceUID, &types.BuildPlan{
			Type:        "docker",
			ContextPath: clonePath,
			Plan:        nil,
		})
		b.logger.Info("Using Docker build for service", "service_uid", serviceUID)
	} else {
		// Use Nixpacks
		suggestedPlan, err := b.getNixpacksSuggestedConfig(clonePath)
		if err != nil {
			return fmt.Errorf("failed to generate Nixpacks plan for %s: %w", serviceUID, err)
		}

		if suggestedPlan != "" {
			b.saveBuildPlan(serviceUID, &types.BuildPlan{
				Type:        "nixpacks",
				ContextPath: clonePath,
				Plan:        suggestedPlan,
			})

			// Only send the nixpacks config to the server on initial clone
			if isInitialClone {
				if err := b.sendNixpacksConfig(serviceUID, suggestedPlan); err != nil {
					b.logger.Error("Failed to send Nixpacks config", "error", err)
				}
			}
			b.logger.Info("Using Nixpacks build for service", "service_uid", serviceUID)
		} else {
			return fmt.Errorf("failed to generate Nixpacks plan for %s: no plan generated", serviceUID)
		}
	}

	b.logger.Info("Build preparation completed", "service_uid", serviceUID)
	return nil
}

// GetBuildCommandInfo returns information needed to execute the build for a service
func (b *BuildServiceImpl) GetBuildCommandInfo(ctx context.Context, serviceUID string) (*types.BuildCommandInfo, error) {
	planInfo, exists := b.loadBuildPlan(serviceUID)
	if !exists {
		b.logger.Warn("No build plan found for service", "service_uid", serviceUID)
		return nil, fmt.Errorf("no build plan found for service %s", serviceUID)
	}

	buildType := planInfo.Type
	contextPath := planInfo.ContextPath
	imageName := fmt.Sprintf("pulseup-app:%s", serviceUID)
	var command string

	switch buildType {
	case "docker":
		command = fmt.Sprintf("docker build -t %s .", imageName)
	case "nixpacks":
		command = fmt.Sprintf("nixpacks build . --name %s", imageName)
	default:
		return nil, fmt.Errorf("unknown build type '%s' for service %s", buildType, serviceUID)
	}

	return &types.BuildCommandInfo{
		ServiceUID: serviceUID,
		Type:       buildType,
		Command:    command,
		CWD:        contextPath,
		Plan:       planInfo.Plan,
	}, nil
}

func (b *BuildServiceImpl) clearBuildPlan(serviceUID string) {
	b.planMu.Lock()
	defer b.planMu.Unlock()
	delete(b.buildPlans, serviceUID)
}

func (b *BuildServiceImpl) saveBuildPlan(serviceUID string, plan *types.BuildPlan) {
	if plan == nil {
		b.clearBuildPlan(serviceUID)
		return
	}

	planCopy := *plan

	b.planMu.Lock()
	defer b.planMu.Unlock()
	b.buildPlans[serviceUID] = &planCopy
}

func (b *BuildServiceImpl) loadBuildPlan(serviceUID string) (*types.BuildPlan, bool) {
	b.planMu.RLock()
	defer b.planMu.RUnlock()

	plan, exists := b.buildPlans[serviceUID]
	if !exists {
		return nil, false
	}

	planCopy := *plan
	return &planCopy, true
}

// findDockerfilePaths finds all Dockerfile paths in a repository
func (b *BuildServiceImpl) findDockerfilePaths(basePath string) []string {
	var dockerfilePaths []string

	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip common directories that shouldn't contain Dockerfiles to build
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "dist" ||
				name == ".cache" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if file is a Dockerfile
		if strings.ToLower(info.Name()) == "dockerfile" ||
			strings.Contains(strings.ToLower(info.Name()), "dockerfile") {
			// Get the relative path from the base_path
			relPath, err := filepath.Rel(basePath, path)
			if err == nil {
				dockerfilePaths = append(dockerfilePaths, relPath)
			}
		}

		return nil
	})

	if err != nil {
		b.logger.Error("Error walking directory for Dockerfiles", "error", err)
	}

	return dockerfilePaths
}

// sendDockerConfig sends the detected Dockerfile paths to the server
func (b *BuildServiceImpl) sendDockerConfig(serviceUID string, dockerfilePaths []string) error {
	if b.wsManager == nil {
		b.logger.Error("Cannot send Docker config: WebSocket manager not set")
		return fmt.Errorf("websocket manager not available")
	}

	payload := map[string]interface{}{
		"service_uid":      serviceUID,
		"dockerfile_paths": dockerfilePaths,
	}

	if err := b.wsManager.Emit("update_docker_config", payload); err != nil {
		b.logger.Error("Failed to send Docker config update", "service_uid", serviceUID, "error", err)
		return err
	}

	b.logger.Debug("Sent Docker config update", "service_uid", serviceUID, "paths", len(dockerfilePaths))
	return nil
}

// sendNixpacksConfig sends the generated Nixpacks configuration plan to the server
func (b *BuildServiceImpl) sendNixpacksConfig(serviceUID, planJSONStr string) error {
	if b.wsManager == nil {
		b.logger.Error("Cannot send Nixpacks config: WebSocket manager not set")
		return fmt.Errorf("websocket manager not available")
	}

	// Parse the JSON string into a dictionary
	var configData interface{}
	if err := json.Unmarshal([]byte(planJSONStr), &configData); err != nil {
		b.logger.Error("Failed to parse Nixpacks plan JSON", "service_uid", serviceUID, "error", err)
		return err
	}

	payload := map[string]interface{}{
		"service_uid": serviceUID,
		"config":      configData,
	}

	if err := b.wsManager.Emit("update_nixpacks_config", payload); err != nil {
		b.logger.Error("Failed to send Nixpacks config update", "service_uid", serviceUID, "error", err)
		return err
	}

	b.logger.Debug("Sent Nixpacks config update", "service_uid", serviceUID)
	return nil
}

// getNixpacksSuggestedConfig gets the suggested Nixpacks configuration for a source path
func (b *BuildServiceImpl) getNixpacksSuggestedConfig(sourcePath string) (string, error) {
	b.logger.Debug("Getting Nixpacks suggested config", "source_path", sourcePath)

	// Check if nixpacks is available
	if _, err := exec.LookPath("nixpacks"); err != nil {
		return "", fmt.Errorf("nixpacks not found in PATH")
	}

	// Run nixpacks plan command
	cmd := exec.Command("nixpacks", "plan", sourcePath, "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		b.logger.Error("Failed to get Nixpacks plan", "error", err)
		return "", fmt.Errorf("failed to get nixpacks plan: %w", err)
	}

	planJSON := string(output)
	b.logger.Debug("Generated Nixpacks plan", "plan_length", len(planJSON))
	return planJSON, nil
}
