package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// DockerfileServiceImpl handles Dockerfile-based deployments
type DockerfileServiceImpl struct {
	logger        *logger.Logger
	dockerService DockerService
	statusService StatusService
	containerBase *containerDeploymentBase
}

// NewDockerfileService creates a new Dockerfile service
func NewDockerfileService(logger *logger.Logger, dockerService DockerService, deploymentService DeploymentService, statusService StatusService) *DockerfileServiceImpl {
	serviceLogger := logger.With("service", "dockerfile")
	return &DockerfileServiceImpl{
		logger:        serviceLogger,
		dockerService: dockerService,
		statusService: statusService,
		containerBase: newContainerDeploymentBase(serviceLogger, deploymentService),
	}
}

// GetDockerfileConfig gets the Dockerfile configuration for a source path
func (d *DockerfileServiceImpl) GetDockerfileConfig(ctx context.Context, sourcePath string) (map[string]interface{}, error) {
	dockerfilePath := filepath.Join(sourcePath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		d.logger.Error("No Dockerfile found", "path", dockerfilePath)
		return nil, fmt.Errorf("no Dockerfile found at %s", dockerfilePath)
	}

	// Return basic configuration information
	// TODO: Add Dockerfile parsing to extract more configuration
	return map[string]interface{}{
		"type":         "dockerfile",
		"path":         dockerfilePath,
		"context_path": sourcePath,
	}, nil
}

// Deploy builds and deploys an application using a Dockerfile
func (d *DockerfileServiceImpl) Deploy(ctx context.Context, deploymentUID, sourcePath, serviceUID string, config map[string]interface{}, envVars map[string]string, networks []string) (*types.DeploymentResult, error) {
	d.logger.Info("Starting Dockerfile deployment",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"source_path", sourcePath)

	// Update deployment status to indicate deployment started
	if d.statusService != nil {
		if err := d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusInProgress, "Starting Dockerfile deployment", nil); err != nil {
			d.logger.Warn("Failed to update deployment status", "error", err)
		}
	}

	// Generate image name
	imageName := fmt.Sprintf("pulseup-app:%s", serviceUID)
	if d.containerBase != nil {
		imageName = d.containerBase.imageNameForService(serviceUID)
	}

	// Check if Dockerfile exists
	dockerfilePath := filepath.Join(sourcePath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		errorMsg := fmt.Sprintf("No Dockerfile found at %s", dockerfilePath)
		d.logger.Error(errorMsg)
		if d.statusService != nil {
			d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	if _, err := exec.LookPath("docker"); err != nil {
		errorMsg := "Docker is not installed or not available in PATH"
		if d.statusService != nil {
			d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	// Update deployment status to indicate building started
	if d.statusService != nil {
		if err := d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusInProgress, "Building container image", nil); err != nil {
			d.logger.Warn("Failed to update deployment status", "error", err)
		}
	}

	// Build the Docker image
	d.logger.Info("Building Docker image", "image_name", imageName, "dockerfile", dockerfilePath)

	buildArgs := []string{"build", "-t", imageName}

	// Add build args from environment variables
	for key, value := range envVars {
		buildArgs = append(buildArgs, "--build-arg", fmt.Sprintf("%s=%s", key, value))
	}

	// Add source path as build context
	buildArgs = append(buildArgs, sourcePath)

	// Execute docker build
	cmd := exec.CommandContext(ctx, "docker", buildArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		errorMsg := fmt.Sprintf("Docker build failed: %s", string(output))
		d.logger.Error("Docker build failed", "error", err, "output", string(output))
		if d.statusService != nil {
			d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	d.logger.Info("Docker build completed successfully", "image_name", imageName)

	// Extract port from config if provided
	var port int
	if internalPort, exists := config["internal_port"]; exists {
		switch v := internalPort.(type) {
		case int:
			port = v
		case float64:
			port = int(v)
		case string:
			if p, err := strconv.Atoi(v); err == nil {
				port = p
			}
		}
	}

	// Add PORT environment variable if port is specified
	if port > 0 {
		envVars["PORT"] = strconv.Itoa(port)
	}

	// Deploy the container using the deployment service
	if d.containerBase == nil {
		errorMsg := "Deployment service not initialized"
		d.logger.Error(errorMsg)
		if d.statusService != nil {
			d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	result, err := d.containerBase.deployBuiltImage(ctx, serviceUID, imageName, deploymentUID, envVars, nil, "")
	if err != nil {
		errorMsg := fmt.Sprintf("Container deployment failed: %v", err)
		d.logger.Error("Container deployment failed", "error", err)
		if d.statusService != nil {
			d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	if !result.Success {
		errorMsg := result.Error
		if errorMsg == "" {
			errorMsg = "Unknown deployment error"
		}
		d.logger.Error("Deployment failed", "error", errorMsg)
		if d.statusService != nil {
			d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusFailed, errorMsg, nil)
		}
		return result, nil
	}

	// Update status to indicate successful deployment
	if d.statusService != nil && result.Success {
		successMsg := fmt.Sprintf("Container ID: %s", result.ContainerID)
		if err := d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, types.DeploymentStatusCompleted, successMsg, nil); err != nil {
			d.logger.Warn("Failed to update deployment status to completed", "error", err)
		}
	}

	return result, nil
}
