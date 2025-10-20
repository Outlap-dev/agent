package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// DockerfileServiceImpl handles Dockerfile-based deployments
type DockerfileServiceImpl struct {
	logger        *logger.Logger
	dockerService DockerService
	statusService StatusService
	containerBase *containerDeploymentBase
	logManager    *deploymentLogManager
}

// NewDockerfileService creates a new Dockerfile service
func NewDockerfileService(logger *logger.Logger, dockerService DockerService, deploymentService DeploymentService, statusService StatusService) *DockerfileServiceImpl {
	serviceLogger := logger.With("service", "dockerfile")
	return &DockerfileServiceImpl{
		logger:        serviceLogger,
		dockerService: dockerService,
		statusService: statusService,
		containerBase: newContainerDeploymentBase(serviceLogger, deploymentService),
		logManager:    newDeploymentLogManager(serviceLogger),
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
	if envVars == nil {
		envVars = make(map[string]string)
	}

	stepTemplates := []types.DeploymentStep{
		{
			ID:          deploymentStepInitialize,
			Name:        "Prepare deployment",
			Description: "Validating Dockerfile and environment",
			Status:      types.DeploymentStepStatusPending,
			LogType:     "deploy",
		},
		{
			ID:          deploymentStepBuildImage,
			Name:        "Build container image",
			Description: "Running docker build",
			Status:      types.DeploymentStepStatusPending,
			LogType:     "build",
		},
		{
			ID:          deploymentStepDeployImage,
			Name:        "Deploy container",
			Description: "Starting application container",
			Status:      types.DeploymentStepStatusPending,
			LogType:     "deploy",
		},
	}

	stepTracker := d.logManager.NewStepTracker(serviceUID, deploymentUID, stepTemplates...)

	startStep := func(stepID, name, description, logType string) {
		if stepTracker != nil {
			stepTracker.StartStep(stepID, name, description, logType)
		}
	}

	appendStepLog := func(stepID, level, message string) {
		if stepTracker != nil {
			stepTracker.AppendLog(stepID, level, message)
		}
	}

	failStep := func(stepID, message string) {
		if stepTracker != nil {
			stepTracker.FailStep(stepID, message)
		}
	}

	completeStep := func(stepID string) {
		if stepTracker != nil {
			stepTracker.CompleteStep(stepID)
		}
	}

	logDeploy := func(level, message string) {
		d.logManager.AppendDeploymentLog(serviceUID, deploymentUID, level, message)
	}

	updateStatus := func(status types.DeploymentStatus, message string, stepID string) {
		if d.statusService == nil {
			return
		}
		if err := d.statusService.UpdateDeploymentStatus(ctx, deploymentUID, status, message, nil); err != nil {
			d.logger.Warn("Failed to update deployment status", "error", err)
			if stepID != "" {
				appendStepLog(stepID, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
			}
		}
	}

	d.logger.Info("Starting Dockerfile deployment",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"source_path", sourcePath)

	startStep(deploymentStepInitialize, "Prepare deployment", "Validating Dockerfile and environment", "deploy")
	logDeploy("INFO", "Starting Dockerfile deployment")
	appendStepLog(deploymentStepInitialize, "INFO", "Starting Dockerfile deployment")
	updateStatus(types.DeploymentStatusInProgress, "Starting Dockerfile deployment", deploymentStepInitialize)

	imageName := fmt.Sprintf("pulseup-app:%s", serviceUID)
	if d.containerBase != nil {
		imageName = d.containerBase.imageNameForService(serviceUID)
	}

	dockerfilePath := filepath.Join(sourcePath, "Dockerfile")
	if _, err := os.Stat(dockerfilePath); os.IsNotExist(err) {
		errorMsg := fmt.Sprintf("No Dockerfile found at %s", dockerfilePath)
		d.logger.Error(errorMsg)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepInitialize, errorMsg)
		updateStatus(types.DeploymentStatusFailed, errorMsg, deploymentStepInitialize)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, nil
	}

	if _, err := exec.LookPath("docker"); err != nil {
		errorMsg := "Docker is not installed or not available in PATH"
		d.logger.Error(errorMsg)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepInitialize, errorMsg)
		updateStatus(types.DeploymentStatusFailed, errorMsg, deploymentStepInitialize)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, nil
	}

	appendStepLog(deploymentStepInitialize, "INFO", "Docker binary detected and Dockerfile located")
	completeStep(deploymentStepInitialize)

	buildArgs := []string{"build", "-t", imageName}
	extraEnv := make([]string, 0, len(envVars))
	for key, value := range envVars {
		buildArgs = append(buildArgs, "--build-arg", key)
		extraEnv = append(extraEnv, fmt.Sprintf("%s=%s", key, value))
	}
	buildArgs = append(buildArgs, sourcePath)

	startStep(deploymentStepBuildImage, "Build container image", "Running docker build", "build")
	appendStepLog(deploymentStepBuildImage, "INFO", "Executing docker build command")
	logDeploy("INFO", fmt.Sprintf("Building Docker image %s", imageName))
	updateStatus(types.DeploymentStatusInProgress, "Building container image", deploymentStepBuildImage)

	command := append([]string{"docker"}, buildArgs...)
	result, err := d.logManager.RunCommand(ctx, command, sourcePath, deploymentUID, serviceUID, "build", extraEnv)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to execute docker build: %v", err)
		d.logger.Error("Docker build execution failed", "error", err)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepBuildImage, errorMsg)
		updateStatus(types.DeploymentStatusFailed, errorMsg, deploymentStepBuildImage)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, nil
	}

	if result.ExitCode != 0 {
		errorMsg := fmt.Sprintf("Docker build exited with code %d: %s", result.ExitCode, result.Stderr)
		d.logger.Error("Docker build failed", "error", errorMsg)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepBuildImage, errorMsg)
		updateStatus(types.DeploymentStatusFailed, errorMsg, deploymentStepBuildImage)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, nil
	}

	appendStepLog(deploymentStepBuildImage, "INFO", "Docker build completed successfully")
	completeStep(deploymentStepBuildImage)
	d.logManager.AppendLogEntry(serviceUID, deploymentUID, "build", "INFO", "Docker build completed successfully")

	var port int
	if config != nil {
		if mappings, exists := config["port_mappings"]; exists {
			if parsed := parsePortMappingsFromConfig(mappings); len(parsed) > 0 {
				port = parsed[0].Internal
			}
		}
		if port == 0 {
			port = extractIntValue(config["internal_port"])
		}
	}

	if port > 0 {
		if _, exists := envVars["PORT"]; !exists {
			envVars["PORT"] = strconv.Itoa(port)
		}
	}

	if d.containerBase == nil {
		errorMsg := "Deployment service not initialized"
		d.logger.Error(errorMsg)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepDeployImage, errorMsg)
		updateStatus(types.DeploymentStatusFailed, errorMsg, deploymentStepDeployImage)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, nil
	}

	startStep(deploymentStepDeployImage, "Deploy container", "Starting application container", "deploy")
	appendStepLog(deploymentStepDeployImage, "INFO", fmt.Sprintf("Deploying container image %s", imageName))
	logDeploy("INFO", fmt.Sprintf("Deploying container image %s", imageName))
	updateStatus(types.DeploymentStatusInProgress, "Deploying container", deploymentStepDeployImage)

	deploymentResult, err := d.containerBase.deployBuiltImage(ctx, serviceUID, imageName, deploymentUID, envVars, stepTracker, deploymentStepDeployImage)
	if err != nil {
		errorMsg := fmt.Sprintf("Container deployment failed: %v", err)
		d.logger.Error("Container deployment failed", "error", err)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepDeployImage, errorMsg)
		updateStatus(types.DeploymentStatusFailed, errorMsg, deploymentStepDeployImage)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, nil
	}

	if !deploymentResult.Success {
		errorMsg := deploymentResult.Error
		if errorMsg == "" {
			errorMsg = "Unknown deployment error"
		}
		d.logger.Error("Deployment failed", "error", errorMsg)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepDeployImage, errorMsg)
		updateStatus(types.DeploymentStatusFailed, errorMsg, deploymentStepDeployImage)
		return deploymentResult, nil
	}

	successMsg := fmt.Sprintf("Container ID: %s", deploymentResult.ContainerID)
	updateStatus(types.DeploymentStatusCompleted, successMsg, deploymentStepDeployImage)
	appendStepLog(deploymentStepDeployImage, "INFO", successMsg)
	completeStep(deploymentStepDeployImage)
	logDeploy("INFO", fmt.Sprintf("Deployment completed successfully. Container ID: %s", deploymentResult.ContainerID))

	return deploymentResult, nil
}

func parsePortMappingsFromConfig(raw interface{}) []types.PortMapping {
	switch value := raw.(type) {
	case []types.PortMapping:
		return value
	case []interface{}:
		result := make([]types.PortMapping, 0, len(value))
		for _, item := range value {
			if mapping, ok := item.(map[string]interface{}); ok {
				result = append(result, types.PortMapping{
					External: extractIntValue(mapping["external"]),
					Internal: extractIntValue(mapping["internal"]),
				})
			}
		}
		return result
	case map[string]interface{}:
		return []types.PortMapping{{
			External: extractIntValue(value["external"]),
			Internal: extractIntValue(value["internal"]),
		}}
	default:
		return nil
	}
}

func extractIntValue(raw interface{}) int {
	switch v := raw.(type) {
	case nil:
		return 0
	case int:
		return v
	case int8:
		return int(v)
	case int16:
		return int(v)
	case int32:
		return int(v)
	case int64:
		return int(v)
	case uint:
		return int(v)
	case uint8:
		return int(v)
	case uint16:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	case string:
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			return 0
		}
		if parsed, err := strconv.Atoi(trimmed); err == nil {
			return parsed
		}
	}
	return 0
}
