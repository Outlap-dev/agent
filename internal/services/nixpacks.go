package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	wscontracts "pulseup-agent-go/pkg/contracts/websocket"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// NixpacksServiceImpl handles Nixpacks operations for building applications
type NixpacksServiceImpl struct {
	logger        *logger.Logger
	logsDir       string
	wsManager     wscontracts.Emitter
	containerBase *containerDeploymentBase
}

const (
	deploymentStepInitialize  = "initialize"
	deploymentStepBuildImage  = "build_image"
	deploymentStepDeployImage = "deploy_container"
)

// NewNixpacksService creates a new Nixpacks service
func NewNixpacksService(logger *logger.Logger, wsManager wscontracts.Emitter, deploymentService DeploymentService) *NixpacksServiceImpl {
	logsDir := "/var/log/pulseup/deployments"

	// Check if we're in debug mode
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_LOG_DIR"); debugDir != "" {
			logsDir = filepath.Join(debugDir, "deployments")
		}
	}

	os.MkdirAll(logsDir, 0755)

	serviceLogger := logger.With("service", "nixpacks")

	return &NixpacksServiceImpl{
		logger:        serviceLogger,
		logsDir:       logsDir,
		wsManager:     wsManager,
		containerBase: newContainerDeploymentBase(serviceLogger, deploymentService),
	}
}

func (n *NixpacksServiceImpl) buildLogPaths(serviceUID, deploymentUID, logType string) []string {
	if logType == "" {
		return nil
	}

	paths := make([]string, 0, 2)
	if deploymentUID != "" {
		paths = append(paths, filepath.Join(n.logsDir, fmt.Sprintf("%s_%s.log", deploymentUID, logType)))
	}
	if serviceUID != "" {
		paths = append(paths, filepath.Join(n.logsDir, fmt.Sprintf("%s_%s.log", serviceUID, logType)))
	}

	return paths
}

func (n *NixpacksServiceImpl) initializeLogFiles(serviceUID, deploymentUID, logType string, command []string) []*os.File {
	paths := n.buildLogPaths(serviceUID, deploymentUID, logType)
	if len(paths) == 0 {
		return nil
	}

	entry := fmt.Sprintf("%s - INFO - Starting command: %s\n", time.Now().Format(time.RFC3339), strings.Join(command, " "))
	files := make([]*os.File, 0, len(paths))

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			n.logger.Warn("Failed to create log directory", "path", path, "error", err)
			continue
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			n.logger.Warn("Failed to create log file", "path", path, "error", err)
			continue
		}
		if _, err := file.WriteString(entry); err != nil {
			n.logger.Warn("Failed to write initial log entry", "path", path, "error", err)
		}
		files = append(files, file)
	}

	return files
}

func (n *NixpacksServiceImpl) appendLogEntry(serviceUID, deploymentUID, logType, level, message string) {
	paths := n.buildLogPaths(serviceUID, deploymentUID, logType)
	if len(paths) == 0 {
		return
	}

	entry := fmt.Sprintf("%s - %s - %s\n", time.Now().Format(time.RFC3339), level, message)

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			n.logger.Warn("Failed to create log directory", "path", path, "error", err)
			continue
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			n.logger.Warn("Failed to append to log file", "path", path, "error", err)
			continue
		}
		if _, err := file.WriteString(entry); err != nil {
			n.logger.Warn("Failed to write log entry", "path", path, "error", err)
		}
		_ = file.Close()
	}
}

func (n *NixpacksServiceImpl) appendDeploymentLog(serviceUID, deploymentUID, level, message string) {
	n.appendLogEntry(serviceUID, deploymentUID, "deploy", level, message)
}

// IsInstalled checks if Nixpacks is installed on the system
func (n *NixpacksServiceImpl) IsInstalled() bool {
	_, err := exec.LookPath("nixpacks")
	return err == nil
}

// BuildImage builds a container image using Nixpacks
func (n *NixpacksServiceImpl) BuildImage(ctx context.Context, sourcePath, serviceUID, deploymentUID string) (*types.BuildResult, error) {
	if !n.IsInstalled() {
		return nil, fmt.Errorf("nixpacks is not installed")
	}

	imageName := fmt.Sprintf("pulseup-app:%s", serviceUID)
	if n.containerBase != nil {
		imageName = n.containerBase.imageNameForService(serviceUID)
	}
	buildCommand := []string{"nixpacks", "build", ".", "--name", imageName}

	n.logger.Info("Starting Nixpacks build",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"image_name", imageName,
		"command", strings.Join(buildCommand, " "),
		"working_directory", sourcePath)

	result, err := n.runCommand(ctx, buildCommand, sourcePath, deploymentUID, serviceUID, "build")
	if err != nil {
		return &types.BuildResult{
			Success:   false,
			Error:     err.Error(),
			ImageName: imageName,
		}, nil
	}

	if result.ExitCode != 0 {
		errorMsg := fmt.Sprintf("Nixpacks build failed with exit code %d: %s", result.ExitCode, result.Stderr)
		n.logger.Error("Build failed", "error", errorMsg)
		return &types.BuildResult{
			Success:   false,
			Error:     errorMsg,
			ImageName: imageName,
		}, nil
	}

	n.logger.Info("Nixpacks build completed successfully", "image_name", imageName)
	return &types.BuildResult{
		Success:   true,
		ImageName: imageName,
		BuildLogs: result.Stdout,
	}, nil
}

// GetSuggestedConfig gets the suggested Nixpacks configuration for a source path
func (n *NixpacksServiceImpl) GetSuggestedConfig(ctx context.Context, sourcePath string) (*types.NixpacksPlan, error) {
	if !n.IsInstalled() {
		return nil, fmt.Errorf("nixpacks is not installed")
	}

	planCommand := []string{"nixpacks", "plan", "."}

	result, err := n.runCommand(ctx, planCommand, sourcePath, "", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get nixpacks plan: %w", err)
	}

	if result.ExitCode != 0 {
		return nil, fmt.Errorf("nixpacks plan failed with exit code %d: %s", result.ExitCode, result.Stderr)
	}

	// Clean and parse the JSON output
	cleanedOutput := strings.TrimSpace(result.Stdout)
	if strings.HasPrefix(cleanedOutput, "\xef\xbb\xbf") { // Remove UTF-8 BOM
		cleanedOutput = cleanedOutput[3:]
	}

	var plan types.NixpacksPlan
	if err := json.Unmarshal([]byte(cleanedOutput), &plan); err != nil {
		return nil, fmt.Errorf("failed to parse nixpacks plan: %w", err)
	}

	return &plan, nil
}

// GeneratePlan generates a Nixpacks plan for the given source path (alias for GetSuggestedConfig)
func (n *NixpacksServiceImpl) GeneratePlan(ctx context.Context, sourcePath string) (*types.NixpacksPlan, error) {
	return n.GetSuggestedConfig(ctx, sourcePath)
}

// CommandResult represents the result of a command execution
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// runCommand executes a command and captures its output with logging
func (n *NixpacksServiceImpl) runCommand(ctx context.Context, command []string, workDir, deploymentUID, serviceUID, logType string) (*CommandResult, error) {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = workDir

	// Set HOME to pulseup-worker if running under that user context to prevent attempts to read /root/.docker
	baseEnv := os.Environ()
	if os.Geteuid() != 0 {
		// Non-root user; ensure HOME points to its home directory if not already set
		hasHome := false
		for _, e := range baseEnv {
			if strings.HasPrefix(e, "HOME=") {
				hasHome = true
				break
			}
		}
		if !hasHome {
			if homeDir, err := os.UserHomeDir(); err == nil {
				baseEnv = append(baseEnv, fmt.Sprintf("HOME=%s", homeDir))
			}
		}
	}

	// Allow opting out of BuildKit disabling; only force legacy mode if DOCKER_FORCE_LEGACY_BUILDS=1
	if os.Getenv("DOCKER_FORCE_LEGACY_BUILDS") == "1" {
		baseEnv = append(baseEnv,
			"DOCKER_BUILDKIT=0",
			"COMPOSE_DOCKER_CLI_BUILD=0",
			"DOCKER_CLI_EXPERIMENTAL=disabled",
		)
	}
	cmd.Env = baseEnv

	// Log the exact command & working directory for troubleshooting
	n.logger.Info("Executing build command",
		"work_dir", workDir,
		"command", strings.Join(command, " "))
	if os.Getenv("DEBUG") == "true" {
		for _, e := range cmd.Env {
			if strings.HasPrefix(e, "DOCKER_") || strings.HasPrefix(e, "COMPOSE_") {
				n.logger.Debug("env", "var", e)
			}
		}
	}

	logFiles := n.initializeLogFiles(serviceUID, deploymentUID, logType, command)
	if len(logFiles) > 0 {
		defer func() {
			for _, file := range logFiles {
				if file != nil {
					_ = file.Close()
				}
			}
		}()
	}

	// Create pipes for stdout and stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Read output streams concurrently
	stdoutChan := make(chan string, 1)
	stderrChan := make(chan string, 1)

	go n.readStream(stdoutPipe, "stdout", logFiles, false, stdoutChan)
	go n.readStream(stderrPipe, "stderr", logFiles, true, stderrChan)

	// Wait for command to complete
	err = cmd.Wait()

	// Get the output
	stdout := <-stdoutChan
	stderr := <-stderrChan

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			return nil, fmt.Errorf("command execution failed: %w", err)
		}
	}

	result := &CommandResult{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
	}

	if logType != "" {
		level := "INFO"
		message := "Command completed successfully"
		if exitCode != 0 {
			level = "ERROR"
			message = fmt.Sprintf("Command exited with code %d", exitCode)
		}
		n.appendLogEntry(serviceUID, deploymentUID, logType, level, message)
	}

	return result, nil
}

// readStream reads from a stream and logs the output
func (n *NixpacksServiceImpl) readStream(reader io.Reader, streamName string, logFiles []*os.File, isStderr bool, output chan<- string) {
	var lines []string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			lines = append(lines, line)
			timestamp := time.Now().Format(time.RFC3339)

			logLevel := "INFO"
			if isStderr {
				// Check if it's Docker build progress (not an error)
				isDockerProgress := strings.Contains(line, "#") ||
					strings.Contains(line, "building with") ||
					(strings.Contains(line, "DONE") && !strings.Contains(line, "ERROR")) ||
					strings.Contains(line, "transferring") ||
					strings.Contains(line, "load build definition") ||
					strings.Contains(line, "exporting layers") ||
					strings.Contains(line, "writing image")

				if !isDockerProgress {
					logLevel = "ERROR"
					n.logger.Error("Build stderr", "line", line)
				} else {
					n.logger.Debug("Build progress", "line", line)
				}
			} else {
				n.logger.Debug("Build stdout", "line", line)
			}

			// Write to log files
			for _, file := range logFiles {
				if file != nil {
					file.WriteString(fmt.Sprintf("%s - %s - %s\n", timestamp, logLevel, line))
				}
			}
		}
	}

	output <- strings.Join(lines, "\n")
}

// UpdateStatus sends status updates via WebSocket
func (n *NixpacksServiceImpl) UpdateStatus(serviceUID, status, message string) error {
	if n.wsManager == nil {
		n.logger.Warn("WebSocket manager not available for status update")
		return nil
	}

	statusUpdate := map[string]interface{}{
		"service_uid": serviceUID,
		"status":      status,
		"message":     message,
		"timestamp":   time.Now().Unix(),
	}

	return n.wsManager.Emit("service_status_update", statusUpdate)
}

// Deploy deploys an application using Nixpacks with the given plan configuration
func (n *NixpacksServiceImpl) Deploy(ctx context.Context, deploymentUID, sourcePath, serviceUID string, planData map[string]interface{}, networks []string) (*types.DeploymentResult, error) {
	stepTemplates := []types.DeploymentStep{
		{
			ID:          deploymentStepInitialize,
			Name:        "Prepare deployment",
			Description: "Validating environment and plan",
			Status:      types.DeploymentStepStatusPending,
			LogType:     "deploy",
		},
		{
			ID:          deploymentStepBuildImage,
			Name:        "Build container image",
			Description: "Running Nixpacks build",
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

	stepTracker := newDeploymentStepTracker(n.logger, n.logsDir, serviceUID, deploymentUID, stepTemplates...)

	if stepTracker != nil {
		stepTracker.StartStep(deploymentStepInitialize, "Prepare deployment", "Validating environment and plan", "deploy")
	}

	if !n.IsInstalled() {
		errorMsg := "nixpacks is not installed"
		if stepTracker != nil {
			stepTracker.FailStep(deploymentStepInitialize, errorMsg)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	n.logger.Info("Starting Nixpacks deployment",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"source_path", sourcePath)

	n.appendDeploymentLog(serviceUID, deploymentUID, "INFO", "Starting Nixpacks deployment")
	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepInitialize, "INFO", "Starting Nixpacks deployment")
	}

	// Update deployment status to in progress
	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusInProgress, "Starting Nixpacks deployment"); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepInitialize, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	// Extract start command from plan data
	startCmd, err := n.extractStartCommand(planData)
	if err != nil {
		errorMsg := fmt.Sprintf("No start command found in Nixpacks plan: %v", err)
		n.logger.Error(errorMsg)
		if updateErr := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusFailed, errorMsg); updateErr != nil {
			n.logger.Warn("Failed to update deployment status", "error", updateErr)
		}
		if stepTracker != nil {
			stepTracker.FailStep(deploymentStepInitialize, errorMsg)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepInitialize, "INFO", fmt.Sprintf("Resolved start command: %s", startCmd))
	}

	imageName := fmt.Sprintf("pulseup-app:%s", serviceUID)
	if n.containerBase != nil {
		imageName = n.containerBase.imageNameForService(serviceUID)
	}

	// We pass arguments directly (no shell), so don't escape quotes.
	buildCommand := []string{"nixpacks", "build", ".", "--name", imageName, "--start-cmd", startCmd}
	if os.Getenv("DEBUG") == "true" { // add verbose output to aid troubleshooting
		buildCommand = append(buildCommand, "--verbose")
	}

	n.logger.Info("Running Nixpacks build",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"image_name", imageName,
		"start_cmd", startCmd,
		"command", strings.Join(buildCommand, " "))

	n.appendDeploymentLog(serviceUID, deploymentUID, "INFO", "Building container image with Nixpacks")
	if stepTracker != nil {
		stepTracker.CompleteStep(deploymentStepInitialize)
		stepTracker.StartStep(deploymentStepBuildImage, "Build container image", "Running Nixpacks build", "build")
		stepTracker.AppendLog(deploymentStepBuildImage, "INFO", "Executing nixpacks build command")
	}

	// Update status to building
	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusInProgress, "Building container image"); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepBuildImage, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	// Build the image
	result, err := n.runCommand(ctx, buildCommand, sourcePath, deploymentUID, serviceUID, "build")
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to execute nixpacks build: %v", err)
		n.logger.Error(errorMsg)
		n.appendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
		if stepTracker != nil {
			stepTracker.FailStep(deploymentStepBuildImage, errorMsg)
		}
		if updateErr := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusFailed, errorMsg); updateErr != nil {
			n.logger.Warn("Failed to update deployment status", "error", updateErr)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	if result.ExitCode != 0 {
		errorMsg := fmt.Sprintf("Nixpacks build failed during deployment for %s. Code: %d. Stderr: %s", serviceUID, result.ExitCode, result.Stderr)
		n.logger.Error(errorMsg)
		n.appendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
		if stepTracker != nil {
			stepTracker.FailStep(deploymentStepBuildImage, errorMsg)
		}
		if updateErr := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusFailed, errorMsg); updateErr != nil {
			n.logger.Warn("Failed to update deployment status", "error", updateErr)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	n.appendDeploymentLog(serviceUID, deploymentUID, "INFO", "Image build completed successfully")
	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepBuildImage, "INFO", "Image build completed successfully")
		stepTracker.CompleteStep(deploymentStepBuildImage)
	}

	// Extract environment variables from plan
	envVars := n.extractEnvVars(planData)

	if stepTracker != nil {
		stepTracker.StartStep(deploymentStepDeployImage, "Deploy container", "Starting application container", "deploy")
	}

	// Update status to deploying
	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusInProgress, "Deploying container"); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepDeployImage, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	// Deploy the container (this would need to be implemented via a deployment service)
	n.appendDeploymentLog(serviceUID, deploymentUID, "INFO", fmt.Sprintf("Deploying container image %s", imageName))
	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepDeployImage, "INFO", fmt.Sprintf("Deploying container image %s", imageName))
	}
	deploymentResult, err := n.deployContainer(ctx, serviceUID, imageName, deploymentUID, envVars, stepTracker)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to deploy container: %v", err)
		n.logger.Error(errorMsg)
		n.appendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
		if stepTracker != nil {
			stepTracker.FailStep(deploymentStepDeployImage, errorMsg)
		}
		if updateErr := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusFailed, errorMsg); updateErr != nil {
			n.logger.Warn("Failed to update deployment status", "error", updateErr)
		}
		return &types.DeploymentResult{
			Success: false,
			Error:   errorMsg,
		}, nil
	}

	if !deploymentResult.Success {
		errorMsg := deploymentResult.Error
		if errorMsg == "" {
			errorMsg = "Unknown deployment error"
		}
		n.logger.Error("Deployment failed", "error", errorMsg)
		n.appendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
		if stepTracker != nil {
			stepTracker.FailStep(deploymentStepDeployImage, errorMsg)
		}
		if updateErr := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusFailed, errorMsg); updateErr != nil {
			n.logger.Warn("Failed to update deployment status", "error", updateErr)
		}
		return deploymentResult, nil
	}

	// Update status to completed
	statusMsg := fmt.Sprintf("Container ID: %s", deploymentResult.ContainerID)
	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusCompleted, statusMsg); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepDeployImage, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	n.appendLogEntry(serviceUID, deploymentUID, "build", "INFO", "Deployment process completed successfully")
	n.appendDeploymentLog(serviceUID, deploymentUID, "INFO", fmt.Sprintf("Deployment completed successfully. Container ID: %s", deploymentResult.ContainerID))
	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepDeployImage, "INFO", fmt.Sprintf("Deployment completed successfully. Container ID: %s", deploymentResult.ContainerID))
		stepTracker.CompleteStep(deploymentStepDeployImage)
	}

	n.logger.Info("Nixpacks deployment completed successfully",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"container_id", deploymentResult.ContainerID)

	return deploymentResult, nil
}

// extractStartCommand extracts the start command from the Nixpacks plan data
func (n *NixpacksServiceImpl) extractStartCommand(planData map[string]interface{}) (string, error) {
	// Try to get start command from phases.start.cmd
	if phases, ok := planData["phases"].(map[string]interface{}); ok {
		if start, ok := phases["start"].(map[string]interface{}); ok {
			if cmd, ok := start["cmd"].(string); ok && cmd != "" {
				return cmd, nil
			}
		}
	}

	// Try to get start command from start.command or start.cmd
	if start, ok := planData["start"].(map[string]interface{}); ok {
		if command, ok := start["command"].(string); ok && command != "" {
			return command, nil
		}
		if cmd, ok := start["cmd"].(string); ok && cmd != "" {
			return cmd, nil
		}
	}

	// Try to get start command directly from startCmd
	if startCmd, ok := planData["startCmd"].(string); ok && startCmd != "" {
		return startCmd, nil
	}

	return "", fmt.Errorf("no start command found in plan data")
}

// extractEnvVars extracts environment variables from the Nixpacks plan data
func (n *NixpacksServiceImpl) extractEnvVars(planData map[string]interface{}) map[string]string {
	envVars := make(map[string]string)

	// Extract from variables field
	if variables, ok := planData["variables"].(map[string]interface{}); ok {
		for k, v := range variables {
			envVars[k] = fmt.Sprintf("%v", v)
		}
	}

	// Extract from env field
	if env, ok := planData["env"].(map[string]interface{}); ok {
		for k, v := range env {
			envVars[k] = fmt.Sprintf("%v", v)
		}
	}

	// Set PORT from plan if not already set
	if _, exists := envVars["PORT"]; !exists {
		if start, ok := planData["start"].(map[string]interface{}); ok {
			if port, ok := start["port"]; ok {
				envVars["PORT"] = fmt.Sprintf("%v", port)
			}
		}
		if port, ok := planData["port"]; ok {
			envVars["PORT"] = fmt.Sprintf("%v", port)
		}
	}

	return envVars
}

// deployContainer deploys the container using a deployment service
func (n *NixpacksServiceImpl) deployContainer(ctx context.Context, serviceUID, imageName, deploymentUID string, envVars map[string]string, recorder types.DeploymentStepRecorder) (*types.DeploymentResult, error) {
	if n.containerBase == nil {
		return nil, fmt.Errorf("deployment service not available")
	}

	return n.containerBase.deployBuiltImage(ctx, serviceUID, imageName, deploymentUID, envVars, recorder, deploymentStepDeployImage)
}

// updateDeploymentStatus updates the deployment status via WebSocket
func (n *NixpacksServiceImpl) updateDeploymentStatus(deploymentUID string, status types.DeploymentStatus, message string) error {
	if n.wsManager == nil {
		return fmt.Errorf("WebSocket manager not available")
	}

	statusUpdate := map[string]interface{}{
		"deployment_uid": deploymentUID,
		"status":         status,
		"message":        message,
		"timestamp":      time.Now().Unix(),
	}

	return n.wsManager.Emit("update_deployment_status", statusUpdate)
}
