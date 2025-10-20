package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

const (
	nixpacksBinary             = "nixpacks"
	defaultNixpacksNodeVersion = "22"
)

// NixpacksServiceImpl provides operations for building and deploying applications with Nixpacks.
type NixpacksServiceImpl struct {
	logger        *logger.Logger
	wsManager     WebSocketManager
	logManager    *deploymentLogManager
	containerBase *containerDeploymentBase
}

// NewNixpacksService wires a Nixpacks service implementation.
func NewNixpacksService(baseLogger *logger.Logger, wsManager WebSocketManager, deploymentService DeploymentService) *NixpacksServiceImpl {
	serviceLogger := baseLogger
	if serviceLogger == nil {
		serviceLogger = logger.New()
	}
	serviceLogger = serviceLogger.With("service", "nixpacks")

	return &NixpacksServiceImpl{
		logger:        serviceLogger,
		wsManager:     wsManager,
		logManager:    newDeploymentLogManager(serviceLogger),
		containerBase: newContainerDeploymentBase(serviceLogger, deploymentService),
	}
}

// IsInstalled checks if the nixpacks binary is available on the host.
func (n *NixpacksServiceImpl) IsInstalled() bool {
	_, err := exec.LookPath(nixpacksBinary)
	return err == nil
}

// BuildImage executes `nixpacks build` for the given source path.
func (n *NixpacksServiceImpl) BuildImage(ctx context.Context, sourcePath, serviceUID, deploymentUID string) (*CommandResult, error) {
	if !n.IsInstalled() {
		return nil, fmt.Errorf("nixpacks is not installed")
	}

	workDir := cleanSourcePath(sourcePath)
	imageName := fmt.Sprintf("pulseup-app:%s", serviceUID)
	if n.containerBase != nil {
		imageName = n.containerBase.imageNameForService(serviceUID)
	}

	command := []string{nixpacksBinary, "build", ".", "--name", imageName}
	result, err := n.logManager.RunCommand(ctx, command, workDir, deploymentUID, serviceUID, "build", nil)
	if err != nil {
		return nil, err
	}

	if result.ExitCode != 0 {
		return result, fmt.Errorf("nixpacks build failed with exit code %d", result.ExitCode)
	}

	return result, nil
}

// GeneratePlan runs `nixpacks plan` and parses the resulting JSON output.
func (n *NixpacksServiceImpl) GeneratePlan(ctx context.Context, sourcePath string) (*types.NixpacksPlan, error) {
	if !n.IsInstalled() {
		return nil, fmt.Errorf("nixpacks is not installed")
	}

	workDir := cleanSourcePath(sourcePath)

	cmd := exec.CommandContext(ctx, nixpacksBinary, "plan", ".", "--format", "json")
	cmd.Dir = workDir

	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			if stderr == "" {
				stderr = exitErr.Error()
			}
			return nil, fmt.Errorf("failed to generate nixpacks plan: %s", stderr)
		}
		return nil, fmt.Errorf("failed to run nixpacks plan: %w", err)
	}

	var plan types.NixpacksPlan
	if err := json.Unmarshal(output, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse nixpacks plan output: %w", err)
	}

	return &plan, nil
}

// Deploy executes the Nixpacks build and orchestrates container deployment.
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

	stepTracker := n.logManager.NewStepTracker(serviceUID, deploymentUID, stepTemplates...)

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

	workDir := cleanSourcePath(sourcePath)

	n.logger.Info("Starting Nixpacks deployment",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"source_path", workDir)

	planData = n.mergeDetectedPlanData(ctx, workDir, planData)

	n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "INFO", "Starting Nixpacks deployment")
	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepInitialize, "INFO", "Starting Nixpacks deployment")
	}

	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusInProgress, "Starting Nixpacks deployment"); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepInitialize, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	imageName := fmt.Sprintf("pulseup-app:%s", serviceUID)
	if n.containerBase != nil {
		imageName = n.containerBase.imageNameForService(serviceUID)
	}

	buildCommand := n.buildCommand(planData, imageName)
	if os.Getenv("DEBUG") == "true" {
		buildCommand = append(buildCommand, "--verbose")
	}

	envVars, runtimeNotes := n.extractEnvVars(planData)

	if extraNotes, err := n.ensureNodeRuntimeOverrides(planData, envVars); err != nil {
		n.logger.Warn("Failed to enforce Node runtime overrides", "error", err)
		n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "WARN", fmt.Sprintf("Failed to enforce Node runtime overrides: %v", err))
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepInitialize, "WARN", fmt.Sprintf("Failed to enforce Node runtime overrides: %v", err))
		}
	} else if len(extraNotes) > 0 {
		runtimeNotes = append(runtimeNotes, extraNotes...)
	}

	if len(envVars) > 0 {
		keys := make([]string, 0, len(envVars))
		for key := range envVars {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			value := strings.TrimSpace(envVars[key])
			if value == "" {
				continue
			}
			buildCommand = append(buildCommand, "--env", fmt.Sprintf("%s=%s", key, value))
		}
	}

	if len(runtimeNotes) > 0 {
		note := fmt.Sprintf("Applied runtime guardrails: %s", strings.Join(runtimeNotes, ", "))
		n.logger.Info(note,
			"service_uid", serviceUID,
			"deployment_uid", deploymentUID)
		n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "INFO", note)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepInitialize, "INFO", note)
		}
	}

	n.logger.Info("Running Nixpacks build",
		"service_uid", serviceUID,
		"deployment_uid", deploymentUID,
		"image_name", imageName,
		"command", strings.Join(buildCommand, " "))

	n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "INFO", "Building container image with Nixpacks")
	if stepTracker != nil {
		stepTracker.CompleteStep(deploymentStepInitialize)
		stepTracker.StartStep(deploymentStepBuildImage, "Build container image", "Running Nixpacks build", "build")
		stepTracker.AppendLog(deploymentStepBuildImage, "INFO", "Executing nixpacks build command")
	}

	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusInProgress, "Building container image"); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepBuildImage, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	result, err := n.logManager.RunCommand(ctx, buildCommand, workDir, deploymentUID, serviceUID, "build", nil)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to execute nixpacks build: %v", err)
		n.logger.Error(errorMsg)
		n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
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
		n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
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

	n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "INFO", "Image build completed successfully")
	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepBuildImage, "INFO", "Image build completed successfully")
		stepTracker.CompleteStep(deploymentStepBuildImage)
	}

	if stepTracker != nil {
		stepTracker.StartStep(deploymentStepDeployImage, "Deploy container", "Starting application container", "deploy")
	}

	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusInProgress, "Deploying container"); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepDeployImage, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "INFO", fmt.Sprintf("Deploying container image %s", imageName))
	if stepTracker != nil {
		stepTracker.AppendLog(deploymentStepDeployImage, "INFO", fmt.Sprintf("Deploying container image %s", imageName))
	}

	deploymentResult, err := n.deployContainer(ctx, serviceUID, imageName, deploymentUID, envVars, stepTracker)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to deploy container: %v", err)
		n.logger.Error(errorMsg)
		n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
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
		n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "ERROR", errorMsg)
		if stepTracker != nil {
			stepTracker.FailStep(deploymentStepDeployImage, errorMsg)
		}
		if updateErr := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusFailed, errorMsg); updateErr != nil {
			n.logger.Warn("Failed to update deployment status", "error", updateErr)
		}
		return deploymentResult, nil
	}

	statusMsg := fmt.Sprintf("Container ID: %s", deploymentResult.ContainerID)
	if err := n.updateDeploymentStatus(deploymentUID, types.DeploymentStatusCompleted, statusMsg); err != nil {
		n.logger.Warn("Failed to update deployment status", "error", err)
		if stepTracker != nil {
			stepTracker.AppendLog(deploymentStepDeployImage, "WARN", fmt.Sprintf("Failed to update deployment status: %v", err))
		}
	}

	n.logManager.AppendLogEntry(serviceUID, deploymentUID, "build", "INFO", "Deployment process completed successfully")
	n.logManager.AppendDeploymentLog(serviceUID, deploymentUID, "INFO", fmt.Sprintf("Deployment completed successfully. Container ID: %s", deploymentResult.ContainerID))
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

func (n *NixpacksServiceImpl) extractEnvVars(planData map[string]interface{}) (map[string]string, []string) {
	envVars := make(map[string]string)

	if variables, ok := planData["variables"].(map[string]interface{}); ok {
		for k, v := range variables {
			envVars[k] = fmt.Sprintf("%v", v)
		}
	}

	if env, ok := planData["env"].(map[string]interface{}); ok {
		for k, v := range env {
			envVars[k] = fmt.Sprintf("%v", v)
		}
	}

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

	guardrailNotes := n.applyRuntimeGuardrails(planData, envVars)

	return envVars, guardrailNotes
}

func (n *NixpacksServiceImpl) ensureNodeRuntimeOverrides(planData map[string]interface{}, envVars map[string]string) ([]string, error) {
	providers := extractProviders(planData)
	needsNodeRuntime := false
	for _, provider := range providers {
		switch provider {
		case "node", "nodejs", "bun":
			needsNodeRuntime = true
			break
		}
		if needsNodeRuntime {
			break
		}
	}

	if !needsNodeRuntime {
		return nil, nil
	}

	desiredVersion := strings.TrimSpace(envVars["NIXPACKS_NODE_VERSION"])
	if desiredVersion == "" {
		desiredVersion = strings.TrimSpace(envVars["NODE_VERSION"])
	}
	if desiredVersion == "" {
		desiredVersion = defaultNixpacksNodeVersion
	}

	envVars["NIXPACKS_NODE_VERSION"] = desiredVersion
	envVars["NODE_VERSION"] = desiredVersion

	notes := []string{fmt.Sprintf("NIXPACKS_NODE_VERSION → %s", desiredVersion)}

	if _, exists := envVars["NIXPACKS_CONFIG_FILE"]; exists {
		return notes, nil
	}

	configPath, descriptor, err := createNixpacksConfigFile(desiredVersion)
	if err != nil {
		return notes, err
	}

	envVars["NIXPACKS_CONFIG_FILE"] = configPath
	notes = append(notes, fmt.Sprintf("Nixpacks packages → %s", descriptor))

	return notes, nil
}

func createNixpacksConfigFile(nodeVersion string) (string, string, error) {
	parsed := parseVersion(nodeVersion)
	if parsed.Invalid || parsed.Major == 0 {
		return "", "", fmt.Errorf("invalid Node version for Nixpacks config: %s", nodeVersion)
	}

	packageName := fmt.Sprintf("nodejs_%d", parsed.Major)
	contents := fmt.Sprintf("[phases.setup]\nnixPkgs = [\"%s\",\"bun\"]\n", packageName)

	tmpFile, err := os.CreateTemp("", "nixpacks-config-*.toml")
	if err != nil {
		return "", "", fmt.Errorf("failed to create temporary Nixpacks config: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(contents); err != nil {
		return "", "", fmt.Errorf("failed to write Nixpacks config: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		return "", "", fmt.Errorf("failed to flush Nixpacks config: %w", err)
	}

	return tmpFile.Name(), fmt.Sprintf("%s,bun", packageName), nil
}

func (n *NixpacksServiceImpl) deployContainer(ctx context.Context, serviceUID, imageName, deploymentUID string, envVars map[string]string, recorder types.DeploymentStepRecorder) (*types.DeploymentResult, error) {
	if n.containerBase == nil {
		return nil, fmt.Errorf("deployment service not available")
	}

	return n.containerBase.deployBuiltImage(ctx, serviceUID, imageName, deploymentUID, envVars, recorder, deploymentStepDeployImage)
}

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

func cleanSourcePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "."
	}
	if strings.HasPrefix(trimmed, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(trimmed, "~"))
		}
	}
	return filepath.Clean(trimmed)
}

func (n *NixpacksServiceImpl) buildCommand(planData map[string]interface{}, imageName string) []string {
	command := []string{nixpacksBinary, "build", ".", "--name", imageName}

	overrides := extractCommandOverrides(planData)
	if overrides.install != "" {
		command = append(command, "--install-cmd", overrides.install)
	}
	if overrides.build != "" {
		command = append(command, "--build-cmd", overrides.build)
	}
	if overrides.start != "" {
		command = append(command, "--start-cmd", overrides.start)
	}

	return command
}

type commandOverrides struct {
	install string
	build   string
	start   string
}

func extractCommandOverrides(planData map[string]interface{}) commandOverrides {
	var overrides commandOverrides

	if phases, ok := planData["phases"].(map[string]interface{}); ok {
		overrides.install = commandFromPhase(phases, "setup", overrides.install)
		overrides.install = commandFromPhase(phases, "install", overrides.install)
		overrides.build = commandFromPhase(phases, "build", overrides.build)
		overrides.start = commandFromPhase(phases, "start", overrides.start)
	}

	if overrides.install == "" {
		overrides.install = stringField(planData, "installCmd")
	}
	if overrides.build == "" {
		if buildSlice, ok := planData["buildCmd"].([]interface{}); ok {
			overrides.build = joinInterfaceSlice(buildSlice)
		} else {
			overrides.build = stringField(planData, "buildCmd")
		}
	}
	if overrides.start == "" {
		overrides.start = stringField(planData, "startCmd")
	}

	return overrides
}

func commandFromPhase(phases map[string]interface{}, key string, existing string) string {
	if existing != "" {
		return existing
	}
	if phase, ok := phases[key].(map[string]interface{}); ok {
		if cmd, ok := phase["cmd"].(string); ok {
			return strings.TrimSpace(cmd)
		}
	}
	return existing
}

func stringField(data map[string]interface{}, key string) string {
	if value, ok := data[key].(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func joinInterfaceSlice(values []interface{}) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		part := strings.TrimSpace(fmt.Sprintf("%v", v))
		if part != "" {
			parts = append(parts, part)
		}
	}
	return strings.Join(parts, " ")
}

func (n *NixpacksServiceImpl) mergeDetectedPlanData(ctx context.Context, workDir string, planData map[string]interface{}) map[string]interface{} {
	if planData == nil {
		planData = make(map[string]interface{})
	}

	cmd := exec.CommandContext(ctx, nixpacksBinary, "plan", ".", "--format", "json")
	cmd.Dir = workDir

	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			n.logger.Warn("Failed to detect Nixpacks plan", "error", strings.TrimSpace(string(exitErr.Stderr)))
		} else {
			n.logger.Warn("Failed to run Nixpacks plan", "error", err)
		}
		return planData
	}

	detected := make(map[string]interface{})
	if err := json.Unmarshal(trimBOM(output), &detected); err != nil {
		n.logger.Warn("Failed to parse detected Nixpacks plan", "error", err)
		return planData
	}

	return mergePlanMaps(detected, planData)
}

var providerDependencies = map[string][]string{
	"bun": {"node"},
}

func canonicalProviderKey(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	switch key {
	case "nodejs":
		return "node"
	case "node":
		return "node"
	case "bun":
		return "bun"
	case "python":
		return "python"
	case "ruby":
		return "ruby"
	case "go":
		return "go"
	case "java":
		return "java"
	case "dotnet":
		return "dotnet"
	case "php":
		return "php"
	default:
		return key
	}
}

func (n *NixpacksServiceImpl) applyRuntimeGuardrails(planData map[string]interface{}, envVars map[string]string) []string {
	providerSet := make(map[string]struct{})

	var addProvider func(string)
	addProvider = func(raw string) {
		key := canonicalProviderKey(raw)
		if key == "" {
			return
		}
		if _, exists := providerSet[key]; exists {
			return
		}
		providerSet[key] = struct{}{}
		if deps, ok := providerDependencies[key]; ok {
			for _, dep := range deps {
				addProvider(dep)
			}
		}
	}

	for _, provider := range extractProviders(planData) {
		addProvider(provider)
	}

	if metadataEnv := strings.TrimSpace(strings.ToLower(envVars["NIXPACKS_METADATA"])); metadataEnv != "" {
		addProvider(metadataEnv)
	}

	if metadata := stringField(planData, "metadata"); metadata != "" {
		addProvider(metadata)
	}

	if len(providerSet) == 0 {
		return nil
	}

	notes := make([]string, 0, len(providerSet))

	for provider := range providerSet {
		spec, ok := runtimeGuardrails[provider]
		if !ok {
			continue
		}

		candidate := findExistingVersion(spec, envVars, planData)
		normalized, adjusted := normalizeRuntimeVersion(spec, candidate)
		if !adjusted {
			continue
		}

		for _, envKey := range spec.EnvKeys {
			if envKey == "" {
				continue
			}
			envVars[envKey] = normalized
		}

		notes = append(notes, fmt.Sprintf("%s → %s", spec.DisplayName, normalized))
	}

	sort.Strings(notes)
	return notes
}

func extractProviders(planData map[string]interface{}) []string {
	providersRaw, ok := planData["providers"].([]interface{})
	if !ok {
		return nil
	}

	providers := make([]string, 0, len(providersRaw))
	seen := make(map[string]struct{})
	for _, value := range providersRaw {
		raw := strings.TrimSpace(fmt.Sprintf("%v", value))
		key := canonicalProviderKey(raw)
		if key == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		providers = append(providers, key)
	}
	return providers
}

func findExistingVersion(spec runtimeGuardrailSpec, envVars map[string]string, planData map[string]interface{}) string {
	for _, key := range spec.EnvKeys {
		if value := strings.TrimSpace(envVars[key]); value != "" {
			return value
		}
	}

	if variables, ok := planData["variables"].(map[string]interface{}); ok {
		for _, key := range spec.EnvKeys {
			if value, ok := variables[key]; ok {
				if str := strings.TrimSpace(fmt.Sprintf("%v", value)); str != "" {
					return str
				}
			}
		}
	}

	if env, ok := planData["env"].(map[string]interface{}); ok {
		for _, key := range spec.EnvKeys {
			if value, ok := env[key]; ok {
				if str := strings.TrimSpace(fmt.Sprintf("%v", value)); str != "" {
					return str
				}
			}
		}
	}

	return ""
}

func normalizeRuntimeVersion(spec runtimeGuardrailSpec, candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return spec.DefaultVersion, spec.DefaultVersion != ""
	}

	version := parseVersion(candidate)
	if version.Invalid {
		return spec.DefaultVersion, spec.DefaultVersion != ""
	}

	if version.Major < spec.MinMajor {
		return spec.DefaultVersion, spec.DefaultVersion != ""
	}
	if version.Major == spec.MinMajor && version.Minor < spec.MinMinor {
		return spec.DefaultVersion, spec.DefaultVersion != ""
	}

	return candidate, false
}

type parsedVersion struct {
	Major   int
	Minor   int
	Invalid bool
}

func parseVersion(raw string) parsedVersion {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(raw), "v"))
	if raw == "" {
		return parsedVersion{Invalid: true}
	}

	parts := strings.Split(raw, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return parsedVersion{Invalid: true}
	}

	minor := 0
	if len(parts) > 1 {
		if value, err := strconv.Atoi(parts[1]); err == nil {
			minor = value
		}
	}

	return parsedVersion{Major: major, Minor: minor}
}

type runtimeGuardrailSpec struct {
	DisplayName    string
	EnvKeys        []string
	DefaultVersion string
	MinMajor       int
	MinMinor       int
}

var runtimeGuardrails = map[string]runtimeGuardrailSpec{
	"node": {
		DisplayName:    "Node.js",
		EnvKeys:        []string{"NIXPACKS_NODE_VERSION", "NODE_VERSION"},
		DefaultVersion: defaultNixpacksNodeVersion,
		MinMajor:       22,
		MinMinor:       0,
	},
	"nodejs": {
		DisplayName:    "Node.js",
		EnvKeys:        []string{"NIXPACKS_NODE_VERSION", "NODE_VERSION"},
		DefaultVersion: defaultNixpacksNodeVersion,
		MinMajor:       22,
		MinMinor:       0,
	},
	"bun": {
		DisplayName:    "Bun",
		EnvKeys:        []string{"BUN_VERSION"},
		DefaultVersion: "latest",
		MinMajor:       1,
		MinMinor:       0,
	},
	"python": {
		DisplayName:    "Python",
		EnvKeys:        []string{"PYTHON_VERSION"},
		DefaultVersion: "3.12",
		MinMajor:       3,
		MinMinor:       11,
	},
	"ruby": {
		DisplayName:    "Ruby",
		EnvKeys:        []string{"RUBY_VERSION"},
		DefaultVersion: "3.3",
		MinMajor:       3,
		MinMinor:       2,
	},
	"go": {
		DisplayName:    "Go",
		EnvKeys:        []string{"GO_VERSION", "GOVERSION"},
		DefaultVersion: "1.22",
		MinMajor:       1,
		MinMinor:       21,
	},
	"java": {
		DisplayName:    "Java",
		EnvKeys:        []string{"JAVA_VERSION"},
		DefaultVersion: "21",
		MinMajor:       21,
		MinMinor:       0,
	},
	"dotnet": {
		DisplayName:    ".NET",
		EnvKeys:        []string{"DOTNET_VERSION", "DOTNET_SDK_VERSION"},
		DefaultVersion: "8.0",
		MinMajor:       8,
		MinMinor:       0,
	},
	"php": {
		DisplayName:    "PHP",
		EnvKeys:        []string{"PHP_VERSION"},
		DefaultVersion: "8.3",
		MinMajor:       8,
		MinMinor:       2,
	},
}

func mergePlanMaps(base, override map[string]interface{}) map[string]interface{} {
	result := clonePlanMap(base)
	for key, value := range override {
		if existing, ok := result[key]; ok {
			existingMap, okExisting := existing.(map[string]interface{})
			valueMap, okValue := value.(map[string]interface{})
			if okExisting && okValue {
				result[key] = mergePlanMaps(existingMap, valueMap)
				continue
			}
		}
		result[key] = clonePlanValue(value)
	}
	return result
}

func clonePlanMap(source map[string]interface{}) map[string]interface{} {
	if source == nil {
		return make(map[string]interface{})
	}
	clone := make(map[string]interface{}, len(source))
	for key, value := range source {
		clone[key] = clonePlanValue(value)
	}
	return clone
}

func clonePlanValue(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		return clonePlanMap(v)
	case []interface{}:
		copySlice := make([]interface{}, len(v))
		for i, item := range v {
			copySlice[i] = clonePlanValue(item)
		}
		return copySlice
	default:
		return v
	}
}

func trimBOM(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return data[3:]
	}
	return data
}
