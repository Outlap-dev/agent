package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"

	"gopkg.in/yaml.v3"
)

type composeRunContext struct {
	LogManager    *deploymentLogManager
	ServiceUID    string
	DeploymentUID string
	LogType       string
}

type composeCommandRunner interface {
	Run(ctx context.Context, name string, args []string, workingDir string, env []string, runCtx composeRunContext) (*CommandResult, error)
}

type execComposeCommandRunner struct{}

func (r *execComposeCommandRunner) Run(ctx context.Context, name string, args []string, workingDir string, env []string, runCtx composeRunContext) (*CommandResult, error) {
	command := append([]string{name}, args...)
	if runCtx.LogManager != nil {
		return runCtx.LogManager.RunCommand(ctx, command, workingDir, runCtx.DeploymentUID, runCtx.ServiceUID, runCtx.LogType, env)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = workingDir
	if len(env) > 0 {
		cmd.Env = env
	}

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return &CommandResult{
		Stdout:   output.String(),
		Stderr:   output.String(),
		ExitCode: exitCode,
	}, nil
}

// DockerComposeServiceImpl coordinates docker compose deployments.
type DockerComposeServiceImpl struct {
	logger     *logger.Logger
	runner     composeCommandRunner
	logManager *deploymentLogManager
}

var composeServiceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][-_A-Za-z0-9]*$`)

// NewDockerComposeService constructs a docker compose deployment service.
func NewDockerComposeService(baseLogger *logger.Logger) *DockerComposeServiceImpl {
	serviceLogger := baseLogger.With("service", "docker_compose")
	return &DockerComposeServiceImpl{
		logger:     serviceLogger,
		runner:     &execComposeCommandRunner{},
		logManager: newDeploymentLogManager(serviceLogger),
	}
}

// WithRunner allows tests to override the command runner implementation.
func (s *DockerComposeServiceImpl) WithRunner(r composeCommandRunner) *DockerComposeServiceImpl {
	if r != nil {
		s.runner = r
	}
	return s
}

// Deploy executes a docker compose deployment using the provided request data.
func (s *DockerComposeServiceImpl) Deploy(ctx context.Context, req *types.DockerComposeDeploymentRequest) (*types.DeploymentResult, error) {
	if req == nil {
		return &types.DeploymentResult{Success: false, Error: "deployment request is nil"}, errors.New("docker compose deployment request is nil")
	}

	if req.SourcePath == "" {
		return &types.DeploymentResult{Success: false, Error: "source path is required"}, errors.New("source path is required")
	}

	serviceUID := strings.TrimSpace(req.ServiceUID)
	deploymentUID := strings.TrimSpace(req.DeploymentUID)

	stepTemplates := []types.DeploymentStep{
		{
			ID:          deploymentStepInitialize,
			Name:        "Prepare deployment",
			Description: "Validating compose configuration",
			Status:      types.DeploymentStepStatusPending,
			LogType:     "deploy",
		},
		{
			ID:          deploymentStepBuildImage,
			Name:        "Build compose project",
			Description: "Running docker compose commands",
			Status:      types.DeploymentStepStatusPending,
			LogType:     "build",
		},
		{
			ID:          deploymentStepDeployImage,
			Name:        "Finalize deployment",
			Description: "Applying PulseUp labels",
			Status:      types.DeploymentStepStatusPending,
			LogType:     "deploy",
		},
	}

	stepTracker := s.logManager.NewStepTracker(serviceUID, deploymentUID, stepTemplates...)

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
		if s.logManager != nil {
			s.logManager.AppendDeploymentLog(serviceUID, deploymentUID, level, message)
		}
	}

	composeFile := strings.TrimSpace(req.ComposeFile)
	if composeFile == "" {
		composeFile = "docker-compose.yml"
	}

	absSource := filepath.Clean(req.SourcePath)
	absCompose := filepath.Join(absSource, filepath.Clean(composeFile))

	startStep(deploymentStepInitialize, "Prepare deployment", "Validating compose configuration", "deploy")
	logDeploy("INFO", fmt.Sprintf("Starting Docker Compose deployment using %s", composeFile))
	appendStepLog(deploymentStepInitialize, "INFO", fmt.Sprintf("Using compose file %s", absCompose))

	rel, err := filepath.Rel(absSource, absCompose)
	if err != nil || strings.HasPrefix(rel, "..") {
		errorMsg := "compose file path escapes repository"
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepInitialize, errorMsg)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, errors.New(errorMsg)
	}

	if _, err := os.Stat(absCompose); err != nil {
		if os.IsNotExist(err) {
			errorMsg := fmt.Sprintf("compose file %s not found", composeFile)
			logDeploy("ERROR", errorMsg)
			failStep(deploymentStepInitialize, errorMsg)
			return &types.DeploymentResult{Success: false, Error: errorMsg}, errors.New(errorMsg)
		}
		errorMsg := fmt.Sprintf("failed to stat compose file: %v", err)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepInitialize, errorMsg)
		return &types.DeploymentResult{Success: false, Error: err.Error()}, errors.New(errorMsg)
	}

	projectName := strings.TrimSpace(req.ProjectName)
	if projectName == "" {
		projectName = fmt.Sprintf("pulseup-%s", req.ServiceUID)
		appendStepLog(deploymentStepInitialize, "INFO", fmt.Sprintf("Defaulting project name to %s", projectName))
	}

	env := append(os.Environ(), formatEnv(req.Environment)...)

	composeFiles := s.collectComposeFiles(absCompose)
	validatedComposeFiles, availableServices := s.validateComposeFiles(ctx, absSource, projectName, composeFiles, env)
	appendStepLog(deploymentStepInitialize, "INFO", fmt.Sprintf("Validated %d compose file(s)", len(validatedComposeFiles)))

	primaryService, restrictServices, selectionErr := s.determineComposeService(req, availableServices)
	if selectionErr != nil {
		errorMsg := selectionErr.Error()
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepInitialize, errorMsg)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, selectionErr
	}
	appendStepLog(deploymentStepInitialize, "INFO", fmt.Sprintf("Deploying compose service: %s", primaryService))

	labelsViaOverride := false
	var (
		overridePath    string
		overrideCleanup func()
	)

	targetServices := []string{primaryService}
	var overrideErr error
	overridePath, overrideCleanup, overrideErr = s.createLabelOverrideFile(absSource, targetServices, req.ServiceUID, req.DeploymentUID, req.PortMappings)
	if overrideErr != nil {
		s.logger.Warn("Failed to prepare compose label override", "error", overrideErr)
		appendStepLog(deploymentStepInitialize, "WARN", fmt.Sprintf("Label override creation failed: %v", overrideErr))
	} else if overridePath != "" {
		labelsViaOverride = true
		appendStepLog(deploymentStepInitialize, "INFO", fmt.Sprintf("Prepared label override file %s", overridePath))
		defer func() {
			if overrideCleanup != nil {
				overrideCleanup()
			}
		}()
	}

	actualComposeFiles := append([]string{}, validatedComposeFiles...)
	if overridePath != "" {
		actualComposeFiles = append(actualComposeFiles, overridePath)
	}

	appendStepLog(deploymentStepInitialize, "INFO", fmt.Sprintf("Final compose file set: %v", actualComposeFiles))
	completeStep(deploymentStepInitialize)

	startStep(deploymentStepBuildImage, "Build compose project", "Running docker compose commands", "build")
	appendStepLog(deploymentStepBuildImage, "INFO", "Stopping any existing compose services")
	logDeploy("INFO", "Stopping existing compose services (docker compose down)")

	downArgs := s.buildComposeArgs(projectName, actualComposeFiles)
	downArgs = append(downArgs, "down", "--remove-orphans")
	downResult, err := s.runDockerCommand(ctx, downArgs, absSource, env, serviceUID, deploymentUID, "deploy")
	if err != nil {
		errorMsg := fmt.Sprintf("docker compose down failed: %v", err)
		s.logger.Warn("docker compose down failed", "error", err)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepBuildImage, errorMsg)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, errors.New(errorMsg)
	}
	if downResult.ExitCode != 0 {
		errorMsg := fmt.Sprintf("docker compose down exited with code %d", downResult.ExitCode)
		s.logger.Warn("docker compose down returned non-zero", "exit_code", downResult.ExitCode)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepBuildImage, errorMsg)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, errors.New(errorMsg)
	}

	appendStepLog(deploymentStepBuildImage, "INFO", "Existing compose services stopped")
	appendStepLog(deploymentStepBuildImage, "INFO", "Running docker compose up --build")
	logDeploy("INFO", "Running docker compose up --build")

	upArgs := s.buildComposeArgs(projectName, actualComposeFiles)
	upArgs = append(upArgs, "up", "-d", "--build")
	if restrictServices && primaryService != "" {
		upArgs = append(upArgs, primaryService)
	}

	upResult, err := s.runDockerCommand(ctx, upArgs, absSource, env, serviceUID, deploymentUID, "build")
	if err != nil {
		errorMsg := fmt.Sprintf("docker compose up failed: %v", err)
		s.logger.Error("docker compose up failed", "error", err)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepBuildImage, errorMsg)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, err
	}
	if upResult.ExitCode != 0 {
		errorMsg := fmt.Sprintf("docker compose up exited with code %d", upResult.ExitCode)
		s.logger.Error("docker compose up returned non-zero", "exit_code", upResult.ExitCode, "stderr", upResult.Stderr)
		logDeploy("ERROR", errorMsg)
		failStep(deploymentStepBuildImage, errorMsg)
		return &types.DeploymentResult{Success: false, Error: errorMsg}, fmt.Errorf(errorMsg)
	}

	appendStepLog(deploymentStepBuildImage, "INFO", "docker compose up completed successfully")
	completeStep(deploymentStepBuildImage)
	if s.logManager != nil {
		s.logManager.AppendLogEntry(serviceUID, deploymentUID, "build", "INFO", "docker compose up completed successfully")
	}

	startStep(deploymentStepDeployImage, "Finalize deployment", "Applying PulseUp labels", "deploy")
	if !labelsViaOverride {
		appendStepLog(deploymentStepDeployImage, "INFO", "Applying PulseUp labels to compose containers")
		if err := s.labelComposeContainers(ctx, projectName, req.ServiceUID, req.DeploymentUID); err != nil {
			s.logger.Warn("Failed to add PulseUp labels to compose containers", "error", err)
			appendStepLog(deploymentStepDeployImage, "WARN", fmt.Sprintf("Failed to label containers: %v", err))
		}
	} else {
		appendStepLog(deploymentStepDeployImage, "INFO", "PulseUp labels applied via override file")
	}

	completeStep(deploymentStepDeployImage)
	logDeploy("INFO", fmt.Sprintf("docker compose deployment completed for project %s", projectName))

	return &types.DeploymentResult{
		Success:         true,
		ContainerName:   projectName,
		DeploymentColor: "compose",
	}, nil
}

func formatEnv(environment map[string]string) []string {
	if len(environment) == 0 {
		return nil
	}

	formatted := make([]string, 0, len(environment))
	for key, value := range environment {
		if key == "" {
			continue
		}
		formatted = append(formatted, fmt.Sprintf("%s=%s", key, value))
	}
	return formatted
}

// labelComposeContainers adds PulseUp management labels to all containers in a compose project
func (s *DockerComposeServiceImpl) labelComposeContainers(ctx context.Context, projectName, serviceUID, deploymentUID string) error {
	// Find all containers with the compose project label
	listArgs := []string{"ps", "-a", "-q", "--filter", fmt.Sprintf("label=com.docker.compose.project=%s", projectName)}

	result, err := s.runDockerCommand(ctx, listArgs, ".", nil, serviceUID, deploymentUID, "")
	if err != nil {
		return fmt.Errorf("failed to list compose containers: %w", err)
	}

	containerIDs := strings.Fields(strings.TrimSpace(result.Stdout))
	if len(containerIDs) == 0 {
		s.logger.Warn("No containers found for compose project", "project", projectName)
		return nil
	}

	// Add labels to each container using docker container update
	// Note: Label operations in docker update were added in Docker API 1.45 / Docker Engine 25.0
	// For compatibility, we'll try the update command and fall back if it fails
	for _, containerID := range containerIDs {
		if containerID == "" {
			continue
		}

		// Try using docker container update to add labels
		labelArgs := []string{
			"container", "update",
			"--label-add", fmt.Sprintf("pulseup.managed=true"),
			"--label-add", fmt.Sprintf("pulseup.service_uid=%s", serviceUID),
			"--label-add", fmt.Sprintf("pulseup.deployment_uid=%s", deploymentUID),
			containerID,
		}

		_, err := s.runDockerCommand(ctx, labelArgs, ".", nil, serviceUID, deploymentUID, "deploy")
		if err != nil {
			// The --label-add flag might not be supported in older Docker versions
			// In this case, we log a warning but don't fail the deployment
			s.logger.Warn("Could not add labels to container (requires Docker 25.0+)",
				"container_id", containerID,
				"error", err,
				"note", "Container deployed successfully but missing PulseUp management labels")
		} else {
			s.logger.Debug("Added PulseUp labels to container", "container_id", containerID)
		}
	}

	return nil
}

func (s *DockerComposeServiceImpl) determineComposeService(req *types.DockerComposeDeploymentRequest, availableServices []string) (string, bool, error) {
	normalizedAvailable := normalizeServiceNames(availableServices)
	if len(normalizedAvailable) == 0 {
		return "", false, fmt.Errorf("no services defined in docker compose configuration")
	}

	if len(normalizedAvailable) == 1 {
		svc := normalizedAvailable[0]
		if len(req.SelectedServices) > 0 {
			normalizedSelected := normalizeServiceNames(req.SelectedServices)
			if len(normalizedSelected) > 1 {
				return "", false, fmt.Errorf("multiple services selected but only one is supported")
			}
			if len(normalizedSelected) == 1 && !strings.EqualFold(normalizedSelected[0], svc) {
				return "", false, fmt.Errorf("selected service %s not found in compose file", normalizedSelected[0])
			}
		}
		return svc, false, nil
	}

	normalizedSelected := normalizeServiceNames(req.SelectedServices)
	if len(normalizedSelected) == 0 {
		if strings.EqualFold(strings.TrimSpace(req.ServiceMode), "all") {
			return "", false, fmt.Errorf("multiple services detected in compose file; select exactly one service to deploy")
		}
		return "", false, fmt.Errorf("select exactly one service to deploy from your compose file")
	}
	if len(normalizedSelected) > 1 {
		return "", false, fmt.Errorf("multiple services selected but only one is supported")
	}

	selected := normalizedSelected[0]
	availableMap := make(map[string]string, len(normalizedAvailable))
	for _, svc := range normalizedAvailable {
		availableMap[strings.ToLower(svc)] = svc
	}
	if canonical, exists := availableMap[strings.ToLower(selected)]; exists {
		return canonical, true, nil
	}

	return "", false, fmt.Errorf("selected service %s not found in compose file", selected)
}

func (s *DockerComposeServiceImpl) listComposeServices(ctx context.Context, workDir string, composeFiles []string, projectName string, env []string) ([]string, error) {
	args := s.buildComposeArgs(projectName, composeFiles)
	args = append(args, "config", "--services")

	result, err := s.runDockerCommand(ctx, args, workDir, env, "", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate compose services: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	services := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if composeServiceNamePattern.MatchString(trimmed) {
			services = append(services, trimmed)
			continue
		}

		if s.logger != nil {
			s.logger.Debug("Ignoring non-service output from compose", "line", trimmed)
		}
	}

	return services, nil
}

func normalizeServiceNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, trimmed)
	}

	sort.Strings(result)
	return result
}

func (s *DockerComposeServiceImpl) runDockerCommand(ctx context.Context, args []string, workDir string, env []string, serviceUID, deploymentUID, logType string) (*CommandResult, error) {
	if s.runner == nil {
		if s.logManager != nil {
			return s.logManager.RunCommand(ctx, append([]string{"docker"}, args...), workDir, deploymentUID, serviceUID, logType, env)
		}
		return (&execComposeCommandRunner{}).Run(ctx, "docker", args, workDir, env, composeRunContext{})
	}

	return s.runner.Run(ctx, "docker", args, workDir, env, composeRunContext{
		LogManager:    s.logManager,
		ServiceUID:    serviceUID,
		DeploymentUID: deploymentUID,
		LogType:       logType,
	})
}

func (s *DockerComposeServiceImpl) createLabelOverrideFile(workDir string, services []string, serviceUID, deploymentUID string, portMappings []types.PortMapping) (string, func(), error) {
	normalized := normalizeServiceNames(services)
	if len(normalized) == 0 {
		return "", nil, nil
	}

	overridePorts := buildComposePortOverrides(portMappings)

	type serviceOverride struct {
		Labels map[string]string `yaml:"labels,omitempty"`
		Ports  []string          `yaml:"ports,omitempty"`
	}

	servicesMap := make(map[string]serviceOverride, len(normalized))
	portsAssigned := false
	for _, svc := range normalized {
		override := serviceOverride{
			Labels: map[string]string{
				"pulseup.managed":        "true",
				"pulseup.service_uid":    serviceUID,
				"pulseup.deployment_uid": deploymentUID,
			},
		}
		if !portsAssigned && len(overridePorts) > 0 {
			override.Ports = overridePorts
			portsAssigned = true
		}
		servicesMap[svc] = override
	}

	composeOverride := map[string]interface{}{
		"services": servicesMap,
	}

	content, err := yaml.Marshal(composeOverride)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal compose override: %w", err)
	}

	file, err := os.CreateTemp(workDir, "pulseup-compose-override-*.yml")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create compose override file: %w", err)
	}

	if _, err := file.Write(content); err != nil {
		file.Close()
		_ = os.Remove(file.Name())
		return "", nil, fmt.Errorf("failed to write compose override file: %w", err)
	}

	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", nil, fmt.Errorf("failed to close compose override file: %w", err)
	}

	cleanup := func() {
		if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
			if s.logger != nil {
				s.logger.Warn("Failed to remove compose override file", "file", file.Name(), "error", err)
			}
		}
	}

	return file.Name(), cleanup, nil
}

func buildComposePortOverrides(portMappings []types.PortMapping) []string {
	if len(portMappings) == 0 {
		return nil
	}

	ports := make([]string, 0, len(portMappings))
	for _, mapping := range portMappings {
		if mapping.Internal <= 0 {
			continue
		}

		if mapping.External > 0 {
			ports = append(ports, fmt.Sprintf("%d:%d", mapping.External, mapping.Internal))
		} else {
			ports = append(ports, fmt.Sprintf("%d", mapping.Internal))
		}
	}

	if len(ports) == 0 {
		return nil
	}
	return ports
}

func (s *DockerComposeServiceImpl) collectComposeFiles(baseCompose string) []string {
	files := []string{baseCompose}
	overrides := detectExistingComposeOverrides(baseCompose)
	if len(overrides) > 0 {
		files = append(files, overrides...)
	}
	return files
}

func detectExistingComposeOverrides(baseCompose string) []string {
	dir := filepath.Dir(baseCompose)
	name := filepath.Base(baseCompose)
	ext := filepath.Ext(name)
	baseName := strings.TrimSuffix(name, ext)

	candidates := []string{
		filepath.Join(dir, fmt.Sprintf("%s.override%s", baseName, ext)),
	}

	if ext == ".yml" {
		candidates = append(candidates, filepath.Join(dir, baseName+".override.yaml"))
	} else if ext == ".yaml" {
		candidates = append(candidates, filepath.Join(dir, baseName+".override.yml"))
	}

	candidates = append(candidates,
		filepath.Join(dir, "docker-compose.override.yml"),
		filepath.Join(dir, "docker-compose.override.yaml"),
		filepath.Join(dir, "compose.override.yml"),
		filepath.Join(dir, "compose.override.yaml"),
	)

	seen := make(map[string]struct{}, len(candidates))
	overrides := make([]string, 0, len(candidates))

	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if candidate == baseCompose {
			continue
		}
		if _, already := seen[candidate]; already {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			seen[candidate] = struct{}{}
			overrides = append(overrides, candidate)
		}
	}

	return overrides
}

func (s *DockerComposeServiceImpl) buildComposeArgs(projectName string, composeFiles []string) []string {
	args := []string{"compose"}
	if projectName != "" {
		args = append(args, "--project-name", projectName)
	}
	for _, file := range composeFiles {
		if file == "" {
			continue
		}
		args = append(args, "-f", file)
	}
	return args
}

func (s *DockerComposeServiceImpl) validateComposeFiles(ctx context.Context, workDir, projectName string, composeFiles []string, env []string) ([]string, []string) {
	if len(composeFiles) == 0 {
		return composeFiles, nil
	}

	validated := append([]string(nil), composeFiles...)

	for len(validated) > 0 {
		services, err := s.listComposeServices(ctx, workDir, validated, projectName, env)
		if err == nil {
			return validated, services
		}

		if len(validated) == 1 {
			s.logger.Warn("Failed to validate compose configuration", "file", validated[0], "error", err)
			return validated, nil
		}

		skipped := validated[len(validated)-1]
		s.logger.Warn("Skipping compose override due to configuration error", "file", skipped, "error", err)
		validated = validated[:len(validated)-1]
	}

	return composeFiles[:1], nil
}
