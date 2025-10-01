package services

import (
	"bytes"
	"context"
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

type composeCommandRunner interface {
	Run(ctx context.Context, name string, args []string, workingDir string, env []string) (string, error)
}

type execComposeCommandRunner struct{}

func (r *execComposeCommandRunner) Run(ctx context.Context, name string, args []string, workingDir string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = workingDir
	if len(env) > 0 {
		cmd.Env = env
	}

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	err := cmd.Run()
	return output.String(), err
}

// DockerComposeServiceImpl coordinates docker compose deployments.
type DockerComposeServiceImpl struct {
	logger *logger.Logger
	runner composeCommandRunner
}

var composeServiceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][-_A-Za-z0-9]*$`)

// NewDockerComposeService constructs a docker compose deployment service.
func NewDockerComposeService(baseLogger *logger.Logger) *DockerComposeServiceImpl {
	return &DockerComposeServiceImpl{
		logger: baseLogger.With("service", "docker_compose"),
		runner: &execComposeCommandRunner{},
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
		return &types.DeploymentResult{Success: false, Error: "deployment request is nil"}, fmt.Errorf("docker compose deployment request is nil")
	}

	if req.SourcePath == "" {
		return &types.DeploymentResult{Success: false, Error: "source path is required"}, fmt.Errorf("source path is required")
	}

	composeFile := strings.TrimSpace(req.ComposeFile)
	if composeFile == "" {
		composeFile = "docker-compose.yml"
	}

	absSource := filepath.Clean(req.SourcePath)
	absCompose := filepath.Join(absSource, filepath.Clean(composeFile))

	rel, err := filepath.Rel(absSource, absCompose)
	if err != nil || strings.HasPrefix(rel, "..") {
		return &types.DeploymentResult{Success: false, Error: "compose file path escapes repository"}, fmt.Errorf("compose file path must reside within repository")
	}

	if _, err := os.Stat(absCompose); err != nil {
		if os.IsNotExist(err) {
			return &types.DeploymentResult{Success: false, Error: fmt.Sprintf("compose file %s not found", composeFile)}, fmt.Errorf("compose file not found: %s", composeFile)
		}
		return &types.DeploymentResult{Success: false, Error: err.Error()}, fmt.Errorf("failed to stat compose file: %w", err)
	}

	projectName := strings.TrimSpace(req.ProjectName)
	if projectName == "" {
		projectName = fmt.Sprintf("pulseup-%s", req.ServiceUID)
	}

	env := append(os.Environ(), formatEnv(req.Environment)...)

	composeFiles := s.collectComposeFiles(absCompose)
	validatedComposeFiles, availableServices := s.validateComposeFiles(ctx, absSource, projectName, composeFiles, env)

	labelsViaOverride := false
	var (
		overridePath    string
		overrideCleanup func()
	)

	targetServices := s.resolveLabelTargets(req, availableServices)
	if len(targetServices) > 0 {
		var overrideErr error
		overridePath, overrideCleanup, overrideErr = s.createLabelOverrideFile(absSource, targetServices, req.ServiceUID, req.DeploymentUID)
		if overrideErr != nil {
			s.logger.Warn("Failed to prepare compose label override", "error", overrideErr)
		} else if overridePath != "" {
			labelsViaOverride = true
			defer func() {
				if overrideCleanup != nil {
					overrideCleanup()
				}
			}()
		}
	}

	actualComposeFiles := append([]string{}, validatedComposeFiles...)
	if overridePath != "" {
		actualComposeFiles = append(actualComposeFiles, overridePath)
	}

	downArgs := s.buildComposeArgs(projectName, actualComposeFiles)
	downArgs = append(downArgs, "down", "--remove-orphans")
	if output, err := s.runner.Run(ctx, "docker", downArgs, absSource, env); err != nil {
		s.logger.Warn("docker compose down failed", "error", err, "output", output)
		return &types.DeploymentResult{Success: false, Error: fmt.Sprintf("docker compose down failed: %v", err)}, err
	}

	upArgs := s.buildComposeArgs(projectName, actualComposeFiles)
	upArgs = append(upArgs, "up", "-d", "--build")
	if strings.EqualFold(req.ServiceMode, "selected") && len(req.SelectedServices) > 0 {
		for _, service := range req.SelectedServices {
			trimmed := strings.TrimSpace(service)
			if trimmed != "" {
				upArgs = append(upArgs, trimmed)
			}
		}
	}

	output, err := s.runner.Run(ctx, "docker", upArgs, absSource, env)
	if err != nil {
		s.logger.Error("docker compose up failed", "error", err, "output", output)
		return &types.DeploymentResult{Success: false, Error: fmt.Sprintf("docker compose up failed: %v", err)}, err
	}

	// If we couldn't inject labels via override, fall back to direct labeling
	if !labelsViaOverride {
		if err := s.labelComposeContainers(ctx, projectName, req.ServiceUID, req.DeploymentUID); err != nil {
			s.logger.Warn("Failed to add PulseUp labels to compose containers", "error", err)
			// Don't fail the deployment if labeling fails, but log it
		}
	}

	s.logger.Info("docker compose deployment completed", "project", projectName, "compose_file", composeFile)

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

	output, err := s.runner.Run(ctx, "docker", listArgs, ".", nil)
	if err != nil {
		return fmt.Errorf("failed to list compose containers: %w", err)
	}

	containerIDs := strings.Fields(strings.TrimSpace(output))
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

		_, err := s.runner.Run(ctx, "docker", labelArgs, ".", nil)
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

func (s *DockerComposeServiceImpl) resolveLabelTargets(req *types.DockerComposeDeploymentRequest, availableServices []string) []string {
	if strings.EqualFold(req.ServiceMode, "selected") && len(req.SelectedServices) > 0 {
		return normalizeServiceNames(req.SelectedServices)
	}

	return normalizeServiceNames(availableServices)
}

func (s *DockerComposeServiceImpl) listComposeServices(ctx context.Context, workDir string, composeFiles []string, projectName string, env []string) ([]string, error) {
	args := s.buildComposeArgs(projectName, composeFiles)
	args = append(args, "config", "--services")

	output, err := s.runner.Run(ctx, "docker", args, workDir, env)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate compose services: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
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

func (s *DockerComposeServiceImpl) createLabelOverrideFile(workDir string, services []string, serviceUID, deploymentUID string) (string, func(), error) {
	normalized := normalizeServiceNames(services)
	if len(normalized) == 0 {
		return "", nil, nil
	}

	type serviceLabels struct {
		Labels map[string]string `yaml:"labels"`
	}

	servicesMap := make(map[string]serviceLabels, len(normalized))
	for _, svc := range normalized {
		servicesMap[svc] = serviceLabels{Labels: map[string]string{
			"pulseup.managed":        "true",
			"pulseup.service_uid":    serviceUID,
			"pulseup.deployment_uid": deploymentUID,
		}}
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
