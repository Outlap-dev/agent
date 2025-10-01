package services

import (
	"context"
	"fmt"
	"strconv"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/go-connections/nat"
)

// DeploymentServiceImpl handles container deployment operations
type DeploymentServiceImpl struct {
	logger          *logger.Logger
	dockerService   DockerService
	lifecycle       *ContainerLifecycleService
	domainRefresher DomainRefresher
}

type DomainRefresher interface {
	RefreshService(ctx context.Context, serviceUID string) error
}

// NewDeploymentService creates a new deployment service
func NewDeploymentService(logger *logger.Logger, dockerService DockerService) *DeploymentServiceImpl {
	return &DeploymentServiceImpl{
		logger:        logger.With("service", "deployment"),
		dockerService: dockerService,
		lifecycle:     NewContainerLifecycleService(logger, dockerService),
	}
}

func (d *DeploymentServiceImpl) SetDomainRefresher(refresher DomainRefresher) {
	d.domainRefresher = refresher
}

// CleanupContainer stops and removes a container by name
func (d *DeploymentServiceImpl) CleanupContainer(ctx context.Context, containerName string) error {
	d.logger.Info("Cleaning up container", "container_name", containerName)

	// Stop the container
	if err := d.dockerService.StopContainerByName(ctx, containerName); err != nil {
		d.logger.Debug("Failed to stop container or container not running", "container_name", containerName, "error", err)
	}

	// Remove the container
	if err := d.dockerService.RemoveContainerByName(ctx, containerName); err != nil {
		d.logger.Debug("Failed to remove container or container doesn't exist", "container_name", containerName, "error", err)
	}

	return nil
}

// DeployContainer deploys a container with blue-green deployment strategy
func (d *DeploymentServiceImpl) DeployContainer(ctx context.Context, serviceUID, imageName, deploymentUID string, envVars map[string]string, recorder types.DeploymentStepRecorder, stepID string) (*types.DeploymentResult, error) {
	d.logger.Info("Starting blue-green container deployment",
		"service_uid", serviceUID,
		"image_name", imageName,
		"deployment_uid", deploymentUID)

	logStep := func(level, message string) {
		if recorder != nil && stepID != "" {
			recorder.AppendLog(stepID, level, message)
		}
	}

	setMetadata := func(key string, value interface{}) {
		if recorder != nil && stepID != "" {
			recorder.SetMetadata(stepID, key, value)
		}
	}

	plan, err := d.lifecycle.PlanDeployment(ctx, serviceUID, deploymentUID)
	if err != nil {
		logStep("ERROR", fmt.Sprintf("Failed to prepare deployment plan: %v", err))
		return &types.DeploymentResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to prepare deployment plan: %v", err),
		}, nil
	}

	d.logger.Info("deployment plan created", "service_uid", serviceUID, "target_version", plan.Version, "candidate", plan.CandidateName, "final", plan.FinalName)
	logStep("INFO", fmt.Sprintf("Provisioning version v%04d", plan.Version))
	setMetadata("deployment_version", plan.Version)
	setMetadata("target_container", plan.CandidateName)
	if plan.Active != nil {
		setMetadata("current_active_container", plan.Active.Name)
	}

	if cleanupErrs := d.lifecycle.CleanupStaleCandidates(ctx, plan); len(cleanupErrs) > 0 {
		for _, cleanupErr := range cleanupErrs {
			d.logger.Warn("failed to clean up stale candidate", "error", cleanupErr)
			logStep("WARN", fmt.Sprintf("Stale candidate cleanup issue: %v", cleanupErr))
		}
	}

	containerName := plan.CandidateName
	logStep("INFO", fmt.Sprintf("Using candidate container name %s", containerName))

	// Convert environment variables to Docker format
	var envList []string
	for key, value := range envVars {
		envList = append(envList, fmt.Sprintf("%s=%s", key, value))
	}

	// Determine port configuration
	var exposedPorts nat.PortSet
	var portBindings nat.PortMap

	// Try to get port from environment variables
	if portStr, exists := envVars["PORT"]; exists {
		if port, err := strconv.Atoi(portStr); err == nil && port > 0 {
			containerPort := nat.Port(fmt.Sprintf("%d/tcp", port))
			exposedPorts = nat.PortSet{containerPort: struct{}{}}
			portBindings = nat.PortMap{
				containerPort: []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: "0", // Let Docker assign a random port
					},
				},
			}
		}
	}

	// Create container configuration
	labels := make(map[string]string, len(plan.Labels)+3)
	for k, v := range plan.Labels {
		labels[k] = v
	}

	config := &container.Config{
		Image:        imageName,
		Env:          envList,
		ExposedPorts: exposedPorts,
		Labels:       labels,
	}

	// Create host configuration
	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		RestartPolicy: container.RestartPolicy{
			Name: "unless-stopped",
		},
		// Add resource limits if needed
		Resources: container.Resources{
			// Memory:   memoryLimit,
			// CPUQuota: cpuLimit,
		},
	}

	// Create the new container
	logStep("INFO", "Creating new deployment container")
	containerID, err := d.dockerService.CreateContainer(ctx, config, hostConfig, containerName)
	if err != nil {
		logStep("ERROR", fmt.Sprintf("Failed to create container %s: %v", containerName, err))
		return &types.DeploymentResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to create container: %v", err),
		}, nil
	}
	logStep("INFO", fmt.Sprintf("Container created with ID %s", containerID))
	setMetadata("container_id", containerID)

	// Start the container by name
	logStep("INFO", fmt.Sprintf("Starting container %s", containerName))
	if err := d.dockerService.StartContainerByName(ctx, containerName); err != nil {
		logStep("ERROR", fmt.Sprintf("Failed to start container %s: %v", containerName, err))
		return &types.DeploymentResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to start container: %v", err),
		}, nil
	}
	logStep("INFO", fmt.Sprintf("Container %s started", containerName))

	if err := d.lifecycle.PromoteCandidate(ctx, plan); err != nil {
		logStep("ERROR", fmt.Sprintf("Failed to promote container %s: %v", containerName, err))
		return &types.DeploymentResult{
			Success:     false,
			Error:       fmt.Sprintf("Failed to promote container: %v", err),
			ContainerID: containerID,
		}, nil
	}

	if err := d.lifecycle.DecommissionPreviousActive(ctx, plan); err != nil {
		d.logger.Warn("failed to decommission previous active container", "service_uid", serviceUID, "error", err)
		logStep("WARN", fmt.Sprintf("Previous active container cleanup issue: %v", err))
	}

	if d.domainRefresher != nil {
		if err := d.domainRefresher.RefreshService(ctx, serviceUID); err != nil {
			d.logger.Warn("failed to refresh domain routing after deployment", "service_uid", serviceUID, "error", err)
			logStep("WARN", fmt.Sprintf("Domain refresh issue: %v", err))
		}
	}

	finalContainerName := plan.FinalName
	d.logger.Info("Container deployed successfully",
		"service_uid", serviceUID,
		"container_id", containerID,
		"candidate_container", containerName,
		"final_container", finalContainerName,
		"version", plan.Version)
	logStep("INFO", fmt.Sprintf("Deployment finished successfully. Active container: %s (v%04d)", finalContainerName, plan.Version))
	setMetadata("active_container", finalContainerName)
	setMetadata("deployment_version", plan.Version)

	return &types.DeploymentResult{
		Success:           true,
		ImageName:         imageName,
		ContainerID:       containerID,
		ContainerName:     finalContainerName,
		DeploymentVersion: plan.Version,
	}, nil
}

// GetContainerInfo retrieves information about a deployed container
func (d *DeploymentServiceImpl) GetContainerInfo(ctx context.Context, serviceUID string) (*types.ServiceInfo, error) {
	containers, err := d.dockerService.ListContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	for _, container := range containers {
		if container.UID == serviceUID {
			return &container, nil
		}
	}

	return nil, fmt.Errorf("container not found for service UID: %s", serviceUID)
}

// StopDeployment stops a deployed container
func (d *DeploymentServiceImpl) StopDeployment(ctx context.Context, serviceUID string) error {
	d.logger.Info("Stopping deployment", "service_uid", serviceUID)

	if err := d.dockerService.StopContainer(ctx, serviceUID); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	d.logger.Info("Deployment stopped successfully", "service_uid", serviceUID)
	return nil
}

// RemoveDeployment removes a deployed container
func (d *DeploymentServiceImpl) RemoveDeployment(ctx context.Context, serviceUID string) error {
	d.logger.Info("Removing deployment", "service_uid", serviceUID)

	// Stop the container first
	if err := d.StopDeployment(ctx, serviceUID); err != nil {
		d.logger.Warn("Failed to stop container before removal", "service_uid", serviceUID, "error", err)
	}

	// Remove the container
	if err := d.dockerService.RemoveContainer(ctx, serviceUID); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	d.logger.Info("Deployment removed successfully", "service_uid", serviceUID)
	return nil
}

// RestartDeployment restarts a deployed container
func (d *DeploymentServiceImpl) RestartDeployment(ctx context.Context, serviceUID string) error {
	d.logger.Info("Restarting deployment", "service_uid", serviceUID)

	if err := d.dockerService.RestartContainer(ctx, serviceUID); err != nil {
		return fmt.Errorf("failed to restart container: %w", err)
	}

	d.logger.Info("Deployment restarted successfully", "service_uid", serviceUID)
	return nil
}

// ListServiceContainers returns lifecycle details for all managed containers for a service.
func (d *DeploymentServiceImpl) ListServiceContainers(ctx context.Context, serviceUID string) ([]types.ContainerInstance, error) {
	return d.lifecycle.ListServiceContainers(ctx, serviceUID)
}

// GetActiveContainer retrieves the currently active container instance for a service.
func (d *DeploymentServiceImpl) GetActiveContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error) {
	return d.lifecycle.GetActiveContainer(ctx, serviceUID)
}

// GetDeployingContainer retrieves the container currently being deployed, if any.
func (d *DeploymentServiceImpl) GetDeployingContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error) {
	return d.lifecycle.GetDeployingContainer(ctx, serviceUID)
}

func (d *DeploymentServiceImpl) resolveActiveContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error) {
	container, err := d.lifecycle.GetActiveContainer(ctx, serviceUID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active container: %w", err)
	}
	return container, nil
}

func containerIdentifier(instance *types.ContainerInstance) string {
	if instance == nil {
		return ""
	}
	if instance.ID != "" {
		return instance.ID
	}
	return instance.Name
}

// GetDeploymentLogs retrieves logs from a deployed container
func (d *DeploymentServiceImpl) GetDeploymentLogs(ctx context.Context, serviceUID string) ([]string, error) {
	container, err := d.resolveActiveContainer(ctx, serviceUID)
	if err != nil {
		return nil, err
	}

	if container == nil {
		return nil, fmt.Errorf("no active container for service %s", serviceUID)
	}

	containerName := container.Name

	logs, err := d.dockerService.GetContainerLogsByName(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get container logs: %w", err)
	}

	return logs, nil
}

// StreamDeploymentLogs streams logs from a deployed container
func (d *DeploymentServiceImpl) StreamDeploymentLogs(ctx context.Context, serviceUID string) (<-chan string, error) {
	container, err := d.resolveActiveContainer(ctx, serviceUID)
	if err != nil {
		return nil, err
	}

	if container == nil {
		return nil, fmt.Errorf("no active container for service %s", serviceUID)
	}

	containerName := container.Name

	logStream, err := d.dockerService.StreamContainerLogs(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to stream container logs: %w", err)
	}

	return logStream, nil
}

// GetDeploymentStatus gets the status of a deployed container
func (d *DeploymentServiceImpl) GetDeploymentStatus(ctx context.Context, serviceUID string) (types.ServiceStatus, error) {
	container, err := d.resolveActiveContainer(ctx, serviceUID)
	if err != nil {
		return types.ServiceStatusFailed, err
	}

	if container == nil {
		d.logger.Info("No active container found while fetching deployment status", "service_uid", serviceUID)
		return types.ServiceStatusStopped, nil
	}

	identifier := containerIdentifier(container)
	if identifier == "" {
		return types.ServiceStatusFailed, fmt.Errorf("active container resolved without identifier for service %s", serviceUID)
	}

	status, err := d.dockerService.GetContainerStatus(ctx, identifier)
	if err != nil {
		return types.ServiceStatusFailed, fmt.Errorf("failed to get container status: %w", err)
	}

	return status, nil
}

// ValidateDeploymentConfig validates deployment configuration
func (d *DeploymentServiceImpl) ValidateDeploymentConfig(config map[string]interface{}) error {
	// Validate required fields
	if _, exists := config["image_name"]; !exists {
		return fmt.Errorf("image_name is required")
	}

	if _, exists := config["service_uid"]; !exists {
		return fmt.Errorf("service_uid is required")
	}

	// Validate port if specified
	if port, exists := config["port"]; exists {
		if portStr, ok := port.(string); ok {
			if portNum, err := strconv.Atoi(portStr); err != nil || portNum <= 0 || portNum > 65535 {
				return fmt.Errorf("invalid port number: %s", portStr)
			}
		}
	}

	return nil
}

// parseNetworkConfig parses network configuration for container deployment
func (d *DeploymentServiceImpl) parseNetworkConfig(networks []string) *network.NetworkingConfig {
	if len(networks) == 0 {
		return nil
	}

	networkingConfig := &network.NetworkingConfig{
		EndpointsConfig: make(map[string]*network.EndpointSettings),
	}

	for _, networkName := range networks {
		networkingConfig.EndpointsConfig[networkName] = &network.EndpointSettings{}
	}

	return networkingConfig
}
