package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"

	"pulseup-agent-go/pkg/logger"
	pulseuptypes "pulseup-agent-go/pkg/types"
)

// DockerStats represents the structure returned by Docker stats API
type DockerStats struct {
	Read        string                        `json:"read"`
	PreRead     string                        `json:"preread"`
	CPUStats    DockerCPUStats                `json:"cpu_stats"`
	PreCPUStats DockerCPUStats                `json:"precpu_stats"`
	MemoryStats DockerMemoryStats             `json:"memory_stats"`
	BlkioStats  DockerBlkioStats              `json:"blkio_stats"`
	Networks    map[string]DockerNetworkStats `json:"networks"`
}

type DockerCPUStats struct {
	CPUUsage       DockerCPUUsage       `json:"cpu_usage"`
	SystemUsage    uint64               `json:"system_cpu_usage"`
	OnlineCPUs     uint32               `json:"online_cpus"`
	ThrottlingData DockerThrottlingData `json:"throttling_data"`
}

type DockerCPUUsage struct {
	TotalUsage        uint64   `json:"total_usage"`
	PercpuUsage       []uint64 `json:"percpu_usage"`
	UsageInKernelmode uint64   `json:"usage_in_kernelmode"`
	UsageInUsermode   uint64   `json:"usage_in_usermode"`
}

type DockerThrottlingData struct {
	Periods          uint64 `json:"periods"`
	ThrottledPeriods uint64 `json:"throttled_periods"`
	ThrottledTime    uint64 `json:"throttled_time"`
}

type DockerMemoryStats struct {
	Usage uint64            `json:"usage"`
	Limit uint64            `json:"limit"`
	Stats map[string]uint64 `json:"stats"`
}

type DockerBlkioStats struct {
	IoServiceBytesRecursive []DockerBlkioStatEntry `json:"io_service_bytes_recursive"`
	IoServicedRecursive     []DockerBlkioStatEntry `json:"io_serviced_recursive"`
}

type DockerBlkioStatEntry struct {
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

type DockerNetworkStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	TxErrors  uint64 `json:"tx_errors"`
}

// DockerServiceImpl implements the DockerService interface
type DockerServiceImpl struct {
	logger *logger.Logger
	client *client.Client
}

// NewDockerService creates a new Docker service
func NewDockerService(logger *logger.Logger) *DockerServiceImpl {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logger.Error("Failed to create Docker client", "error", err)
		// Return service with nil client - will handle gracefully
		return &DockerServiceImpl{
			logger: logger.With("service", "docker"),
			client: nil,
		}
	}

	return &DockerServiceImpl{
		logger: logger.With("service", "docker"),
		client: dockerClient,
	}
}

// ensureClient checks if Docker client is available
func (d *DockerServiceImpl) ensureClient() error {
	if d.client == nil {
		return fmt.Errorf("docker client not available")
	}
	return nil
}

// ListContainers returns a list of all containers
func (d *DockerServiceImpl) ListContainers(ctx context.Context) ([]pulseuptypes.ServiceInfo, error) {
	if err := d.ensureClient(); err != nil {
		return nil, err
	}

	d.logger.Debug("Listing containers")

	containers, err := d.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var services []pulseuptypes.ServiceInfo
	for _, cont := range containers {
		// Extract service info from container
		serviceName := cont.Names[0]
		if strings.HasPrefix(serviceName, "/") {
			serviceName = serviceName[1:] // Remove leading slash
		}

		status := pulseuptypes.ServiceStatusStopped
		if cont.State == "running" {
			status = pulseuptypes.ServiceStatusRunning
		} else if cont.State == "exited" {
			status = pulseuptypes.ServiceStatusStopped
		} else if cont.State == "restarting" {
			status = pulseuptypes.ServiceStatusRestarting
		}

		// Extract port if available
		var port int
		if len(cont.Ports) > 0 && cont.Ports[0].PublicPort > 0 {
			port = int(cont.Ports[0].PublicPort)
		}

		services = append(services, pulseuptypes.ServiceInfo{
			UID:       cont.ID[:12], // Use short container ID
			Name:      serviceName,
			Status:    status,
			Port:      port,
			CreatedAt: time.Unix(cont.Created, 0),
			UpdatedAt: time.Now(),
		})
	}

	d.logger.Debug("Listed containers", "count", len(services))
	return services, nil
}

// StartContainer starts a container
func (d *DockerServiceImpl) StartContainer(ctx context.Context, serviceUID string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Info("Starting container", "service_uid", serviceUID)

	err := d.client.ContainerStart(ctx, serviceUID, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", serviceUID, err)
	}

	d.logger.Info("Container started successfully", "service_uid", serviceUID)
	return nil
}

// StopContainer stops a container
func (d *DockerServiceImpl) StopContainer(ctx context.Context, serviceUID string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Info("Stopping container", "service_uid", serviceUID)

	timeout := 30 // 30 seconds timeout
	err := d.client.ContainerStop(ctx, serviceUID, container.StopOptions{
		Timeout: &timeout,
	})
	if err != nil {
		if errdefs.IsNotFound(err) {
			d.logger.Info("Container not found while stopping; continuing", "service_uid", serviceUID)
			return nil
		}
		return fmt.Errorf("failed to stop container %s: %w", serviceUID, err)
	}

	d.logger.Info("Container stopped successfully", "service_uid", serviceUID)
	return nil
}

// RestartContainer restarts a container
func (d *DockerServiceImpl) RestartContainer(ctx context.Context, serviceUID string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Info("Restarting container", "service_uid", serviceUID)

	timeout := 30 // 30 seconds timeout
	err := d.client.ContainerRestart(ctx, serviceUID, container.StopOptions{
		Timeout: &timeout,
	})
	if err != nil {
		return fmt.Errorf("failed to restart container %s: %w", serviceUID, err)
	}

	d.logger.Info("Container restarted successfully", "service_uid", serviceUID)
	return nil
}

// TagImage applies an additional tag to an existing Docker image
func (d *DockerServiceImpl) TagImage(ctx context.Context, source, target string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Debug("Tagging image", "source", source, "target", target)
	if err := d.client.ImageTag(ctx, source, target); err != nil {
		return fmt.Errorf("failed to tag image %s as %s: %w", source, target, err)
	}

	return nil
}

// GetContainerLogs returns container logs
func (d *DockerServiceImpl) GetContainerLogs(ctx context.Context, serviceUID string) ([]string, error) {
	if err := d.ensureClient(); err != nil {
		return nil, err
	}

	d.logger.Debug("Getting container logs", "service_uid", serviceUID)

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       "100", // Last 100 lines
	}

	// Try original serviceUID first
	reader, err := d.client.ContainerLogs(ctx, serviceUID, options)
	if err != nil {
		// If container not found, try with -blue suffix
		d.logger.Debug("Container not found, trying with -blue suffix", "service_uid", serviceUID)
		blueServiceUID := serviceUID + "-blue"
		reader, err = d.client.ContainerLogs(ctx, blueServiceUID, options)
		if err != nil {
			return nil, fmt.Errorf("failed to get logs for container %s or %s: %w", serviceUID, blueServiceUID, err)
		}
		d.logger.Debug("Found container with -blue suffix", "service_uid", blueServiceUID)
	}
	defer reader.Close()

	// Read logs
	logData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read logs: %w", err)
	}

	// Split into lines and clean up
	lines := strings.Split(string(logData), "\n")
	var cleanLines []string
	for _, line := range lines {
		// Docker logs include header bytes, clean them up
		if len(line) > 8 {
			cleanLine := line[8:] // Skip Docker log header
			if strings.TrimSpace(cleanLine) != "" {
				cleanLines = append(cleanLines, cleanLine)
			}
		}
	}

	return cleanLines, nil
}

// StreamContainerLogs streams container logs
func (d *DockerServiceImpl) StreamContainerLogs(ctx context.Context, serviceUID string) (<-chan string, error) {
	if err := d.ensureClient(); err != nil {
		return nil, err
	}

	d.logger.Debug("Streaming container logs", "service_uid", serviceUID)

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "10", // Start with last 10 lines
	}

	reader, err := d.client.ContainerLogs(ctx, serviceUID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to stream logs for container %s: %w", serviceUID, err)
	}

	logChan := make(chan string, 100)

	go func() {
		defer close(logChan)
		defer reader.Close()

		buf := make([]byte, 1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := reader.Read(buf)
				if err != nil {
					if err != io.EOF {
						d.logger.Error("Error reading log stream", "error", err)
					}
					return
				}

				if n > 8 { // Skip Docker log header
					logLine := string(buf[8:n])
					logLine = strings.TrimSpace(logLine)
					if logLine != "" {
						select {
						case logChan <- logLine:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()

	return logChan, nil
}
func (d *DockerServiceImpl) GetContainerStatus(ctx context.Context, serviceUID string) (pulseuptypes.ServiceStatus, error) {
	if err := d.ensureClient(); err != nil {
		return pulseuptypes.ServiceStatusStopped, err
	}

	d.logger.Debug("Getting container status", "service_uid", serviceUID)

	containerJSON, err := d.client.ContainerInspect(ctx, serviceUID)
	if err != nil {
		return pulseuptypes.ServiceStatusStopped, fmt.Errorf("failed to inspect container %s: %w", serviceUID, err)
	}

	switch containerJSON.State.Status {
	case "running":
		return pulseuptypes.ServiceStatusRunning, nil
	case "exited":
		return pulseuptypes.ServiceStatusStopped, nil
	case "restarting":
		return pulseuptypes.ServiceStatusRestarting, nil
	case "paused":
		return pulseuptypes.ServiceStatusStopped, nil
	default:
		return pulseuptypes.ServiceStatusStopped, nil
	}
}

// RemoveContainer removes a container
func (d *DockerServiceImpl) RemoveContainer(ctx context.Context, serviceUID string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Info("Removing container", "service_uid", serviceUID)

	err := d.client.ContainerRemove(ctx, serviceUID, container.RemoveOptions{
		Force: true, // Force remove even if running
	})
	if err != nil {
		if errdefs.IsNotFound(err) {
			d.logger.Info("Container not found while removing; continuing", "service_uid", serviceUID)
			return nil
		}
		return fmt.Errorf("failed to remove container %s: %w", serviceUID, err)
	}

	d.logger.Info("Container removed successfully", "service_uid", serviceUID)
	return nil
}

// ExecContainer executes a command inside a container
func (d *DockerServiceImpl) ExecContainer(ctx context.Context, containerID string, cmd []string) (*pulseuptypes.ExecResult, error) {
	if err := d.ensureClient(); err != nil {
		return nil, err
	}

	d.logger.Debug("Executing command in container", "container_id", containerID[:12], "command", cmd)

	// Create exec instance
	execConfig := container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          cmd,
	}

	execID, err := d.client.ContainerExecCreate(ctx, containerID, execConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create exec instance: %w", err)
	}

	// Start the exec instance
	execStartOptions := container.ExecStartOptions{
		Detach: false,
	}

	hijackedResp, err := d.client.ContainerExecAttach(ctx, execID.ID, execStartOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to attach to exec instance: %w", err)
	}
	defer hijackedResp.Close()

	// Read the output
	output, err := io.ReadAll(hijackedResp.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read exec output: %w", err)
	}

	// Get the exit code
	inspectResp, err := d.client.ContainerExecInspect(ctx, execID.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect exec instance: %w", err)
	}

	result := &pulseuptypes.ExecResult{
		ExitCode: inspectResp.ExitCode,
		Output:   string(output),
	}

	if inspectResp.ExitCode != 0 {
		result.Error = fmt.Sprintf("command exited with code %d", inspectResp.ExitCode)
	}

	d.logger.Debug("Command executed successfully", "container_id", containerID[:12], "exit_code", inspectResp.ExitCode)

	return result, nil
}

// BuildImage builds a Docker image
func (d *DockerServiceImpl) BuildImage(ctx context.Context, buildContext string, tags []string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Info("Building image", "context", buildContext, "tags", tags)

	// Create build context (this would need to be implemented based on your needs)
	// For now, we'll return a placeholder
	return fmt.Errorf("build image not yet implemented - use BuildApplication instead")
}

// PullImage pulls a Docker image
func (d *DockerServiceImpl) PullImage(ctx context.Context, imageName string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Info("Pulling image", "image", imageName)

	reader, err := d.client.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", imageName, err)
	}
	defer reader.Close()

	// Read the pull output (optional, for logging)
	_, err = io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read pull output: %w", err)
	}

	d.logger.Info("Image pulled successfully", "image", imageName)
	return nil
}

// CreateVolume creates a new Docker volume
func (d *DockerServiceImpl) CreateVolume(ctx context.Context, volumeName string, labels map[string]string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Debug("Creating Docker volume", "volume", volumeName)

	_, err := d.client.VolumeCreate(ctx, volume.CreateOptions{
		Name:   volumeName,
		Labels: labels,
	})
	if err != nil {
		return fmt.Errorf("failed to create volume %s: %w", volumeName, err)
	}

	d.logger.Debug("Volume created successfully", "volume", volumeName)
	return nil
}

// VolumeExists checks if a Docker volume exists
func (d *DockerServiceImpl) VolumeExists(ctx context.Context, volumeName string) (bool, error) {
	if err := d.ensureClient(); err != nil {
		return false, err
	}

	d.logger.Debug("Checking if volume exists", "volume", volumeName)

	volumes, err := d.client.VolumeList(ctx, volume.ListOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to list volumes: %w", err)
	}

	for _, vol := range volumes.Volumes {
		if vol.Name == volumeName {
			return true, nil
		}
	}

	return false, nil
}

// CreateContainer creates a new container
func (d *DockerServiceImpl) CreateContainer(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, containerName string) (string, error) {
	if err := d.ensureClient(); err != nil {
		return "", err
	}

	d.logger.Info("Creating container", "name", containerName, "image", config.Image)

	resp, err := d.client.ContainerCreate(ctx, config, hostConfig, nil, nil, containerName)
	if err != nil {
		return "", fmt.Errorf("failed to create container %s: %w", containerName, err)
	}

	d.logger.Info("Container created successfully", "name", containerName, "id", resp.ID[:12])
	return resp.ID, nil
}

// ContainerExists checks if a container with the given name exists
func (d *DockerServiceImpl) ContainerExists(ctx context.Context, containerName string) (bool, error) {
	if err := d.ensureClient(); err != nil {
		return false, err
	}

	containers, err := d.client.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return false, fmt.Errorf("failed to list containers: %w", err)
	}

	for _, c := range containers {
		for _, name := range c.Names {
			// Container names in Docker start with "/"
			if name == "/"+containerName || name == containerName {
				return true, nil
			}
		}
	}

	return false, nil
}

// FindContainersByLabel returns container names matching the provided label key/value pair.
func (d *DockerServiceImpl) FindContainersByLabel(ctx context.Context, labelKey, labelValue string) ([]string, error) {
	if err := d.ensureClient(); err != nil {
		return nil, err
	}

	labelFilter := fmt.Sprintf("%s=%s", labelKey, labelValue)
	filtersArgs := filters.NewArgs(filters.Arg("label", labelFilter))

	containers, err := d.client.ContainerList(ctx, container.ListOptions{All: true, Filters: filtersArgs})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers by label %s: %w", labelFilter, err)
	}

	results := make([]string, 0, len(containers))
	for _, c := range containers {
		if len(c.Names) > 0 {
			name := strings.TrimPrefix(c.Names[0], "/")
			results = append(results, name)
		} else {
			results = append(results, c.ID[:12])
		}
	}

	return results, nil
}

// RenameContainer renames a container from oldName to newName
func (d *DockerServiceImpl) RenameContainer(ctx context.Context, oldName, newName string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Info("Renaming container", "from", oldName, "to", newName)

	err := d.client.ContainerRename(ctx, oldName, newName)
	if err != nil {
		return fmt.Errorf("failed to rename container from %s to %s: %w", oldName, newName, err)
	}

	d.logger.Info("Container renamed successfully", "from", oldName, "to", newName)
	return nil
}

// StopContainerByName stops a container by its name
func (d *DockerServiceImpl) StopContainerByName(ctx context.Context, containerName string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Debug("Stopping container by name", "name", containerName)

	timeout := 10 // 10 seconds timeout
	options := container.StopOptions{Timeout: &timeout}

	err := d.client.ContainerStop(ctx, containerName, options)
	if err != nil {
		return fmt.Errorf("failed to stop container %s: %w", containerName, err)
	}

	d.logger.Debug("Container stopped successfully", "name", containerName)
	return nil
}

// RemoveContainerByName removes a container by its name
func (d *DockerServiceImpl) RemoveContainerByName(ctx context.Context, containerName string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Debug("Removing container by name", "name", containerName)

	options := container.RemoveOptions{
		Force: true, // Force removal even if running
	}

	err := d.client.ContainerRemove(ctx, containerName, options)
	if err != nil {
		return fmt.Errorf("failed to remove container %s: %w", containerName, err)
	}

	d.logger.Debug("Container removed successfully", "name", containerName)
	return nil
}

// StartContainerByName starts a container by its name
func (d *DockerServiceImpl) StartContainerByName(ctx context.Context, containerName string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	d.logger.Debug("Starting container by name", "name", containerName)

	err := d.client.ContainerStart(ctx, containerName, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("failed to start container %s: %w", containerName, err)
	}

	d.logger.Debug("Container started successfully", "name", containerName)
	return nil
}

// GetContainerLogsByName returns container logs by container name
func (d *DockerServiceImpl) GetContainerLogsByName(ctx context.Context, containerName string) ([]string, error) {
	if err := d.ensureClient(); err != nil {
		return nil, err
	}

	d.logger.Debug("Getting container logs by name", "container_name", containerName)

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       "100", // Last 100 lines
	}

	// Try original containerName first
	reader, err := d.client.ContainerLogs(ctx, containerName, options)
	if err != nil {
		// If container not found, try with -blue suffix
		d.logger.Debug("Container not found, trying with -blue suffix", "container_name", containerName)
		blueContainerName := containerName + "-blue"
		reader, err = d.client.ContainerLogs(ctx, blueContainerName, options)
		if err != nil {
			return nil, fmt.Errorf("failed to get logs for container %s or %s: %w", containerName, blueContainerName, err)
		}
		d.logger.Debug("Found container with -blue suffix", "container_name", blueContainerName)
	}
	defer reader.Close()

	// Read logs
	logData, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read logs: %w", err)
	}

	// Split into lines and clean up
	lines := strings.Split(string(logData), "\n")
	var cleanLines []string
	for _, line := range lines {
		// Docker logs include header bytes, clean them up
		if len(line) > 8 {
			cleanLine := line[8:] // Skip Docker log header
			if strings.TrimSpace(cleanLine) != "" {
				cleanLines = append(cleanLines, cleanLine)
			}
		}
	}

	return cleanLines, nil
}

// CleanupOldDeploymentImages removes old Docker images for a service
func (d *DockerServiceImpl) CleanupOldDeploymentImages(ctx context.Context, serviceUID string) error {
	if err := d.ensureClient(); err != nil {
		return err
	}

	// List all images with the service UID label or tag
	images, err := d.client.ImageList(ctx, image.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list images: %w", err)
	}

	// Look for images that belong to this service
	var imagesToRemove []string
	for _, img := range images {
		// Check image tags
		for _, tag := range img.RepoTags {
			if strings.Contains(tag, serviceUID) {
				imagesToRemove = append(imagesToRemove, img.ID)
				break
			}
		}
	}

	// Remove the identified images
	for _, imageID := range imagesToRemove {
		if _, err := d.client.ImageRemove(ctx, imageID, image.RemoveOptions{
			Force:         true,
			PruneChildren: true,
		}); err != nil {
			d.logger.Warn("Failed to remove image", "image_id", imageID, "error", err)
			// Continue with other images even if one fails
		} else {
			d.logger.Info("Removed image", "image_id", imageID)
		}
	}

	return nil
}

// GetContainerStats gets live statistics for a specific container using Docker stats API
func (d *DockerServiceImpl) GetContainerStats(ctx context.Context, containerID string) (*pulseuptypes.ContainerMetrics, error) {
	if err := d.ensureClient(); err != nil {
		return nil, err
	}

	d.logger.Debug("Getting container stats", "container_id", containerID)

	// Get container inspect info for basic details
	inspect, err := d.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %s: %w", containerID, err)
	}

	// Get container stats from Docker API
	statsResponse, err := d.client.ContainerStats(ctx, containerID, false) // false = one-shot stats
	if err != nil {
		return nil, fmt.Errorf("failed to get container stats for %s: %w", containerID, err)
	}
	defer statsResponse.Body.Close()

	// Parse stats response
	var stats DockerStats
	if err := json.NewDecoder(statsResponse.Body).Decode(&stats); err != nil {
		return nil, fmt.Errorf("failed to decode container stats: %w", err)
	}

	// Calculate metrics from stats
	cpuMetrics := d.calculateCPUMetrics(&stats)
	memoryMetrics := d.calculateMemoryMetrics(&stats)
	networkMetrics := d.calculateNetworkMetrics(&stats)
	diskMetrics := d.calculateDiskMetrics(&stats)

	// Get uptime
	startTime, _ := time.Parse(time.RFC3339Nano, inspect.State.StartedAt)
	uptime := time.Since(startTime)

	// Determine health status
	healthStatus := d.determineHealthStatus(&inspect)

	// Clean container name
	cleanName := inspect.Name
	if strings.HasPrefix(cleanName, "/") {
		cleanName = cleanName[1:]
	}

	// Create container metrics
	containerMetrics := &pulseuptypes.ContainerMetrics{
		ContainerID:   containerID,
		ContainerName: cleanName,
		Status:        pulseuptypes.FromDockerStatus(inspect.State.Status),
		CPU:           cpuMetrics,
		Memory:        memoryMetrics,
		Network:       networkMetrics,
		Disk:          diskMetrics,
		Health:        healthStatus,
		Uptime:        uptime,
		Timestamp:     time.Now(),
	}

	d.logger.Debug("Successfully retrieved container stats",
		"container_id", containerID,
		"cpu_usage", cpuMetrics.Usage,
		"memory_usage", memoryMetrics.Percent,
		"network_rx", networkMetrics.RxBytes,
		"network_tx", networkMetrics.TxBytes)

	return containerMetrics, nil
}

// InspectContainer retrieves detailed information about a container.
func (d *DockerServiceImpl) InspectContainer(ctx context.Context, containerID string) (dockertypes.ContainerJSON, error) {
	if err := d.ensureClient(); err != nil {
		return dockertypes.ContainerJSON{}, err
	}

	inspect, err := d.client.ContainerInspect(ctx, containerID)
	if err != nil {
		return dockertypes.ContainerJSON{}, err
	}

	return inspect, nil
}

// calculateCPUMetrics calculates CPU metrics from Docker stats
func (d *DockerServiceImpl) calculateCPUMetrics(stats *DockerStats) pulseuptypes.ContainerCPUMetrics {
	var cpuPercent float64
	var throttled uint64
	var limit float64

	// Calculate CPU percentage
	if stats.PreCPUStats.CPUUsage.TotalUsage != 0 {
		// CPU delta
		cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage) - float64(stats.PreCPUStats.CPUUsage.TotalUsage)
		systemDelta := float64(stats.CPUStats.SystemUsage) - float64(stats.PreCPUStats.SystemUsage)

		if systemDelta > 0.0 && cpuDelta > 0.0 {
			// Number of CPUs available to the container
			onlineCPUs := float64(stats.CPUStats.OnlineCPUs)
			if onlineCPUs == 0 {
				onlineCPUs = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
			}
			if onlineCPUs == 0 {
				onlineCPUs = 1.0
			}

			cpuPercent = (cpuDelta / systemDelta) * onlineCPUs * 100.0
		}
	}

	// Get throttling info
	if stats.CPUStats.ThrottlingData.ThrottledPeriods != 0 {
		throttled = stats.CPUStats.ThrottlingData.ThrottledPeriods
	}

	// Calculate CPU limit (in cores)
	if stats.CPUStats.CPUUsage.TotalUsage != 0 {
		// If there's a CPU limit set, use it
		if stats.CPUStats.ThrottlingData.Periods != 0 {
			limit = float64(stats.CPUStats.ThrottlingData.Periods) / 100000.0 // Convert from nanoseconds
		} else {
			// Default to number of online CPUs
			limit = float64(stats.CPUStats.OnlineCPUs)
			if limit == 0 {
				limit = float64(len(stats.CPUStats.CPUUsage.PercpuUsage))
			}
		}
	}

	return pulseuptypes.ContainerCPUMetrics{
		Usage:     cpuPercent,
		Throttled: throttled,
		Limit:     limit,
	}
}

// calculateMemoryMetrics calculates memory metrics from Docker stats
func (d *DockerServiceImpl) calculateMemoryMetrics(stats *DockerStats) pulseuptypes.ContainerMemoryMetrics {
	usage := stats.MemoryStats.Usage
	limit := stats.MemoryStats.Limit

	// Calculate cache and RSS
	cache := stats.MemoryStats.Stats["cache"]
	rss := stats.MemoryStats.Stats["rss"]

	// Calculate percentage
	var percent float64
	if limit > 0 {
		percent = (float64(usage) / float64(limit)) * 100.0
	}

	return pulseuptypes.ContainerMemoryMetrics{
		Usage:   usage,
		Limit:   limit,
		Percent: percent,
		Cache:   cache,
		RSS:     rss,
	}
}

// calculateNetworkMetrics calculates network metrics from Docker stats
func (d *DockerServiceImpl) calculateNetworkMetrics(stats *DockerStats) pulseuptypes.ContainerNetworkMetrics {
	var rxBytes, txBytes, rxPackets, txPackets, rxErrors, txErrors uint64

	// Sum up all network interfaces
	for _, network := range stats.Networks {
		rxBytes += network.RxBytes
		txBytes += network.TxBytes
		rxPackets += network.RxPackets
		txPackets += network.TxPackets
		rxErrors += network.RxErrors
		txErrors += network.TxErrors
	}

	return pulseuptypes.ContainerNetworkMetrics{
		RxBytes:   rxBytes,
		TxBytes:   txBytes,
		RxPackets: rxPackets,
		TxPackets: txPackets,
		RxErrors:  rxErrors,
		TxErrors:  txErrors,
	}
}

// calculateDiskMetrics calculates disk I/O metrics from Docker stats
func (d *DockerServiceImpl) calculateDiskMetrics(stats *DockerStats) pulseuptypes.ContainerDiskMetrics {
	var readBytes, writeBytes, readOps, writeOps uint64

	// Sum up all block devices
	for _, ioStat := range stats.BlkioStats.IoServiceBytesRecursive {
		if ioStat.Op == "Read" {
			readBytes += ioStat.Value
		} else if ioStat.Op == "Write" {
			writeBytes += ioStat.Value
		}
	}

	for _, ioStat := range stats.BlkioStats.IoServicedRecursive {
		if ioStat.Op == "Read" {
			readOps += ioStat.Value
		} else if ioStat.Op == "Write" {
			writeOps += ioStat.Value
		}
	}

	return pulseuptypes.ContainerDiskMetrics{
		ReadBytes:  readBytes,
		WriteBytes: writeBytes,
		ReadOps:    readOps,
		WriteOps:   writeOps,
	}
}

// determineHealthStatus determines the health status of a container
func (d *DockerServiceImpl) determineHealthStatus(inspect *dockertypes.ContainerJSON) pulseuptypes.HealthStatus {
	if inspect.State.Health == nil {
		return pulseuptypes.HealthStatusNone
	}

	switch inspect.State.Health.Status {
	case "healthy":
		return pulseuptypes.HealthStatusHealthy
	case "unhealthy":
		return pulseuptypes.HealthStatusUnhealthy
	case "starting":
		return pulseuptypes.HealthStatusStarting
	default:
		return pulseuptypes.HealthStatusNone
	}
}
