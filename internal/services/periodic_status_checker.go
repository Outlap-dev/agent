package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"

	"outlap-agent-go/pkg/logger"
	outlaptypes "outlap-agent-go/pkg/types"
)

// PeriodicStatusChecker periodically checks and reports the status of all outlap-managed containers.
type PeriodicStatusChecker struct {
	logger        *logger.Logger
	dockerService DockerService
	statusService StatusService

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
}

// NewPeriodicStatusChecker creates a new periodic status checker.
func NewPeriodicStatusChecker(baseLogger *logger.Logger, dockerService DockerService, statusService StatusService) *PeriodicStatusChecker {
	return &PeriodicStatusChecker{
		logger:        baseLogger.With("service", "periodic_status_checker"),
		dockerService: dockerService,
		statusService: statusService,
	}
}

// Start begins the periodic status checking loop.
func (p *PeriodicStatusChecker) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("periodic status checker already running")
	}

	if p.dockerService == nil {
		return fmt.Errorf("docker service not available")
	}

	if p.statusService == nil {
		return fmt.Errorf("status service not available")
	}

	runCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.running = true

	go p.run(runCtx)

	return nil
}

// Stop terminates the periodic status checking loop.
func (p *PeriodicStatusChecker) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	if p.cancel != nil {
		p.cancel()
	}

	p.running = false
	p.cancel = nil
	return nil
}

func (p *PeriodicStatusChecker) run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	p.logger.Info("Starting periodic status checker", "interval", "30s")

	// Do an initial check immediately
	p.checkAndReportStatuses(ctx)

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Periodic status checker stopped")
			return
		case <-ticker.C:
			p.checkAndReportStatuses(ctx)
		}
	}
}

func (p *PeriodicStatusChecker) checkAndReportStatuses(ctx context.Context) {
	// Find all outlap-managed containers
	containerNames, err := p.dockerService.FindContainersByLabel(ctx, "outlap.managed", "true")
	if err != nil {
		p.logger.Error("Failed to find outlap-managed containers", "error", err)
		return
	}

	if len(containerNames) == 0 {
		p.logger.Debug("No outlap-managed containers found")
		return
	}

	p.logger.Debug("Checking status of outlap-managed containers", "count", len(containerNames))

	// Check status for each container
	for _, containerName := range containerNames {
		p.checkContainerStatus(ctx, containerName)
	}
}

func (p *PeriodicStatusChecker) checkContainerStatus(ctx context.Context, containerName string) {
	// Get container details to extract service UID
	containerJSON, err := p.dockerService.InspectContainer(ctx, containerName)
	if err != nil {
		p.logger.Warn("Failed to inspect container", "container", containerName, "error", err)
		return
	}

	// Extract service UID from labels
	serviceUID, ok := containerJSON.Config.Labels["outlap.service_uid"]
	if !ok || serviceUID == "" {
		p.logger.Debug("Container missing service UID label", "container", containerName)
		return
	}

	// Determine status from container state
	status := p.determineStatus(containerJSON.State)
	errorMessage := ""

	// If container failed with non-zero exit code, include the exit code in the error message
	if status == outlaptypes.ServiceStatusFailed && containerJSON.State.ExitCode != 0 {
		errorMessage = fmt.Sprintf("container exited with code %d", containerJSON.State.ExitCode)
	}

	// Report status update
	if err := p.statusService.UpdateServiceStatus(ctx, serviceUID, status, errorMessage); err != nil {
		p.logger.Error("Failed to update service status",
			"service_uid", serviceUID,
			"status", status,
			"error", err,
		)
	} else {
		p.logger.Debug("Reported service status",
			"service_uid", serviceUID,
			"container", containerName,
			"status", status,
		)
	}
}

func (p *PeriodicStatusChecker) determineStatus(state *dockertypes.ContainerState) outlaptypes.ServiceStatus {
	if state == nil {
		return outlaptypes.ServiceStatusStopped
	}

	// Map Docker container state to service status
	switch state.Status {
	case "running":
		// Check health status if available
		if state.Health != nil {
			switch state.Health.Status {
			case "healthy":
				return outlaptypes.ServiceStatusRunning
			case "unhealthy":
				return outlaptypes.ServiceStatusFailed
			case "starting":
				return outlaptypes.ServiceStatusRunning
			}
		}
		return outlaptypes.ServiceStatusRunning
	case "restarting":
		return outlaptypes.ServiceStatusRestarting
	case "paused":
		return outlaptypes.ServiceStatusStopped
	case "exited":
		// If exit code is non-zero, it's a failure
		if state.ExitCode != 0 {
			return outlaptypes.ServiceStatusFailed
		}
		return outlaptypes.ServiceStatusStopped
	case "dead":
		return outlaptypes.ServiceStatusFailed
	default:
		return outlaptypes.ServiceStatusStopped
	}
}
