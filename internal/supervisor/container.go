// Package supervisor provides privileged services for the supervisor process
package supervisor

import (
	"context"
	"fmt"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/pkg/logger"
)

// Container manages all privileged services in the supervisor process
type Container struct {
	config *config.Config
	logger *logger.Logger

	// Privileged services
	systemService  *SystemService
	serviceManager *ServiceManager
	updateManager  *UpdateManager
}

// NewContainer creates a new supervisor service container
func NewContainer(cfg *config.Config, logger *logger.Logger) (*Container, error) {
	return &Container{
		config: cfg,
		logger: logger.With("component", "supervisor_container"),
	}, nil
}

// Initialize sets up all privileged services
func (c *Container) Initialize(ctx context.Context) error {
	c.logger.Info("Initializing supervisor services")

	// Initialize system service
	c.systemService = NewSystemService(c.logger)

	// Initialize service manager
	c.serviceManager = NewServiceManager(c.logger)

	// Initialize update manager
	c.updateManager = NewUpdateManager(c.logger, c.config)

	c.logger.Info("Supervisor services initialized successfully")
	return nil
}

// Start starts all background supervisor services
func (c *Container) Start(ctx context.Context) error {
	c.logger.Info("Starting supervisor services")

	// No background services to start currently
	
	c.logger.Info("Supervisor services started successfully")
	return nil
}

// Shutdown gracefully shuts down all supervisor services
func (c *Container) Shutdown(ctx context.Context) error {
	c.logger.Info("Shutting down supervisor services")

	// No background services to shut down currently

	c.logger.Info("Supervisor services shut down")
	return nil
}

// HandlePrivilegedRequest handles a privileged request from the worker
func (c *Container) HandlePrivilegedRequest(ctx context.Context, req *ipc.PrivilegedRequest) (*ipc.PrivilegedResponse, error) {
	operation := ipc.OperationType(req.Operation)
	
	c.logger.Info("Handling privileged request",
		"operation", operation,
		"request_id", req.ID,
		"worker_pid", req.WorkerPID,
	)

	// Route request to appropriate service
	switch operation {
	// System operations
	case ipc.OpSystemReboot:
		return c.systemService.Reboot(ctx, req.Args)
	case ipc.OpSystemShutdown:
		return c.systemService.Shutdown(ctx, req.Args)
	case ipc.OpSystemUpdatePackages:
		return c.systemService.UpdatePackages(ctx, req.Args)
	case ipc.OpSystemInstallPackage:
		return c.systemService.InstallPackage(ctx, req.Args)

	// Service management operations
	case ipc.OpServiceRestart:
		return c.serviceManager.RestartService(ctx, req.Args)
	case ipc.OpServiceStart:
		return c.serviceManager.StartService(ctx, req.Args)
	case ipc.OpServiceStop:
		return c.serviceManager.StopService(ctx, req.Args)
	case ipc.OpServiceStatus:
		return c.serviceManager.GetServiceStatus(ctx, req.Args)

	// Agent management operations
	case ipc.OpAgentUpdate:
		return c.updateManager.UpdateAgent(ctx, req.Args)
	case ipc.OpAgentRestart:
		return c.updateManager.RestartAgent(ctx, req.Args)

	default:
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("unknown operation: %s", operation),
		}, nil
	}
}