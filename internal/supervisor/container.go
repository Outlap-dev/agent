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
	updateManager *UpdateManager
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
	case ipc.OpAgentUpdate:
		return c.updateManager.UpdateAgent(ctx, req.Args)
	default:
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("unknown operation: %s", operation),
		}, nil
	}
}
