// Package worker provides unprivileged services for the worker process
package worker

import (
	"context"
	"fmt"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/internal/services"
	"pulseup-agent-go/pkg/logger"
)

// Container manages all unprivileged services in the worker process
type Container struct {
	config    *config.Config
	logger    *logger.Logger
	ipcClient *ipc.Client

	// Service container (modified to use IPC)
	serviceContainer *services.ServiceContainer
}

// NewContainer creates a new worker service container
func NewContainer(cfg *config.Config, logger *logger.Logger, ipcClient *ipc.Client) (*Container, error) {
	return &Container{
		config:    cfg,
		logger:    logger.With("component", "worker_container"),
		ipcClient: ipcClient,
	}, nil
}

// Initialize sets up all unprivileged services
func (c *Container) Initialize(ctx context.Context) error {
	c.logger.Info("Initializing worker services")

	// Create modified service container that uses IPC for privileged operations
	serviceContainer, err := services.NewServiceContainerWithIPC(c.config, c.logger, c.ipcClient)
	if err != nil {
		return fmt.Errorf("failed to create service container: %w", err)
	}

	// Initialize with worker-specific modifications
	if err := serviceContainer.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize service container: %w", err)
	}

	c.serviceContainer = serviceContainer

	return nil
}

// Start starts all worker services including WebSocket communication
func (c *Container) Start(ctx context.Context) error {
	// Start the service container (which handles WebSocket connections)
	if err := c.serviceContainer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start service container: %w", err)
	}

	c.logger.Info("Worker services started successfully")
	return nil
}

// Shutdown gracefully shuts down all worker services
func (c *Container) Shutdown(ctx context.Context) error {
	c.logger.Info("Shutting down worker services")

	// Stop service container
	if c.serviceContainer != nil {
		if err := c.serviceContainer.Shutdown(ctx); err != nil {
			c.logger.Error("Error stopping service container", "error", err)
		}
	}

	c.logger.Info("Worker services shut down")
	return nil
}
