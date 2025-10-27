// Package worker provides unprivileged services for the worker process
package worker

import (
	"context"
	"fmt"

	"outlap-agent-go/internal/config"
	"outlap-agent-go/internal/services"
	"outlap-agent-go/pkg/logger"
)

// Container manages all unprivileged services in the agent process
type Container struct {
	config *config.Config
	logger *logger.Logger

	// Service container
	serviceContainer *services.ServiceContainer
}

// NewContainer creates a new agent service container
func NewContainer(cfg *config.Config, logger *logger.Logger, _ interface{}) (*Container, error) {
	return &Container{
		config: cfg,
		logger: logger.With("component", "agent_container"),
	}, nil
}

// Initialize sets up all agent services
func (c *Container) Initialize(ctx context.Context) error {
	c.logger.Info("Initializing agent services")

	serviceContainer, err := services.NewServiceContainer(c.config, c.logger)
	if err != nil {
		return fmt.Errorf("failed to create service container: %w", err)
	}

	// Initialize services
	if err := serviceContainer.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize service container: %w", err)
	}

	c.serviceContainer = serviceContainer

	return nil
}

// Start starts all agent services including WebSocket communication
func (c *Container) Start(ctx context.Context) error {
	// Start the service container (which handles WebSocket connections)
	if err := c.serviceContainer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start service container: %w", err)
	}

	c.logger.Info("Agent services started successfully")
	return nil
}

// Shutdown gracefully shuts down all agent services
func (c *Container) Shutdown(ctx context.Context) error {
	c.logger.Info("Shutting down agent services")

	// Stop service container
	if c.serviceContainer != nil {
		if err := c.serviceContainer.Shutdown(ctx); err != nil {
			c.logger.Error("Error stopping service container", "error", err)
		}
	}

	c.logger.Info("Agent services shut down")
	return nil
}
