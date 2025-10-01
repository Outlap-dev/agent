package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/services"
	"pulseup-agent-go/pkg/logger"
)

func main() {
	// Initialize logger with configuration-based format
	logger := logger.NewFromConfig()

	// Log version information
	logger.Info("Starting PulseUp Agent", "version", config.GetVersionString())

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize agent
	agent := &PulseUpAgent{
		logger: logger,
		config: cfg,
	}

	// Setup agent
	if err := agent.Setup(ctx); err != nil {
		logger.Error("Failed to setup agent", "error", err)
		return
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start agent in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- agent.Run(ctx)
	}()

	// Wait for shutdown signal or error
	select {
	case <-sigChan:
		logger.Info("Received shutdown signal")
		cancel()
	case err := <-errChan:
		if err != nil {
			logger.Error("Agent error", "error", err)
		}
		cancel()
	}

	// Wait for graceful shutdown
	logger.Info("Shutting down agent...")
	if err := agent.Shutdown(ctx); err != nil {
		logger.Error("Error during shutdown", "error", err)
	}
}

type PulseUpAgent struct {
	logger    *logger.Logger
	config    *config.Config
	container *services.ServiceContainer
}

func (a *PulseUpAgent) Setup(ctx context.Context) error {
	// Initialize service container
	container, err := services.NewServiceContainer(a.config, a.logger)
	if err != nil {
		return err
	}
	a.container = container

	// Initialize all services
	if err := a.container.Initialize(ctx); err != nil {
		return err
	}

	return nil
}

func (a *PulseUpAgent) Run(ctx context.Context) error {
	a.logger.Info("Starting PulseUp Agent")

	// Start all services
	return a.container.Start(ctx)
}

func (a *PulseUpAgent) Shutdown(ctx context.Context) error {
	if a.container != nil {
		return a.container.Shutdown(ctx)
	}
	return nil
}
