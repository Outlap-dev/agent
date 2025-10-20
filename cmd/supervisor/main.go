// PulseUp Agent Supervisor - Privileged process for handling system operations
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/internal/supervisor"
	"pulseup-agent-go/pkg/logger"
)

func main() {
	// Check if running as root
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Error: supervisor must run as root\n")
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logLevel := logger.LogLevelInfo
	if cfg.Debug {
		logLevel = logger.LogLevelDebug
	}
	mainLogger := logger.NewWithLevel(logLevel)
	mainLogger.Info("Starting PulseUp Agent Supervisor",
		"version", config.GetVersionString(),
		"build_date", config.BuildDate,
		"git_commit", config.GitCommit,
		"pid", os.Getpid(),
		"uid", os.Getuid(),
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create supervisor service container
	supervisorContainer, err := supervisor.NewContainer(cfg, mainLogger)
	if err != nil {
		mainLogger.Error("Failed to create supervisor container", "error", err)
		os.Exit(1)
	}

	// Initialize supervisor services
	if err := supervisorContainer.Initialize(ctx); err != nil {
		mainLogger.Error("Failed to initialize supervisor services", "error", err)
		os.Exit(1)
	}

	// Create IPC server
	socketConfig := ipc.DefaultSocketConfigWithGroup(cfg.SocketGroup)
	ipcServer := ipc.NewServer(socketConfig, mainLogger, supervisorContainer)

	// Start IPC server
	if err := ipcServer.Start(ctx); err != nil {
		mainLogger.Error("Failed to start IPC server", "error", err)
		os.Exit(1)
	}
	defer ipcServer.Stop()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	mainLogger.Info("Supervisor ready and listening for requests")

	// Start supervisor services
	serviceErrChan := make(chan error, 1)
	go func() {
		if err := supervisorContainer.Start(ctx); err != nil {
			serviceErrChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		mainLogger.Info("Received shutdown signal", "signal", sig)
	case err := <-serviceErrChan:
		mainLogger.Error("Supervisor service error", "error", err)
	}

	// Initiate graceful shutdown
	mainLogger.Info("Initiating graceful shutdown")
	cancel()

	// Give services time to shutdown gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	shutdownComplete := make(chan struct{})
	go func() {
		defer close(shutdownComplete)

		// Stop supervisor services
		if err := supervisorContainer.Shutdown(shutdownCtx); err != nil {
			mainLogger.Error("Error during supervisor shutdown", "error", err)
		}

		// Stop IPC server
		if err := ipcServer.Stop(); err != nil {
			mainLogger.Error("Error stopping IPC server", "error", err)
		}
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-shutdownComplete:
		mainLogger.Info("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		mainLogger.Warn("Shutdown timeout exceeded, forcing exit")
	}

	mainLogger.Info("Supervisor stopped")
}
