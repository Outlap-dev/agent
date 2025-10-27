// Outlap Agent - single-process unprivileged agent
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"outlap-agent-go/internal/config"
	"outlap-agent-go/internal/worker"
	"outlap-agent-go/pkg/logger"
)

func main() {
	// Ensure we're NOT running as root
	if os.Getuid() == 0 {
		fmt.Fprintf(os.Stderr, "Error: outlap-agent must NOT run as root for security\n")
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
	mainLogger.Info("Starting Outlap Agent",
		"version", config.GetVersionString(),
		"build_date", config.BuildDate,
		"git_commit", config.GitCommit,
		"pid", os.Getpid(),
		"uid", os.Getuid(),
		"gid", os.Getgid(),
	)

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create agent service container (no supervisor IPC)
	agentContainer, err := worker.NewContainer(cfg, mainLogger, nil)
	if err != nil {
		mainLogger.Error("Failed to create agent container", "error", err)
		os.Exit(1)
	}

	// Initialize services
	if err := agentContainer.Initialize(ctx); err != nil {
		mainLogger.Error("Failed to initialize agent services", "error", err)
		os.Exit(1)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	// Start services
	serviceErrChan := make(chan error, 1)
	go func() {
		if err := agentContainer.Start(ctx); err != nil {
			serviceErrChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		mainLogger.Info("Received shutdown signal", "signal", sig)
	case err := <-serviceErrChan:
		mainLogger.Error("Agent service error", "error", err)
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

		if err := agentContainer.Shutdown(shutdownCtx); err != nil {
			mainLogger.Error("Error during agent shutdown", "error", err)
		}
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-shutdownComplete:
		mainLogger.Info("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		mainLogger.Warn("Shutdown timeout exceeded, forcing exit")
	}

	mainLogger.Info("Agent stopped")
}
