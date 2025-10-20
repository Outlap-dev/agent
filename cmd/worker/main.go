// PulseUp Agent Worker - Unprivileged process for handling WebSocket communication
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
	"pulseup-agent-go/internal/worker"
	"pulseup-agent-go/pkg/logger"
)

func main() {
	// Ensure we're NOT running as root
	if os.Getuid() == 0 {
		fmt.Fprintf(os.Stderr, "Error: worker must NOT run as root for security\n")
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
	mainLogger.Info("Starting PulseUp Agent Worker",
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

	// Create IPC client to communicate with supervisor
	socketConfig := ipc.DefaultSocketConfigWithGroup(cfg.SocketGroup)
	ipcClient := ipc.NewClient(socketConfig, mainLogger)

	// Connect to supervisor with retry
	mainLogger.Info("Connecting to supervisor...")
	if err := ipcClient.ConnectWithRetry(ctx); err != nil {
		mainLogger.Error("Failed to connect to supervisor", "error", err)
		os.Exit(1)
	}
	defer ipcClient.Disconnect()

	mainLogger.Info("Connected to supervisor successfully")

	// Create worker service container
	workerContainer, err := worker.NewContainer(cfg, mainLogger, ipcClient)
	if err != nil {
		mainLogger.Error("Failed to create worker container", "error", err)
		os.Exit(1)
	}

	// Initialize worker services
	if err := workerContainer.Initialize(ctx); err != nil {
		mainLogger.Error("Failed to initialize worker services", "error", err)
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)

	// Start worker services
	serviceErrChan := make(chan error, 1)
	go func() {
		if err := workerContainer.Start(ctx); err != nil {
			serviceErrChan <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		mainLogger.Info("Received shutdown signal", "signal", sig)
	case err := <-serviceErrChan:
		mainLogger.Error("Worker service error", "error", err)
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

		// Stop worker services
		if err := workerContainer.Shutdown(shutdownCtx); err != nil {
			mainLogger.Error("Error during worker shutdown", "error", err)
		}

		// Disconnect from supervisor
		if err := ipcClient.Disconnect(); err != nil {
			mainLogger.Error("Error disconnecting from supervisor", "error", err)
		}
	}()

	// Wait for graceful shutdown or timeout
	select {
	case <-shutdownComplete:
		mainLogger.Info("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		mainLogger.Warn("Shutdown timeout exceeded, forcing exit")
	}

	mainLogger.Info("Worker stopped")
}
