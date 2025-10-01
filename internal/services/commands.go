package services

import (
	"context"
	"fmt"
	"strings"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/runtime"
	"pulseup-agent-go/pkg/types"
)

type commandService struct {
	logger          *logger.Logger
	dockerService   DockerService
	systemService   SystemService
	whitelistedCmds map[string]types.WhitelistedCommand
	executor        *runtime.Executor
	osInfo          *runtime.OSInfo
}

func NewCommandService(logger *logger.Logger, dockerService DockerService, systemService SystemService) CommandService {
	cs := &commandService{
		logger:        logger,
		dockerService: dockerService,
		systemService: systemService,
		executor:      runtime.NewExecutor(),
		osInfo:        runtime.DetectOS(),
	}
	cs.initializeWhitelistedCommands()
	return cs
}

func (cs *commandService) initializeWhitelistedCommands() {
	cs.whitelistedCmds = map[string]types.WhitelistedCommand{
		// System commands
		"system.reboot": {
			ID:                   "system.reboot",
			Name:                 "Reboot Server",
			Description:          "Safely reboot the server",
			Category:             "system",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.rebootServer(ctx)
			},
		},
		"system.shutdown": {
			ID:                   "system.shutdown",
			Name:                 "Shutdown Server",
			Description:          "Safely shutdown the server",
			Category:             "system",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.shutdownServer(ctx)
			},
		},
		"system.update_packages": {
			ID:                   "system.update_packages",
			Name:                 "Update System Packages",
			Description:          "Update all system packages",
			Category:             "system",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.updateSystemPackages(ctx)
			},
		},

		// Docker commands
		"docker.list_all": {
			ID:          "docker.list_all",
			Name:        "List All Containers",
			Description: "List all Docker containers including stopped ones",
			Category:    "docker",
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.listAllContainers(ctx)
			},
		},
		"docker.prune_images": {
			ID:                   "docker.prune_images",
			Name:                 "Prune Docker Images",
			Description:          "Remove unused Docker images",
			Category:             "docker",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.pruneDockerImages(ctx)
			},
		},
		"docker.prune_volumes": {
			ID:                   "docker.prune_volumes",
			Name:                 "Prune Docker Volumes",
			Description:          "Remove unused Docker volumes",
			Category:             "docker",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.pruneDockerVolumes(ctx)
			},
		},
		"docker.system_prune": {
			ID:                   "docker.system_prune",
			Name:                 "Docker System Prune",
			Description:          "Clean up Docker system (containers, networks, images, build cache)",
			Category:             "docker",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.dockerSystemPrune(ctx)
			},
		},

		// Service management
		"service.restart_caddy": {
			ID:          "service.restart_caddy",
			Name:        "Restart Caddy",
			Description: "Restart the Caddy reverse proxy service",
			Category:    "service",
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.restartService(ctx, "caddy")
			},
		},
		"service.restart_docker": {
			ID:                   "service.restart_docker",
			Name:                 "Restart Docker",
			Description:          "Restart the Docker daemon",
			Category:             "service",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.restartService(ctx, "docker")
			},
		},

		// Disk management
		"disk.cleanup_logs": {
			ID:          "disk.cleanup_logs",
			Name:        "Cleanup Old Logs",
			Description: "Remove log files older than 30 days",
			Category:    "disk",
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.cleanupOldLogs(ctx)
			},
		},
		"disk.cleanup_temp": {
			ID:          "disk.cleanup_temp",
			Name:        "Cleanup Temp Files",
			Description: "Remove temporary files",
			Category:    "disk",
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.cleanupTempFiles(ctx)
			},
		},

		// Agent self-management
		"agent.update": {
			ID:                   "agent.update",
			Name:                 "Update Agent",
			Description:          "Update the PulseUp agent to the latest version",
			Category:             "agent",
			RequiresConfirmation: true,
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				// Delegate to update handler
				return &types.CommandResult{
					Success: false,
					Output:  "Please use the 'agent.update.apply' command to update the agent",
				}, nil
			},
		},
		"agent.restart": {
			ID:          "agent.restart",
			Name:        "Restart Agent",
			Description: "Restart the PulseUp agent",
			Category:    "agent",
			Handler: func(ctx context.Context, args map[string]string) (*types.CommandResult, error) {
				return cs.restartAgent(ctx)
			},
		},
	}
}

func (cs *commandService) ExecuteWhitelistedCommand(ctx context.Context, commandID string, args map[string]string) (*types.CommandResult, error) {
	cmd, exists := cs.whitelistedCmds[commandID]
	if !exists {
		return nil, fmt.Errorf("command %s is not whitelisted", commandID)
	}

	cs.logger.Info("Executing whitelisted command", "commandID", commandID, "args", args)

	if cmd.Handler == nil {
		return nil, fmt.Errorf("command %s has no handler", commandID)
	}

	result, err := cmd.Handler(ctx, args)
	if err != nil {
		cs.logger.Error("Command execution failed", "commandID", commandID, "error", err)
		return &types.CommandResult{
			Success: false,
			Output:  fmt.Sprintf("Command failed: %v", err),
			Error:   err.Error(),
		}, nil
	}

	return result, nil
}

func (cs *commandService) GetAvailableCommands() []types.WhitelistedCommand {
	var commands []types.WhitelistedCommand
	for _, cmd := range cs.whitelistedCmds {
		// Don't include the handler function in the response
		cmdCopy := cmd
		cmdCopy.Handler = nil
		commands = append(commands, cmdCopy)
	}
	return commands
}

func (cs *commandService) IsCommandWhitelisted(commandID string) bool {
	_, exists := cs.whitelistedCmds[commandID]
	return exists
}

// Command implementations
func (cs *commandService) rebootServer(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "sudo", []string{"reboot"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) shutdownServer(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "sudo", []string{"shutdown", "-h", "now"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) updateSystemPackages(ctx context.Context) (*types.CommandResult, error) {
	// Use OS detection to get the right update command
	cmd := cs.osInfo.GetUpgradeCommand()
	if cmd == nil {
		return &types.CommandResult{
			Success: false,
			Output:  "No supported package manager found",
		}, fmt.Errorf("no supported package manager found")
	}

	// Add sudo if needed
	cmd = cs.osInfo.PrefixSudo(cmd)

	result := cs.executor.Execute(ctx, cmd[0], cmd[1:], nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) listAllContainers(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "docker", []string{"ps", "-a", "--format", "table {{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Image}}"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) pruneDockerImages(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "docker", []string{"image", "prune", "-a", "-f"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) pruneDockerVolumes(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "docker", []string{"volume", "prune", "-f"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) dockerSystemPrune(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "docker", []string{"system", "prune", "-a", "-f", "--volumes"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) restartService(ctx context.Context, serviceName string) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "sudo", []string{"systemctl", "restart", serviceName}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) cleanupOldLogs(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "find", []string{"/var/log", "-type", "f", "-name", "*.log", "-mtime", "+30", "-delete"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) cleanupTempFiles(ctx context.Context) (*types.CommandResult, error) {
	result := cs.executor.Execute(ctx, "find", []string{"/tmp", "-type", "f", "-atime", "+7", "-delete"}, nil)

	return &types.CommandResult{
		Success:   result.Error == nil,
		Output:    result.Stdout + result.Stderr,
		Timestamp: time.Now(),
	}, result.Error
}

func (cs *commandService) restartAgent(ctx context.Context) (*types.CommandResult, error) {
	var attempts []string

	// Try systemctl first
	systemctlResult := cs.executor.Execute(ctx, "systemctl", []string{"--version"}, nil)
	if systemctlResult.Error == nil {
		result := cs.executor.Execute(ctx, "sudo", []string{"systemctl", "restart", "pulseup-agent"}, nil)
		attempts = append(attempts, fmt.Sprintf("systemctl attempt: %s", result.Stdout+result.Stderr))

		if result.Error == nil {
			return &types.CommandResult{
				Success:   true,
				Output:    fmt.Sprintf("Agent restarted via systemctl: %s", result.Stdout+result.Stderr),
				Timestamp: time.Now(),
			}, nil
		}

		// Check if service exists but failed for other reasons
		combinedOutput := result.Stdout + result.Stderr
		if !strings.Contains(combinedOutput, "not found") && !strings.Contains(combinedOutput, "could not be found") {
			return &types.CommandResult{
				Success:   false,
				Output:    fmt.Sprintf("systemctl restart failed: %s", combinedOutput),
				Error:     result.Error.Error(),
				Timestamp: time.Now(),
			}, result.Error
		}
	}

	// Try Docker container restart if running in Docker
	dockerResult := cs.executor.Execute(ctx, "docker", []string{"restart", "pulseup-agent"}, nil)
	if dockerResult.Error == nil {
		attempts = append(attempts, fmt.Sprintf("docker restart: %s", dockerResult.Stdout+dockerResult.Stderr))
		return &types.CommandResult{
			Success:   true,
			Output:    fmt.Sprintf("Agent container restarted: %s", dockerResult.Stdout+dockerResult.Stderr),
			Timestamp: time.Now(),
		}, nil
	}
	attempts = append(attempts, fmt.Sprintf("docker restart failed: %s", dockerResult.Stdout+dockerResult.Stderr))

	// Fall back to pkill and rely on supervisor/systemd/docker to restart
	pkillResult := cs.executor.Execute(ctx, "pkill", []string{"-f", "pulseup-agent"}, nil)
	attempts = append(attempts, fmt.Sprintf("pkill attempt: %s", pkillResult.Stdout+pkillResult.Stderr))

	if pkillResult.Error == nil {
		return &types.CommandResult{
			Success:   true,
			Output:    fmt.Sprintf("Agent process killed (should auto-restart): %s\nAttempts: %s", pkillResult.Stdout+pkillResult.Stderr, strings.Join(attempts, "; ")),
			Timestamp: time.Now(),
		}, nil
	}

	return &types.CommandResult{
		Success:   false,
		Output:    fmt.Sprintf("All restart methods failed. Attempts: %s", strings.Join(attempts, "; ")),
		Error:     pkillResult.Error.Error(),
		Timestamp: time.Now(),
	}, pkillResult.Error
}
