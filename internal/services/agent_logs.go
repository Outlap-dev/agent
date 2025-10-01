package services

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"pulseup-agent-go/pkg/logger"
)

// AgentLogServiceImpl implements the AgentLogService interface
type AgentLogServiceImpl struct {
	logger *logger.Logger
}

// NewAgentLogService creates a new agent log service
func NewAgentLogService(logger *logger.Logger) *AgentLogServiceImpl {
	return &AgentLogServiceImpl{
		logger: logger.With("service", "agent_logs"),
	}
}

// GetAgentLogs retrieves agent logs from multiple sources
func (s *AgentLogServiceImpl) GetAgentLogs(ctx context.Context, lines int) ([]string, error) {
	var allLogs []string

	// First, try to get logs from the agent log file if it exists
	logFilePath := "/var/log/pulseup/agent.log"
	if _, err := os.Stat(logFilePath); err == nil {
		fileLogs, err := s.getLogsFromFile(logFilePath, lines)
		if err != nil {
			s.logger.Warn("Failed to read agent log file", "path", logFilePath, "error", err)
		} else {
			allLogs = append(allLogs, fileLogs...)
		}
	}

	// If we don't have enough logs from file or file doesn't exist,
	// try to get logs from Docker container logs
	if len(allLogs) < lines {
		remainingLines := lines - len(allLogs)
		containerLogs, err := s.getLogsFromContainer(ctx, remainingLines)
		if err != nil {
			s.logger.Warn("Failed to read container logs", "error", err)
		} else {
			allLogs = append(allLogs, containerLogs...)
		}
	}

	// If we still don't have enough logs, try journalctl for systemd logs
	if len(allLogs) < lines {
		remainingLines := lines - len(allLogs)
		systemLogs, err := s.getLogsFromJournalctl(ctx, remainingLines)
		if err != nil {
			s.logger.Warn("Failed to read systemd logs", "error", err)
		} else {
			allLogs = append(allLogs, systemLogs...)
		}
	}

	// Limit to requested number of lines
	if len(allLogs) > lines {
		allLogs = allLogs[len(allLogs)-lines:]
	}

	return allLogs, nil
}

// getLogsFromFile reads logs from the agent log file
func (s *AgentLogServiceImpl) getLogsFromFile(filePath string, maxLines int) ([]string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read log file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var nonEmptyLines []string
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines = append(nonEmptyLines, line)
		}
	}

	// Return the last N lines
	if len(nonEmptyLines) > maxLines {
		return nonEmptyLines[len(nonEmptyLines)-maxLines:], nil
	}
	
	return nonEmptyLines, nil
}

// getLogsFromContainer attempts to get logs from the current container
func (s *AgentLogServiceImpl) getLogsFromContainer(ctx context.Context, maxLines int) ([]string, error) {
	// Try to get the container ID from various sources
	containerID, err := s.getCurrentContainerID()
	if err != nil {
		return nil, fmt.Errorf("failed to get container ID: %w", err)
	}

	// Use docker logs command to get container logs
	cmd := exec.CommandContext(ctx, "docker", "logs", "--tail", fmt.Sprintf("%d", maxLines), containerID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get docker logs: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var nonEmptyLines []string
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines = append(nonEmptyLines, line)
		}
	}

	return nonEmptyLines, nil
}

// getCurrentContainerID attempts to determine the current container ID
func (s *AgentLogServiceImpl) getCurrentContainerID() (string, error) {
	// Method 1: Try to read from /proc/self/cgroup (works in most Docker containers)
	if content, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.Contains(line, "docker") {
				parts := strings.Split(line, "/")
				if len(parts) > 0 {
					containerID := parts[len(parts)-1]
					// Container ID should be 64 characters long
					if len(containerID) >= 12 {
						return containerID[:12], nil // Use short ID
					}
				}
			}
		}
	}

	// Method 2: Try to read from /proc/1/cpuset (alternative method)
	if content, err := os.ReadFile("/proc/1/cpuset"); err == nil {
		cpuset := strings.TrimSpace(string(content))
		if strings.HasPrefix(cpuset, "/docker/") {
			containerID := strings.TrimPrefix(cpuset, "/docker/")
			if len(containerID) >= 12 {
				return containerID[:12], nil
			}
		}
	}

	// Method 3: Check hostname (Docker containers often use container ID as hostname)
	if hostname, err := os.Hostname(); err == nil {
		if len(hostname) >= 12 {
			return hostname, nil
		}
	}

	return "", fmt.Errorf("could not determine container ID")
}

// getLogsFromJournalctl attempts to get logs from systemd journal
func (s *AgentLogServiceImpl) getLogsFromJournalctl(ctx context.Context, maxLines int) ([]string, error) {
	// Try to get logs for pulseup-agent service
	cmd := exec.CommandContext(ctx, "journalctl", "-u", "pulseup-agent", "--no-pager", "-n", fmt.Sprintf("%d", maxLines))
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If specific service doesn't exist, try to get recent logs with pulseup in them
		cmd = exec.CommandContext(ctx, "journalctl", "--no-pager", "-n", fmt.Sprintf("%d", maxLines*2), "--grep", "pulseup")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("failed to get journalctl logs: %w", err)
		}
	}

	lines := strings.Split(string(output), "\n")
	var nonEmptyLines []string
	
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines = append(nonEmptyLines, line)
		}
	}

	// Limit to requested number of lines
	if len(nonEmptyLines) > maxLines {
		return nonEmptyLines[len(nonEmptyLines)-maxLines:], nil
	}

	return nonEmptyLines, nil
}