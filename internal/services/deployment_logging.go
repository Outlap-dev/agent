package services

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"errors"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

type deploymentLogManager struct {
	logger  *logger.Logger
	logsDir string
}

type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func newDeploymentLogManager(baseLogger *logger.Logger) *deploymentLogManager {
	logsDir := ResolveDeploymentLogsDir()

	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		baseLogger.Warn("Failed to ensure deployment logs directory", "dir", logsDir, "error", err)
	}

	return &deploymentLogManager{
		logger:  baseLogger,
		logsDir: logsDir,
	}
}

func (m *deploymentLogManager) LogsDir() string {
	if m == nil {
		return ""
	}
	return m.logsDir
}

func (m *deploymentLogManager) NewStepTracker(serviceUID, deploymentUID string, templates ...types.DeploymentStep) *deploymentStepTracker {
	if m == nil {
		return nil
	}
	return newDeploymentStepTracker(m.logger, m.logsDir, serviceUID, deploymentUID, templates...)
}

func (m *deploymentLogManager) buildLogPaths(serviceUID, deploymentUID, logType string) []string {
	if m == nil || logType == "" {
		return nil
	}

	paths := make([]string, 0, 2)
	if deploymentUID != "" {
		paths = append(paths, filepath.Join(m.logsDir, fmt.Sprintf("%s_%s.log", deploymentUID, logType)))
	}
	if serviceUID != "" {
		paths = append(paths, filepath.Join(m.logsDir, fmt.Sprintf("%s_%s.log", serviceUID, logType)))
	}

	return paths
}

func (m *deploymentLogManager) initializeLogFiles(serviceUID, deploymentUID, logType string, command []string) []*os.File {
	paths := m.buildLogPaths(serviceUID, deploymentUID, logType)
	if len(paths) == 0 {
		return nil
	}

	files := make([]*os.File, 0, len(paths))

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			m.logger.Warn("Failed to create log directory", "path", path, "error", err)
			continue
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			m.logger.Warn("Failed to create log file", "path", path, "error", err)
			continue
		}
		files = append(files, file)
	}

	return files
}

func (m *deploymentLogManager) AppendLogEntry(serviceUID, deploymentUID, logType, level, message string) {
	if m == nil {
		return
	}

	paths := m.buildLogPaths(serviceUID, deploymentUID, logType)
	if len(paths) == 0 {
		return
	}

	entry := fmt.Sprintf("%s - %s - %s\n", time.Now().Format(time.RFC3339), level, message)

	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			m.logger.Warn("Failed to create log directory", "path", path, "error", err)
			continue
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			m.logger.Warn("Failed to append to log file", "path", path, "error", err)
			continue
		}
		if _, err := file.WriteString(entry); err != nil {
			m.logger.Warn("Failed to write log entry", "path", path, "error", err)
		}
		_ = file.Close()
	}
}

func (m *deploymentLogManager) AppendDeploymentLog(serviceUID, deploymentUID, level, message string) {
	if m == nil {
		return
	}
	m.AppendLogEntry(serviceUID, deploymentUID, "deploy", level, message)
}

func (m *deploymentLogManager) RunCommand(ctx context.Context, command []string, workDir, deploymentUID, serviceUID, logType string, extraEnv []string) (*CommandResult, error) {
	if m == nil {
		return nil, fmt.Errorf("deployment log manager is nil")
	}
	if len(command) == 0 {
		return nil, fmt.Errorf("command cannot be empty")
	}

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = workDir

	baseEnv := os.Environ()
	dockerConfigSet := false
	for _, e := range baseEnv {
		if strings.HasPrefix(e, "DOCKER_CONFIG=") {
			dockerConfigSet = true
			break
		}
	}
	if !dockerConfigSet {
		defaultDockerConfig := filepath.Join("/var/lib/outlap", "docker-config")
		if err := os.MkdirAll(defaultDockerConfig, 0o750); err != nil {
			m.logger.Warn("Failed to ensure default Docker config dir", "dir", defaultDockerConfig, "error", err)
			fallbackDockerConfig := filepath.Join(os.TempDir(), "outlap-docker-config")
			if fallbackErr := os.MkdirAll(fallbackDockerConfig, 0o700); fallbackErr != nil {
				m.logger.Warn("Failed to create fallback Docker config dir", "dir", fallbackDockerConfig, "error", fallbackErr)
			} else {
				defaultDockerConfig = fallbackDockerConfig
			}
		}
		configFile := filepath.Join(defaultDockerConfig, "config.json")
		if _, err := os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
			if writeErr := os.WriteFile(configFile, []byte("{}\n"), 0o644); writeErr != nil {
				m.logger.Warn("Failed to initialize Docker config", "file", configFile, "error", writeErr)
			}
		} else if err != nil {
			m.logger.Warn("Failed to stat Docker config", "file", configFile, "error", err)
		}
		baseEnv = append(baseEnv, fmt.Sprintf("DOCKER_CONFIG=%s", defaultDockerConfig))
	}
	if os.Geteuid() != 0 {
		hasHome := false
		for _, e := range baseEnv {
			if strings.HasPrefix(e, "HOME=") {
				hasHome = true
				break
			}
		}
		if !hasHome {
			if homeDir, err := os.UserHomeDir(); err == nil {
				baseEnv = append(baseEnv, fmt.Sprintf("HOME=%s", homeDir))
			}
		}
	}

	if os.Getenv("DOCKER_FORCE_LEGACY_BUILDS") == "1" {
		baseEnv = append(baseEnv,
			"DOCKER_BUILDKIT=0",
			"COMPOSE_DOCKER_CLI_BUILD=0",
			"DOCKER_CLI_EXPERIMENTAL=disabled",
		)
	}

	if len(extraEnv) > 0 {
		baseEnv = append(baseEnv, extraEnv...)
	}
	cmd.Env = baseEnv

	m.logger.Info("Executing deployment command",
		"work_dir", workDir,
		"command", strings.Join(command, " "))

	if os.Getenv("DEBUG") == "true" {
		for _, e := range cmd.Env {
			if strings.HasPrefix(e, "DOCKER_") || strings.HasPrefix(e, "COMPOSE_") {
				m.logger.Debug("env", "var", e)
			}
		}
	}

	logFiles := m.initializeLogFiles(serviceUID, deploymentUID, logType, command)
	if len(logFiles) > 0 {
		defer func() {
			for _, file := range logFiles {
				if file != nil {
					_ = file.Close()
				}
			}
		}()
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	stdoutChan := make(chan string, 1)
	stderrChan := make(chan string, 1)

	go m.readStream(stdoutPipe, false, logFiles, stdoutChan)
	go m.readStream(stderrPipe, true, logFiles, stderrChan)

	err = cmd.Wait()

	stdout := <-stdoutChan
	stderr := <-stderrChan

	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			return nil, fmt.Errorf("command execution failed: %w", err)
		}
	}

	result := &CommandResult{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
	}

	if logType != "" {
		level := "INFO"
		message := "Command completed successfully"
		if exitCode != 0 {
			level = "ERROR"
			message = fmt.Sprintf("Command exited with code %d", exitCode)
		}
		m.AppendLogEntry(serviceUID, deploymentUID, logType, level, message)
	}

	return result, nil
}

func (m *deploymentLogManager) readStream(reader io.Reader, isStderr bool, logFiles []*os.File, output chan<- string) {
	if m == nil {
		output <- ""
		return
	}

	var lines []string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		lines = append(lines, line)
		timestamp := time.Now().Format(time.RFC3339)

		logLevel := "INFO"
		if isStderr {
			isDockerProgress := strings.Contains(line, "#") ||
				strings.Contains(line, "building with") ||
				(strings.Contains(line, "DONE") && !strings.Contains(line, "ERROR")) ||
				strings.Contains(line, "transferring") ||
				strings.Contains(line, "load build definition") ||
				strings.Contains(line, "exporting layers") ||
				strings.Contains(line, "writing image")

			if !isDockerProgress {
				logLevel = "ERROR"
				m.logger.Error("Command stderr", "line", line)
			} else {
				m.logger.Debug("Command progress", "line", line)
			}
		} else {
			m.logger.Debug("Command stdout", "line", line)
		}

		for _, file := range logFiles {
			if file != nil {
				file.WriteString(fmt.Sprintf("%s - %s - %s\n", timestamp, logLevel, line))
			}
		}
	}

	output <- strings.Join(lines, "\n")
}
