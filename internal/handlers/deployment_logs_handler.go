package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// DeploymentLogsHandler handles requests to retrieve deployment logs.
type DeploymentLogsHandler struct {
	*BaseHandler
}

// DeploymentLogsRequest represents the request structure for deployment log retrieval.
type DeploymentLogsRequest struct {
	ServiceUID    string `json:"service_uid"`
	DeploymentUID string `json:"deployment_uid,omitempty"`
	Lines         int    `json:"lines,omitempty"`    // Number of lines to return (default: 100)
	Since         string `json:"since,omitempty"`    // Time filter (e.g., "1h", "30m")
	LogType       string `json:"log_type,omitempty"` // build, deploy, runtime (default: all)
}

// NewDeploymentLogsHandler creates a new deployment logs handler.
func NewDeploymentLogsHandler(logger *logger.Logger, services ServiceProvider) *DeploymentLogsHandler {
	return &DeploymentLogsHandler{
		BaseHandler: NewBaseHandler(logger.With("handler", "service.deploy.logs.fetch"), services),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *DeploymentLogsHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Fetch processes deployment log requests and returns the filtered logs.
func (h *DeploymentLogsHandler) Fetch(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request DeploymentLogsRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format: " + err.Error(),
		}, nil
	}

	if request.ServiceUID == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "service_uid is required",
		}, nil
	}

	// Set defaults
	if request.Lines == 0 {
		request.Lines = 100
	}
	if request.LogType == "" {
		request.LogType = "build"
	}

	// Always return raw log content
	rawContent, err := h.getBuildLogContent(request.ServiceUID, request.DeploymentUID)
	if err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   fmt.Sprintf("Failed to get build log content: %v", err),
		}, nil
	}

	steps, err := h.getDeploymentSteps(request.ServiceUID, request.DeploymentUID)
	if err != nil {
		h.logger.Warn("Failed to load deployment step metadata", "error", err, "deployment_uid", request.DeploymentUID, "service_uid", request.ServiceUID)
		steps = []types.DeploymentStep{}
	}
	if steps == nil {
		steps = []types.DeploymentStep{}
	}

	// Split into lines for processing
	lines := strings.Split(rawContent, "\n")

	// Apply time filter if specified
	if request.Since != "" {
		filteredLines, err := h.filterRawLinesBySince(lines, request.Since)
		if err != nil {
			h.logger.Warn("Failed to apply time filter", "error", err)
			// Continue without filtering if time parsing fails
		} else {
			lines = filteredLines
		}
	}

	// Apply line limit if specified (get last N lines)
	if request.Lines > 0 && len(lines) > request.Lines {
		lines = lines[len(lines)-request.Lines:]
	}

	rawContent = strings.Join(lines, "\n")

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"service_uid":     request.ServiceUID,
			"deployment_uid":  request.DeploymentUID,
			"logs":            rawContent,
			"deployment_logs": rawContent,
			"container_logs":  "",
			"log_type":        "build",
			"lines_returned":  len(lines),
			"steps":           steps,
		},
	}, nil
}

// getBuildLogContent retrieves the raw build log content for a deployment or service.
func (h *DeploymentLogsHandler) getBuildLogContent(serviceUID, deploymentUID string) (string, error) {
	logsDir := "/var/log/outlap/deployments"

	// Check if we're in debug mode
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_LOG_DIR"); debugDir != "" {
			logsDir = filepath.Join(debugDir, "deployments")
		}
	}

	if deploymentUID == "" {
		return "", fmt.Errorf("deployment_uid is required to fetch build logs")
	}

	logFile := filepath.Join(logsDir, deploymentUID+"_build.log")

	if content, err := os.ReadFile(logFile); err == nil {
		return strings.TrimRight(string(content), "\n"), nil
	}

	return "", fmt.Errorf("no build log files found for service_uid: %s, deployment_uid: %s", serviceUID, deploymentUID)
}

func (h *DeploymentLogsHandler) getDeploymentSteps(serviceUID, deploymentUID string) ([]types.DeploymentStep, error) {
	if deploymentUID == "" {
		return nil, fmt.Errorf("deployment_uid is required to fetch deployment steps")
	}

	logsDir := "/var/log/outlap/deployments"
	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_LOG_DIR"); debugDir != "" {
			logsDir = filepath.Join(debugDir, "deployments")
		}
	}

	stepsFile := filepath.Join(logsDir, fmt.Sprintf("%s_steps.json", deploymentUID))
	content, err := os.ReadFile(stepsFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read deployment steps file: %w", err)
	}

	var steps []types.DeploymentStep
	if err := json.Unmarshal(content, &steps); err != nil {
		return nil, fmt.Errorf("failed to decode deployment steps: %w", err)
	}

	return steps, nil
}

// filterRawLinesBySince filters raw log lines by time duration.
func (h *DeploymentLogsHandler) filterRawLinesBySince(lines []string, since string) ([]string, error) {
	duration, err := time.ParseDuration(since)
	if err != nil {
		return nil, fmt.Errorf("invalid duration format: %w", err)
	}

	cutoff := time.Now().Add(-duration)
	var filtered []string

	for _, line := range lines {
		if line == "" {
			filtered = append(filtered, line)
			continue
		}

		// Try to parse timestamp from line format: "2023-01-01T12:00:00Z - LEVEL - message"
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) >= 1 {
			if ts, err := time.Parse(time.RFC3339, parts[0]); err == nil {
				if ts.After(cutoff) {
					filtered = append(filtered, line)
				}
			} else {
				// If we can't parse timestamp, include the line
				filtered = append(filtered, line)
			}
		} else {
			// If line doesn't match expected format, include it
			filtered = append(filtered, line)
		}
	}

	return filtered, nil
}
