package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// ServiceLogsHandler handles all service log operations (fetch, stream start, stream stop).
type ServiceLogsHandler struct {
	*BaseHandler
	activeStreams map[string]*LogStream
	streamsMutex  sync.RWMutex
}

// LogStream represents an active log streaming session
type LogStream struct {
	ServiceUID string
	Cancel     context.CancelFunc
	StartTime  time.Time
}

// NewServiceLogsHandler creates a new service logs handler.
func NewServiceLogsHandler(logger *logger.Logger, services ServiceProvider) *ServiceLogsHandler {
	return &ServiceLogsHandler{
		BaseHandler:   NewBaseHandler(logger.With("handler", "service.logs"), services),
		activeStreams: make(map[string]*LogStream),
	}
}

// Base returns the underlying BaseHandler for routing helpers.
func (h *ServiceLogsHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Fetch retrieves historical container logs for a service.
func (h *ServiceLogsHandler) Fetch(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request struct {
		ServiceUID string `json:"service_uid"`
		Lines      int    `json:"lines,omitempty"` // Number of lines to fetch (default: 100)
	}

	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format",
		}, nil
	}

	if request.ServiceUID == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "service_uid is required",
		}, nil
	}

	if request.Lines <= 0 {
		request.Lines = 100 // Default to 100 lines
	}

	// Resolve the active container for the service
	activeContainer, err := h.resolveActiveContainer(ctx, request.ServiceUID)
	if err != nil {
		h.logger.Error("Failed to resolve active container", "service_uid", request.ServiceUID, "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	containerName := activeContainer.Name

	// Get container logs
	logs, err := h.services.GetDockerService().GetContainerLogsByName(ctx, containerName)
	if err != nil {
		h.logger.Error("Failed to get container logs", "error", err, "container_name", containerName)
		return &types.CommandResponse{
			Success: false,
			Error:   "failed to get container logs: " + err.Error(),
		}, nil
	}

	// Limit to requested number of lines
	if len(logs) > request.Lines {
		logs = logs[len(logs)-request.Lines:]
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"logs":      logs,
			"container": containerName,
		},
	}, nil
}

// StreamStart initiates real-time log streaming for a service.
func (h *ServiceLogsHandler) StreamStart(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request struct {
		ServiceUID string `json:"service_uid"`
		Follow     bool   `json:"follow,omitempty"`
		Tail       int    `json:"tail,omitempty"`
	}

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

	h.logger.Info("Starting container log stream", "service_uid", request.ServiceUID)

	// Check if there's already an active stream for this service
	h.streamsMutex.Lock()
	if existingStream, exists := h.activeStreams[request.ServiceUID]; exists {
		h.logger.Info("Stopping existing stream", "service_uid", request.ServiceUID)
		existingStream.Cancel()
		delete(h.activeStreams, request.ServiceUID)
	}
	h.streamsMutex.Unlock()

	// Create a new context for this stream
	streamCtx, cancel := context.WithCancel(context.Background())

	// Store the stream info
	stream := &LogStream{
		ServiceUID: request.ServiceUID,
		Cancel:     cancel,
		StartTime:  time.Now(),
	}

	h.streamsMutex.Lock()
	h.activeStreams[request.ServiceUID] = stream
	h.streamsMutex.Unlock()

	// Start streaming logs in a goroutine
	go h.streamLogs(streamCtx, request.ServiceUID)

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":     "Log streaming started",
			"service_uid": request.ServiceUID,
			"start_time":  stream.StartTime,
		},
	}, nil
}

// StreamStop terminates an active log stream for a service.
func (h *ServiceLogsHandler) StreamStop(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request struct {
		ServiceUID string `json:"service_uid"`
	}

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

	h.logger.Info("Stopping container log stream", "service_uid", request.ServiceUID)

	// Attempt to stop the stream
	stopped := h.stopStream(request.ServiceUID)

	if stopped {
		h.logger.Info("Successfully stopped log stream", "service_uid", request.ServiceUID)
		return &types.CommandResponse{
			Success: true,
			Data: map[string]interface{}{
				"message":     "Log stream stopped successfully",
				"service_uid": request.ServiceUID,
			},
		}, nil
	}

	h.logger.Warn("No active stream found for service", "service_uid", request.ServiceUID)
	return &types.CommandResponse{
		Success: false,
		Error:   "no active log stream found for service: " + request.ServiceUID,
	}, nil
}

// streamLogs handles the actual log streaming in a background goroutine.
func (h *ServiceLogsHandler) streamLogs(ctx context.Context, serviceUID string) {
	defer func() {
		h.streamsMutex.Lock()
		delete(h.activeStreams, serviceUID)
		h.streamsMutex.Unlock()
		h.logger.Info("Log stream ended", "service_uid", serviceUID)
	}()

	// Generate container name for application using service UID
	containerName := fmt.Sprintf("outlap-app-%s", serviceUID)

	// Get the log stream from Docker service
	logChan, err := h.services.GetDockerService().StreamContainerLogs(ctx, containerName)
	if err != nil {
		h.logger.Error("Failed to start log stream", "service_uid", serviceUID, "container_name", containerName, "error", err)
		h.sendLogMessage(serviceUID, fmt.Sprintf("Error starting log stream: %v", err), "error")
		return
	}

	h.logger.Info("Log stream established", "service_uid", serviceUID, "container_name", containerName)
	h.sendLogMessage(serviceUID, "Log stream started", "info")

	// Stream logs until context is cancelled
	for {
		select {
		case <-ctx.Done():
			h.logger.Info("Log stream cancelled", "service_uid", serviceUID)
			h.sendLogMessage(serviceUID, "Log stream stopped", "info")
			return
		case logLine, ok := <-logChan:
			if !ok {
				h.logger.Info("Log stream channel closed", "service_uid", serviceUID)
				h.sendLogMessage(serviceUID, "Log stream ended", "info")
				return
			}
			h.sendLogMessage(serviceUID, logLine, "log")
		}
	}
}

// sendLogMessage sends a log message via WebSocket.
func (h *ServiceLogsHandler) sendLogMessage(serviceUID, message, messageType string) {
	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil {
		h.logger.Warn("WebSocket manager not available")
		return
	}

	logData := map[string]interface{}{
		"service_uid": serviceUID,
		"message":     message,
		"type":        messageType,
		"timestamp":   time.Now().Unix(),
	}

	if err := wsManager.Emit("container_log", logData); err != nil {
		h.logger.Error("Failed to send log message", "error", err)
	}
}

// stopStream stops an active log stream for a service.
func (h *ServiceLogsHandler) stopStream(serviceUID string) bool {
	h.streamsMutex.Lock()
	defer h.streamsMutex.Unlock()

	stream, exists := h.activeStreams[serviceUID]
	if !exists {
		return false
	}

	stream.Cancel()
	delete(h.activeStreams, serviceUID)
	return true
}
