package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// ServerHandler aggregates server-centric commands, including live stats and package management.
type ServerHandler struct {
	*BaseHandler

	streamsMutex  sync.RWMutex
	activeStreams map[string]*packageUpdateStream
}

type packageUpdateStream struct {
	streamID  string
	cancel    context.CancelFunc
	startTime time.Time
}

type packageUpdateRequest struct {
	PackageNames []string `json:"package_names"`
	UpdateAll    bool     `json:"update_all"`
	StreamID     string   `json:"stream_id,omitempty"`
}

// NewServerHandler constructs a ServerHandler that can service multiple commands.
func NewServerHandler(logger *logger.Logger, services ServiceProvider) *ServerHandler {
	return &ServerHandler{
		BaseHandler:   NewBaseHandler(logger.With("controller", "server"), services),
		activeStreams: make(map[string]*packageUpdateStream),
	}
}

// Base exposes the embedded base handler for routing helpers.
func (h *ServerHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// LiveStats surfaces current system metrics in a dashboard-friendly format.
func (h *ServerHandler) LiveStats(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Debug("Getting live system stats")

	systemService := h.services.GetSystemService()
	if systemService == nil {
		h.logger.Error("System service not available")
		return &types.CommandResponse{
			Success: false,
			Error:   "system service not available",
		}, nil
	}

	metrics, err := systemService.GetSystemMetrics(ctx)
	if err != nil {
		h.logger.Error("Failed to get system metrics", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "failed to get system metrics: " + err.Error(),
		}, nil
	}

	const bytesToGB = 1024 * 1024 * 1024

	liveStats := map[string]interface{}{
		"cpu_percent":          metrics.CPU.Usage,
		"memory_used_gb":       float64(metrics.Memory.Used) / bytesToGB,
		"memory_total_gb":      float64(metrics.Memory.Total) / bytesToGB,
		"memory_usage_percent": metrics.Memory.Usage,
		"disk_used_gb":         float64(metrics.Disk.Used) / bytesToGB,
		"disk_total_gb":        float64(metrics.Disk.Total) / bytesToGB,
		"disk_usage_percent":   metrics.Disk.Usage,
		"network_bytes_in":     metrics.Network.BytesIn,
		"network_bytes_out":    metrics.Network.BytesOut,
		"uptime_seconds":       int64(metrics.Uptime.Seconds()),
		"load_avg_1":           metrics.CPU.LoadAvg1,
		"load_avg_5":           metrics.CPU.LoadAvg5,
		"load_avg_15":          metrics.CPU.LoadAvg15,
		"timestamp":            metrics.Timestamp,
	}

	h.logger.Debug("Successfully retrieved live stats",
		"cpu_usage", liveStats["cpu_percent"],
		"memory_used_gb", liveStats["memory_used_gb"],
		"disk_used_gb", liveStats["disk_used_gb"],
		"uptime_seconds", liveStats["uptime_seconds"])

	return &types.CommandResponse{
		Success: true,
		Data:    liveStats,
	}, nil
}

// ListUpgradablePackages enumerates packages that can be updated.
func (h *ServerHandler) ListUpgradablePackages(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Handling get_upgradable_packages command")

	packages, err := h.services.GetPackageService().GetUpgradablePackages(ctx)
	if err != nil {
		h.logger.Error("Failed to get upgradable packages", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "Failed to get upgradable packages: " + err.Error(),
		}, nil
	}

	h.logger.Info("Successfully retrieved upgradable packages",
		"count", packages.TotalCount,
		"total_size", packages.TotalSize)

	return &types.CommandResponse{
		Success: true,
		Data:    packages,
	}, nil
}

// UpdatePackages applies package updates, either targeted or system-wide.
func (h *ServerHandler) UpdatePackages(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Handling update_packages command")

	var req packageUpdateRequest
	if err := json.Unmarshal(data, &req); err != nil {
		h.logger.Error("Failed to parse request", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "Invalid request format: " + err.Error(),
		}, nil
	}

	if !req.UpdateAll && len(req.PackageNames) == 0 {
		return &types.CommandResponse{
			Success: false,
			Error:   "Either package_names or update_all must be specified",
		}, nil
	}

	var (
		result *types.PackageUpdateResult
		err    error
	)

	if req.UpdateAll {
		h.logger.Info("Updating all packages")
		result, err = h.services.GetPackageService().UpdateAllPackages(ctx)
	} else {
		h.logger.Info("Updating specific packages", "packages", req.PackageNames)
		result, err = h.services.GetPackageService().UpdatePackages(ctx, req.PackageNames)
	}

	if err != nil {
		h.logger.Error("Failed to update packages", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "Failed to update packages: " + err.Error(),
		}, nil
	}

	if result.Success {
		h.logger.Info("Successfully updated packages",
			"updated_count", len(result.UpdatedPackages),
			"failed_count", len(result.FailedPackages))
	} else {
		h.logger.Error("Package update failed",
			"message", result.Message,
			"errors", result.Errors)
	}

	response := &types.CommandResponse{
		Success: result.Success,
		Data:    result,
	}

	if !result.Success {
		response.Error = fmt.Sprintf("%s: %v", result.Message, result.Errors)
	}

	return response, nil
}

// StartPackageUpdateStream begins a long-lived package update stream, mirroring the previous handler behaviour.
func (h *ServerHandler) StartPackageUpdateStream(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request packageUpdateRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format: " + err.Error(),
		}, nil
	}

	if !request.UpdateAll && len(request.PackageNames) == 0 {
		return &types.CommandResponse{
			Success: false,
			Error:   "Either package_names or update_all must be specified",
		}, nil
	}

	streamID := request.StreamID
	if streamID == "" {
		streamID = fmt.Sprintf("pkg_update_%d", time.Now().UnixNano())
	}

	h.logger.Info("Starting package update stream",
		"stream_id", streamID,
		"update_all", request.UpdateAll,
		"packages", request.PackageNames)

	h.streamsMutex.Lock()
	if existing, exists := h.activeStreams[streamID]; exists {
		h.logger.Info("Stopping existing stream", "stream_id", streamID)
		existing.cancel()
		delete(h.activeStreams, streamID)
	}
	h.streamsMutex.Unlock()

	streamCtx, cancel := context.WithCancel(context.Background())
	stream := &packageUpdateStream{
		streamID:  streamID,
		cancel:    cancel,
		startTime: time.Now(),
	}

	h.streamsMutex.Lock()
	h.activeStreams[streamID] = stream
	h.streamsMutex.Unlock()

	go h.streamPackageUpdate(streamCtx, request, streamID)

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":    "Package update streaming started",
			"stream_id":  streamID,
			"start_time": stream.startTime,
		},
	}, nil
}

// StopPackageUpdateStream terminates an active streaming session by ID.
func (h *ServerHandler) StopPackageUpdateStream(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request struct {
		StreamID string `json:"stream_id"`
	}

	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid request format: " + err.Error(),
		}, nil
	}

	if request.StreamID == "" {
		return &types.CommandResponse{
			Success: false,
			Error:   "stream_id is required",
		}, nil
	}

	h.logger.Info("Stopping package update stream", "stream_id", request.StreamID)

	stopped := h.stopStream(request.StreamID)
	if !stopped {
		h.logger.Info("Package update stream already stopped", "stream_id", request.StreamID)
		return &types.CommandResponse{
			Success: true,
			Data: map[string]interface{}{
				"message":   "Package update stream already stopped",
				"stream_id": request.StreamID,
			},
		}, nil
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":   "Package update stream stopped",
			"stream_id": request.StreamID,
		},
	}, nil
}

// Restart triggers a system restart through the system service.
func (h *ServerHandler) Restart(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Restarting server")

	systemService := h.services.GetSystemService()
	if systemService == nil {
		h.logger.Error("System service not available")
		return &types.CommandResponse{
			Success: false,
			Error:   "system service not available",
		}, nil
	}

	if err := systemService.RestartServer(ctx); err != nil {
		h.logger.Error("Failed to restart server", "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   "failed to restart server: " + err.Error(),
		}, nil
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "Server restart initiated",
			"success": true,
		},
	}, nil
}

func (h *ServerHandler) streamPackageUpdate(ctx context.Context, request packageUpdateRequest, streamID string) {
	defer func() {
		h.streamsMutex.Lock()
		delete(h.activeStreams, streamID)
		h.streamsMutex.Unlock()
		h.logger.Info("Package update stream ended", "stream_id", streamID)
	}()

	h.logger.Info("Package update stream established", "stream_id", streamID)

	outputChan := make(chan types.PackageLogMessage, 100)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case logMsg, ok := <-outputChan:
				if !ok {
					return
				}
				h.sendPackageLogMessage(streamID, logMsg)
			}
		}
	}()

	packageService := h.services.GetPackageService()
	if packageService == nil {
		h.sendLogMessage(streamID, "Package service not available", "error")
		close(outputChan)
		return
	}

	var (
		result *types.PackageUpdateResult
		err    error
	)

	if request.UpdateAll {
		h.logger.Info("Updating all packages with streaming", "stream_id", streamID)
		result, err = packageService.UpdateAllPackagesStream(ctx, outputChan)
	} else {
		h.logger.Info("Updating specific packages with streaming",
			"stream_id", streamID,
			"packages", request.PackageNames)
		result, err = packageService.UpdatePackagesStream(ctx, request.PackageNames, outputChan)
	}

	close(outputChan)

	if err != nil {
		h.logger.Error("Package update failed", "stream_id", streamID, "error", err)
		h.sendLogMessage(streamID, fmt.Sprintf("Package update failed: %v", err), "error")
		return
	}

	if result == nil {
		h.sendLogMessage(streamID, "Package update completed with no result", "warn")
		return
	}

	if result.Success {
		h.sendLogMessage(streamID, result.Message, "info")
	} else {
		h.sendLogMessage(streamID, result.Message, "error")
	}

	h.sendUpdateResult(streamID, result)
}

func (h *ServerHandler) sendPackageLogMessage(streamID string, logMsg types.PackageLogMessage) {
	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil {
		h.logger.Warn("WebSocket manager not available")
		return
	}

	logData := map[string]interface{}{
		"stream_id": streamID,
		"message":   logMsg.Message,
		"level":     logMsg.Level,
		"timestamp": logMsg.Timestamp,
		"type":      "package_log",
	}

	if err := wsManager.Emit("package_update_log", logData); err != nil {
		h.logger.Error("Failed to send package log message", "error", err)
	}
}

func (h *ServerHandler) sendLogMessage(streamID, message, level string) {
	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil {
		h.logger.Warn("WebSocket manager not available")
		return
	}

	logData := map[string]interface{}{
		"stream_id": streamID,
		"message":   message,
		"level":     level,
		"timestamp": time.Now().Unix(),
		"type":      "package_log",
	}

	if err := wsManager.Emit("package_update_log", logData); err != nil {
		h.logger.Error("Failed to send log message", "error", err)
	}
}

func (h *ServerHandler) sendUpdateResult(streamID string, result *types.PackageUpdateResult) {
	wsManager := h.services.GetWebSocketManager()
	if wsManager == nil {
		h.logger.Warn("WebSocket manager not available")
		return
	}

	resultData := map[string]interface{}{
		"stream_id":        streamID,
		"type":             "package_update_result",
		"success":          result.Success,
		"message":          result.Message,
		"updated_packages": result.UpdatedPackages,
		"failed_packages":  result.FailedPackages,
		"errors":           result.Errors,
		"timestamp":        time.Now().Unix(),
	}

	if err := wsManager.Emit("package_update_result", resultData); err != nil {
		h.logger.Error("Failed to send update result", "error", err)
	}
}

func (h *ServerHandler) stopStream(streamID string) bool {
	h.streamsMutex.Lock()
	defer h.streamsMutex.Unlock()

	if stream, exists := h.activeStreams[streamID]; exists {
		h.logger.Info("Stopping package update stream", "stream_id", streamID)
		stream.cancel()
		delete(h.activeStreams, streamID)
		return true
	}

	return false
}

// StopAllStreams halts every active package update stream. Useful for shutdown hooks and tests.
func (h *ServerHandler) StopAllStreams() {
	h.streamsMutex.Lock()
	defer h.streamsMutex.Unlock()

	for streamID, stream := range h.activeStreams {
		h.logger.Info("Stopping package update stream", "stream_id", streamID)
		stream.cancel()
	}

	h.activeStreams = make(map[string]*packageUpdateStream)
}

// ActiveStreams lists current stream identifiers. Intended for diagnostics and tests.
func (h *ServerHandler) ActiveStreams() []string {
	h.streamsMutex.RLock()
	defer h.streamsMutex.RUnlock()

	streams := make([]string, 0, len(h.activeStreams))
	for streamID := range h.activeStreams {
		streams = append(streams, streamID)
	}

	return streams
}
