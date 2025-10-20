package handlers

import (
	"context"
	"encoding/json"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// ServerHandler aggregates server-centric commands such as live stats.
type ServerHandler struct {
	*BaseHandler
}

// NewServerHandler constructs a ServerHandler that can service multiple commands.
func NewServerHandler(logger *logger.Logger, services ServiceProvider) *ServerHandler {
	return &ServerHandler{
		BaseHandler: NewBaseHandler(logger.With("controller", "server"), services),
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
