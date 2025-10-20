package handlers

import (
	"context"
	"encoding/json"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// MonitoringHandler aggregates monitoring-related command handlers (status, metrics, alerts, lifecycle).
type MonitoringHandler struct {
	*BaseHandler
}

// NewMonitoringHandler constructs a monitoring controller backed by the provided services.
func NewMonitoringHandler(logger *logger.Logger, services ServiceProvider) *MonitoringHandler {
	return &MonitoringHandler{
		BaseHandler: NewBaseHandler(logger.With("controller", "monitoring"), services),
	}
}

// Base exposes the embedded base handler for the router helpers.
func (h *MonitoringHandler) Base() *BaseHandler {
	return h.BaseHandler
}

func (h *MonitoringHandler) Status(ctx context.Context, _ json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Getting monitoring status")

	monitoringService := h.services.GetMonitoringService()
	if monitoringService == nil {
		return &types.CommandResponse{Success: false, Error: "monitoring service not available"}, nil
	}

	status, err := monitoringService.GetMonitoringStatus(ctx)
	if err != nil {
		h.logger.Error("Failed to get monitoring status", "error", err)
		return &types.CommandResponse{Success: false, Error: err.Error()}, nil
	}

	return &types.CommandResponse{Success: true, Data: status}, nil
}

func (h *MonitoringHandler) ContainerMetrics(ctx context.Context, _ json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Getting container metrics")

	monitoringService := h.services.GetMonitoringService()
	if monitoringService == nil {
		return &types.CommandResponse{Success: false, Error: "monitoring service not available"}, nil
	}

	metrics, err := monitoringService.GetContainerMetrics(ctx)
	if err != nil {
		h.logger.Error("Failed to get container metrics", "error", err)
		return &types.CommandResponse{Success: false, Error: err.Error()}, nil
	}

	return &types.CommandResponse{Success: true, Data: metrics}, nil
}

// SetupAlertsRequest represents the request for configuring alert rules.
type SetupAlertsRequest struct {
	Rules []types.AlertRule `json:"rules"`
}

func (h *MonitoringHandler) SetupAlerts(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var request SetupAlertsRequest
	if len(data) > 0 {
		if err := json.Unmarshal(data, &request); err != nil {
			h.logger.Error("Failed to unmarshal setup alerts request", "error", err)
			return &types.CommandResponse{Success: false, Error: "invalid request format"}, nil
		}
	}

	h.logger.Info("Setting up monitoring alerts", "rules_count", len(request.Rules))

	monitoringService := h.services.GetMonitoringService()
	if monitoringService == nil {
		return &types.CommandResponse{Success: false, Error: "monitoring service not available"}, nil
	}

	if err := monitoringService.SetupAlerts(ctx, request.Rules); err != nil {
		h.logger.Error("Failed to setup alerts", "error", err)
		return &types.CommandResponse{Success: false, Error: err.Error()}, nil
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message":    "alerts configured successfully",
			"rule_count": len(request.Rules),
		},
	}, nil
}

func (h *MonitoringHandler) Start(ctx context.Context, _ json.RawMessage) (*types.CommandResponse, error) {
	monitoringService := h.services.GetMonitoringService()
	if monitoringService == nil {
		return &types.CommandResponse{Success: false, Error: "monitoring service not available"}, nil
	}

	if err := monitoringService.StartMetricsCollection(ctx); err != nil {
		h.logger.Error("Failed to start monitoring", "error", err)
		return &types.CommandResponse{Success: false, Error: err.Error()}, nil
	}

	return &types.CommandResponse{Success: true, Data: map[string]interface{}{"message": "monitoring started successfully"}}, nil
}

func (h *MonitoringHandler) Stop(ctx context.Context, _ json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Stopping monitoring collection")

	monitoringService := h.services.GetMonitoringService()
	if monitoringService == nil {
		return &types.CommandResponse{Success: false, Error: "monitoring service not available"}, nil
	}

	if err := monitoringService.StopMetricsCollection(ctx); err != nil {
		h.logger.Error("Failed to stop monitoring", "error", err)
		return &types.CommandResponse{Success: false, Error: err.Error()}, nil
	}

	return &types.CommandResponse{Success: true, Data: map[string]interface{}{"message": "monitoring stopped successfully"}}, nil
}
