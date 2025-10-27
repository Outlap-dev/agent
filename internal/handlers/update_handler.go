package handlers

import (
	"context"
	"encoding/json"

	"outlap-agent-go/internal/update"
	"outlap-agent-go/pkg/logger"
	"outlap-agent-go/pkg/types"
)

// UpdateHandler aggregates agent update commands (check/apply).
type UpdateHandler struct {
	*BaseHandler
}

// NewUpdateHandler constructs an update controller backed by the provided services.
func NewUpdateHandler(logger *logger.Logger, services ServiceProvider) *UpdateHandler {
	return &UpdateHandler{
		BaseHandler: NewBaseHandler(logger.With("controller", "agent.update"), services),
	}
}

// Base exposes the embedded base handler for router helpers.
func (h *UpdateHandler) Base() *BaseHandler {
	return h.BaseHandler
}

// Check queries for available agent updates.
func (h *UpdateHandler) Check(ctx context.Context, _ json.RawMessage) (*types.CommandResponse, error) {
	h.logger.Info("Checking for agent updates")

	updateService := h.services.GetUpdateService()
	if updateService == nil {
		return &types.CommandResponse{Success: false, Error: "Update service not available"}, nil
	}

	metadata, err := updateService.CheckForUpdate(ctx)
	if err != nil {
		h.logger.Error("Update check failed", "error", err)
		return &types.CommandResponse{Success: false, Error: "Failed to check for updates: " + err.Error()}, nil
	}

	responseData := map[string]interface{}{
		"current_version":  update.GetCurrentVersion().String(),
		"update_available": metadata != nil,
	}

	if metadata != nil {
		responseData["latest_version"] = metadata.Version
		responseData["download_url"] = metadata.DownloadURL
		responseData["changelog"] = metadata.Changelog
		responseData["signed_at"] = metadata.SignedAt
		responseData["checksum"] = metadata.SHA256
		responseData["signature"] = metadata.Signature
		responseData["checksum_manifest"] = metadata.ChecksumManifest
		if metadata.ReleaseURL != "" {
			responseData["release_url"] = metadata.ReleaseURL
		}
	}

	return &types.CommandResponse{Success: true, Data: responseData}, nil
}

// ApplyUpdateRequest captures request fields for forcing a particular update version.
type ApplyUpdateRequest struct {
	Version string `json:"version"`
	Force   bool   `json:"force"`
}

// Apply downloads, validates, and applies the latest (or requested) agent update.
func (h *UpdateHandler) Apply(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	var req ApplyUpdateRequest
	if len(data) > 0 {
		if err := json.Unmarshal(data, &req); err != nil {
			// keep zero-value request when parsing fails and continue with best effort behaviour
			h.logger.Warn("Invalid apply update payload, proceeding with defaults", "error", err)
		}
	}

	h.logger.Info("Applying agent update", "version", req.Version, "force", req.Force)

	updateService := h.services.GetUpdateService()
	if updateService == nil {
		return &types.CommandResponse{Success: false, Error: "Update service not available"}, nil
	}

	metadata, err := updateService.CheckForUpdate(ctx)
	if err != nil {
		h.logger.Error("Update check failed", "error", err)
		return &types.CommandResponse{Success: false, Error: "Failed to check for updates: " + err.Error()}, nil
	}

	if metadata == nil {
		return &types.CommandResponse{
			Success: true,
			Data:    map[string]interface{}{"message": "No updates available"},
		}, nil
	}

	if req.Version != "" && metadata.Version != req.Version {
		if !req.Force {
			return &types.CommandResponse{Success: false, Error: "Requested version " + req.Version + " does not match available version " + metadata.Version}, nil
		}
		h.logger.Warn("Forced update version differs from available metadata", "requested", req.Version, "available", metadata.Version)
	}

	applyOpts := &types.UpdateApplyOptions{VersionOverride: req.Version, Force: req.Force}
	if err := updateService.ApplyUpdate(ctx, metadata, applyOpts); err != nil {
		h.logger.Error("Failed to apply update", "error", err)
		return &types.CommandResponse{Success: false, Error: "Failed to apply update: " + err.Error()}, nil
	}

	return &types.CommandResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "Update applied successfully. Agent will restart.",
			"version": metadata.Version,
		},
	}, nil
}
