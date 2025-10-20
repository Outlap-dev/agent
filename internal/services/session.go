package services

import (
	"context"
	"sync"

	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

type AgentSession struct {
	mu            sync.Mutex
	cfg           *config.Config
	updateService UpdateService
	logger        *logger.Logger

	ctx                context.Context
	autoUpdatesEnabled bool
	updateLoopActive   bool
	latestKnownVersion string
}

func NewAgentSession(cfg *config.Config, updateService UpdateService, baseLogger *logger.Logger) *AgentSession {
	if cfg == nil || updateService == nil || baseLogger == nil {
		return nil
	}

	return &AgentSession{
		cfg:                cfg,
		updateService:      updateService,
		logger:             baseLogger.With("component", "agent_session"),
		autoUpdatesEnabled: cfg.UpdateEnabled,
	}
}

func (s *AgentSession) SetContext(ctx context.Context) {
	if s == nil {
		return
	}

	s.mu.Lock()
	s.ctx = ctx
	shouldStart := s.autoUpdatesEnabled && !s.updateLoopActive
	s.mu.Unlock()

	if shouldStart {
		s.startUpdateLoop()
	}
}

func (s *AgentSession) ApplyConfig(payload types.AgentConfigPayload) {
	if s == nil {
		return
	}

	s.mu.Lock()
	previousEnabled := s.autoUpdatesEnabled
	s.autoUpdatesEnabled = payload.AutoUpdatesEnabled
	s.latestKnownVersion = payload.LatestVersion

	if s.cfg != nil {
		s.cfg.UpdateEnabled = payload.AutoUpdatesEnabled
		s.cfg.UpdateAutoApply = payload.AutoUpdatesEnabled
	}

	shouldStart := s.autoUpdatesEnabled && !s.updateLoopActive
	shouldStop := !s.autoUpdatesEnabled && s.updateLoopActive
	s.mu.Unlock()

	if shouldStart {
		s.startUpdateLoop()
	} else if shouldStop {
		s.stopUpdateLoop()
	}

	if previousEnabled != s.autoUpdatesEnabled {
		s.logger.Info("Auto-update configuration updated", "enabled", s.autoUpdatesEnabled)
	}
}

func (s *AgentSession) startUpdateLoop() {
	s.mu.Lock()
	if s == nil || s.updateService == nil {
		s.mu.Unlock()
		return
	}

	ctx := s.ctx
	if ctx == nil {
		if !s.updateLoopActive {
			s.logger.Warn("Auto-update enabled but runtime context unavailable; will start when context is set")
		}
		s.mu.Unlock()
		return
	}

	if s.updateLoopActive {
		s.mu.Unlock()
		return
	}

	s.mu.Unlock()

	if err := s.updateService.StartAutoUpdateLoop(ctx); err != nil {
		s.logger.Error("Failed to start auto-update loop", "error", err)
		return
	}

	s.mu.Lock()
	s.updateLoopActive = true
	s.mu.Unlock()

	s.logger.Debug("Auto-update loop started")
}

func (s *AgentSession) stopUpdateLoop() {
	s.mu.Lock()
	if s == nil || s.updateService == nil || !s.updateLoopActive {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if err := s.updateService.StopAutoUpdateLoop(); err != nil {
		s.logger.Error("Failed to stop auto-update loop", "error", err)
		return
	}

	s.mu.Lock()
	s.updateLoopActive = false
	s.mu.Unlock()

	s.logger.Debug("Auto-update loop stopped")
}
