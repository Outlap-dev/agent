package bootstrap

import (
	"strings"

	"outlap-agent-go/internal/config"
	"outlap-agent-go/internal/handlers"
	"outlap-agent-go/internal/security"
	"outlap-agent-go/internal/websocket"
	wsbootstrap "outlap-agent-go/internal/websocket/bootstrap"
	"outlap-agent-go/pkg/logger"
)

// RuntimeEnvironment captures shared runtime dependencies that multiple services rely on.
type RuntimeEnvironment struct {
	Config            *config.Config
	Logger            *logger.Logger
	CertManager       *security.CertificateManager
	HandlerRegistry   *handlers.Registry
	WebsocketBundle   *wsbootstrap.Bundle
	JoinTokenProvided bool
	JoinTokenPreview  string
}

// NewRuntimeEnvironment constructs the fundamental runtime dependencies used by the agent services.
func NewRuntimeEnvironment(cfg *config.Config, baseLogger *logger.Logger) *RuntimeEnvironment {
	if cfg == nil {
		return nil
	}

	certManager := security.NewCertificateManager(cfg.CertDir, baseLogger)
	handlerRegistry := handlers.NewRegistry(baseLogger)
	mtlsClient := websocket.NewMTLSClient(cfg, certManager, baseLogger)
	wsBundle := wsbootstrap.NewBundle(mtlsClient)

	joinToken := strings.TrimSpace(cfg.JoinToken)
	preview := joinToken
	if len(preview) > 8 {
		preview = preview[:8] + "..."
	}

	return &RuntimeEnvironment{
		Config:            cfg,
		Logger:            baseLogger,
		CertManager:       certManager,
		HandlerRegistry:   handlerRegistry,
		WebsocketBundle:   wsBundle,
		JoinTokenProvided: joinToken != "",
		JoinTokenPreview:  preview,
	}
}

// LogJoinTokenStatus emits a consistent diagnostic message about join token configuration.
func (r *RuntimeEnvironment) LogJoinTokenStatus(log *logger.Logger) {
	if r == nil || r.Config == nil {
		return
	}

	target := log
	if target == nil {
		target = r.Logger
	}
	if target == nil {
		return
	}
}
