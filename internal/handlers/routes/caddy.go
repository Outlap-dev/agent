package routes

import (
	"outlap-agent-go/internal/handlers"
	"outlap-agent-go/pkg/logger"
)

// RegisterCaddyRoutes registers Caddy-related command handlers
func RegisterCaddyRoutes(router *Router, handlerLogger *logger.Logger, services handlers.ServiceProvider) {
	if router == nil || handlerLogger == nil || services == nil {
		return
	}

	base := handlers.NewBaseHandler(handlerLogger, services)
	caddyHandler := handlers.NewCaddyHandler(base, services.GetCaddyService())

	// Register Caddy commands
	router.Group("caddy").
		Route("install").Handler(handlers.NewMethodHandler(base, caddyHandler.InstallCaddy))
}
