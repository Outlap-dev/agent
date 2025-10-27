package routes

import (
	"outlap-agent-go/internal/handlers"
	"outlap-agent-go/pkg/logger"
)

// RegisterServerRoutes wires server commands into the registry.
func RegisterServerRoutes(router *Router, handlerLogger *logger.Logger, services handlers.ServiceProvider) {
	if router == nil || handlerLogger == nil || services == nil {
		if router != nil {
			router.logger.Warn("skipping server routes registration due to missing dependencies")
		}
		return
	}

	serverHandler := handlers.NewServerHandler(handlerLogger, services)

	server := router.Group("server")
	{
		server.Controller("", serverHandler).
			Handle("stats.live", serverHandler.LiveStats)
	}
}
