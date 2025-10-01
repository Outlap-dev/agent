package routes

import (
	"pulseup-agent-go/internal/handlers"
	"pulseup-agent-go/pkg/logger"
)

// RegisterServerRoutes wires server and package management commands into the registry.
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
			Handle("stats.live", serverHandler.LiveStats).
			Handle("restart", serverHandler.Restart)
	}

	packages := router.Group("packages")
	{
		packages.Controller("upgradable", serverHandler).
			Handle("list", serverHandler.ListUpgradablePackages)

		packages.Controller("update", serverHandler).
			Handle("run", serverHandler.UpdatePackages).
			Handle("stream.start", serverHandler.StartPackageUpdateStream).
			Handle("stream.stop", serverHandler.StopPackageUpdateStream)
	}
}
