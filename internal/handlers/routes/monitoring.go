package routes

import (
	"pulseup-agent-go/internal/handlers"
	"pulseup-agent-go/pkg/logger"
)

// RegisterMonitoringRoutes wires monitoring-related commands into the registry.
func RegisterMonitoringRoutes(router *Router, handlerLogger *logger.Logger, services handlers.ServiceProvider) {
	if router == nil || handlerLogger == nil || services == nil {
		if router != nil {
			router.logger.Warn("skipping monitoring routes registration due to missing dependencies")
		}
		return
	}

	controller := handlers.NewMonitoringHandler(handlerLogger, services)

	monitoring := router.Group("monitoring")
	{
		monitoring.Controller("", controller).
			Handle("status", controller.Status).
			Handle("start", controller.Start).
			Handle("stop", controller.Stop)

		monitoring.Controller("container", controller).
			Handle("metrics", controller.ContainerMetrics)

		monitoring.Controller("alerts", controller).
			Handle("setup", controller.SetupAlerts)
	}
}
