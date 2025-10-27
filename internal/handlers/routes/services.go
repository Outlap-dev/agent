package routes

import (
	"outlap-agent-go/internal/handlers"
	"outlap-agent-go/pkg/logger"
)

// RegisterServiceRoutes registers all service-related command handlers.
// Uses an Echo-style fluent API for clean, hierarchical route organization.
func RegisterServiceRoutes(router *Router, logger *logger.Logger, services handlers.ServiceProvider) {
	if services == nil {
		router.logger.Warn("skipping service routes registration due to missing service provider")
		return
	}

	// Create the main service group
	service := router.Group("service")
	{
		// Application deployment routes
		deployApp := handlers.NewDeployApplicationHandler(logger, services)
		service.Controller("app", deployApp).
			Handle("deploy", deployApp.Deploy)

		installApp := handlers.NewAppInstallationHandler(logger, services)
		service.Controller("app", installApp).
			Handle("install", installApp.Install)

		// Deployment management routes
		rollback := handlers.NewAppDeploymentRollbackHandler(logger, services)
		service.Controller("deploy", rollback).
			Handle("rollback", rollback.Rollback)

		deploymentLogs := handlers.NewDeploymentLogsHandler(logger, services)
		service.Controller("deploy", deploymentLogs).
			Handle("logs.fetch", deploymentLogs.Fetch)

		deploymentLogStream := handlers.NewDeploymentLogStreamHandler(logger, services)
		service.Controller("deploy", deploymentLogStream).
			Handle("logs.stream.start", deploymentLogStream.StreamStart).
			Handle("logs.stream.stop", deploymentLogStream.StreamStop)

		// Log management routes - single handler with multiple methods
		logsHandler := handlers.NewServiceLogsHandler(logger, services)
		service.Controller("logs", logsHandler).
			Handle("fetch", logsHandler.Fetch).
			Handle("stream.start", logsHandler.StreamStart).
			Handle("stream.stop", logsHandler.StreamStop)

		// Container monitoring routes
		containerStats := handlers.NewContainerStatsHandler(logger, services)
		service.Controller("container", containerStats).
			Handle("stats.live", containerStats.Fetch)

		domainHandler := handlers.NewDomainHandler(logger, services)
		service.Controller("", domainHandler).
			Handle("domain.manage", domainHandler.Manage)

		// Service lifecycle routes - single handler with multiple methods
		lifecycleHandler := handlers.NewServiceLifecycleHandler(logger, services)
		service.Controller("", lifecycleHandler).
			Handle("start", lifecycleHandler.Start).
			Handle("stop", lifecycleHandler.Stop).
			Handle("restart", lifecycleHandler.Restart).
			Handle("delete", lifecycleHandler.Delete)

		statusHandler := handlers.NewServiceStatusHandler(logger, services)
		service.Controller("", statusHandler).
			Handle("status.get", statusHandler.Get)
	}
}
