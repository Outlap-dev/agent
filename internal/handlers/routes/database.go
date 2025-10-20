package routes

import (
	"os"
	"strings"

	"pulseup-agent-go/internal/handlers"
	"pulseup-agent-go/pkg/logger"
)

// DatabaseRouteConfig allows callers to customize database route registration.
// APIBaseURL is optional; when omitted, the handler will fall back to
// environment defaults where possible.
type DatabaseRouteConfig struct {
	APIBaseURL string
}

func defaultAPIBaseURL() string {
	if api := strings.TrimRight(strings.TrimSpace(os.Getenv("API_BASE_URL")), "/"); api != "" {
		return api
	}

	wsURL := strings.TrimSpace(os.Getenv("WEBSOCKET_URL"))
	if wsURL == "" {
		return ""
	}

	converted := strings.Replace(wsURL, "wss://", "https://", 1)
	converted = strings.Replace(converted, "ws://", "http://", 1)
	if idx := strings.Index(converted, "/ws/"); idx != -1 {
		converted = converted[:idx]
	}

	return strings.TrimRight(converted, "/")
}

func sanitizeDatabaseConfig(cfg *DatabaseRouteConfig) *DatabaseRouteConfig {
	if cfg == nil {
		cfg = &DatabaseRouteConfig{}
	}

	if trimmed := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/"); trimmed != "" {
		cfg.APIBaseURL = trimmed
	} else {
		cfg.APIBaseURL = defaultAPIBaseURL()
	}

	return cfg
}

// RegisterDatabaseRoutes wires database-related controller methods into the registry.
func RegisterDatabaseRoutes(router *Router, handlerLogger *logger.Logger, services handlers.ServiceProvider, cfg *DatabaseRouteConfig) {
	if router == nil || handlerLogger == nil || services == nil {
		if router != nil {
			router.logger.Warn("skipping database routes registration due to missing dependencies")
		}
		return
	}

	sanitized := sanitizeDatabaseConfig(cfg)
	controller := handlers.NewDatabaseHandler(handlerLogger, services, sanitized.APIBaseURL)

	database := router.Group("database")
	{
		database.Controller("", controller).
			Handle("deploy", controller.Deploy)

		database.Controller("logs", controller).
			Handle("fetch", controller.Logs)

		backups := database.Group("backup")
		{
			backups.Controller("", controller).
				Handle("create", controller.Backup).
				Handle("list", controller.ListBackups).
				Handle("restore", controller.Restore).
				Handle("download", controller.DownloadBackup)

			backups.Controller("automation", controller).
				Handle("update", controller.UpdateAutomation)

			backups.Controller("storage", controller).
				Handle("verify", controller.VerifyAutomationPath)
		}
	}
}
