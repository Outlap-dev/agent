package routes

import (
	"outlap-agent-go/internal/handlers"
	"outlap-agent-go/pkg/logger"
)

// RegisterAgentRoutes wires agent-related commands (logs, hardware info, uninstall) into the registry.
func RegisterAgentRoutes(router *Router, handlerLogger *logger.Logger, services handlers.ServiceProvider) {
	if router == nil || handlerLogger == nil || services == nil {
		if router != nil {
			router.logger.Warn("skipping agent routes registration due to missing dependencies")
		}
		return
	}

	agentHandler := handlers.NewAgentHandler(handlerLogger, services)
	commandHandler := handlers.NewCommandHandler(handlerLogger, services)
	updateHandler := handlers.NewUpdateHandler(handlerLogger, services)

	agent := router.Group("agent")
	{
		agent.Controller("logs", agentHandler).
			Handle("fetch", agentHandler.FetchLogs)

		agent.Controller("hardware", agentHandler).
			Handle("info", agentHandler.HardwareInfo)

		agent.Controller("", agentHandler).
			Handle("uninstall", agentHandler.Uninstall)

		agent.Controller("command", commandHandler).
			Handle("execute", commandHandler.Execute).
			Handle("list", commandHandler.List)

		agent.Controller("update", updateHandler).
			Handle("check", updateHandler.Check).
			Handle("apply", updateHandler.Apply)
	}
}
