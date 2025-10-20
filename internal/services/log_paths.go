package services

import "pulseup-agent-go/internal/shared/logpaths"

// ResolveDeploymentLogsDir exposes the shared deployment logs directory helper for
// existing service consumers while allowing other packages to import the logic without
// creating circular dependencies.
func ResolveDeploymentLogsDir() string {
	return logpaths.ResolveDeploymentLogsDir()
}

// DeploymentLogPath proxies to the shared deployment log path helper.
func DeploymentLogPath(deploymentUID, logType string) string {
	return logpaths.DeploymentLogPath(deploymentUID, logType)
}

// ServiceDeploymentLogPath proxies to the shared service deployment log path helper.
func ServiceDeploymentLogPath(serviceUID, logType string) string {
	return logpaths.ServiceDeploymentLogPath(serviceUID, logType)
}

// DeploymentStepsPath proxies to the shared deployment steps path helper.
func DeploymentStepsPath(deploymentUID string) string {
	return logpaths.DeploymentStepsPath(deploymentUID)
}
