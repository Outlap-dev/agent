package logpaths

import (
	"fmt"
	"os"
	"path/filepath"
)

const defaultDeploymentLogsDir = "/var/log/pulseup/deployments"

// ResolveDeploymentLogsDir returns the base directory where deployment logs are stored.
// It mirrors the logic used by deployment services to persist build and deployment logs
// so that auxiliary components (streamers, fetch handlers, etc.) can share a consistent
// view of the filesystem layout.
func ResolveDeploymentLogsDir() string {
	logsDir := defaultDeploymentLogsDir

	if os.Getenv("DEBUG") == "true" {
		if debugDir := os.Getenv("DEBUG_LOG_DIR"); debugDir != "" {
			return filepath.Join(debugDir, "deployments")
		}
	}

	return logsDir
}

// DeploymentLogPath returns the absolute path for a deployment-scoped log file of the
// given type (e.g. "build", "deploy").
func DeploymentLogPath(deploymentUID, logType string) string {
	if deploymentUID == "" || logType == "" {
		return ""
	}
	return filepath.Join(ResolveDeploymentLogsDir(), fmt.Sprintf("%s_%s.log", deploymentUID, logType))
}

// ServiceDeploymentLogPath returns the absolute path for a service-scoped log file of the
// given type. Some log writers persist duplicates keyed by service UID for convenience.
func ServiceDeploymentLogPath(serviceUID, logType string) string {
	if serviceUID == "" || logType == "" {
		return ""
	}
	return filepath.Join(ResolveDeploymentLogsDir(), fmt.Sprintf("%s_%s.log", serviceUID, logType))
}

// DeploymentStepsPath returns the path to the JSON file that tracks structured deployment
// steps metadata for a given deployment.
func DeploymentStepsPath(deploymentUID string) string {
	if deploymentUID == "" {
		return ""
	}
	return filepath.Join(ResolveDeploymentLogsDir(), fmt.Sprintf("%s_steps.json", deploymentUID))
}
