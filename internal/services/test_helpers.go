package services

import (
	outlaptypes "outlap-agent-go/pkg/types"
)

// serviceStatusUpdate represents a service status update captured during testing
type serviceStatusUpdate struct {
	serviceUID   string
	status       outlaptypes.ServiceStatus
	errorMessage string
}
