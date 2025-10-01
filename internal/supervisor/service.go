// Package supervisor provides privileged service management operations
package supervisor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"pulseup-agent-go/internal/ipc"
	"pulseup-agent-go/pkg/logger"
)

// ServiceManager handles privileged system service operations
type ServiceManager struct {
	logger *logger.Logger
}

// NewServiceManager creates a new service manager
func NewServiceManager(logger *logger.Logger) *ServiceManager {
	return &ServiceManager{
		logger: logger.With("service", "service_manager"),
	}
}

// RestartService restarts a system service
func (sm *ServiceManager) RestartService(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	serviceName, ok := args["service_name"].(string)
	if !ok || serviceName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "service_name is required",
		}, nil
	}

	if err := sm.validateServiceName(serviceName); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid service name: %v", err),
		}, nil
	}

	sm.logger.Info("Restarting service", "service", serviceName)

	// Execute systemctl restart command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "systemctl", "restart", serviceName)
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Error("Failed to restart service", "service", serviceName, "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to restart service: %v", err),
			Data: map[string]interface{}{
				"service": serviceName,
				"output":  string(output),
			},
		}, nil
	}

	sm.logger.Info("Service restarted successfully", "service", serviceName)
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Service '%s' restarted successfully", serviceName),
			"service": serviceName,
			"output":  string(output),
		},
	}, nil
}

// StartService starts a system service
func (sm *ServiceManager) StartService(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	serviceName, ok := args["service_name"].(string)
	if !ok || serviceName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "service_name is required",
		}, nil
	}

	if err := sm.validateServiceName(serviceName); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid service name: %v", err),
		}, nil
	}

	sm.logger.Info("Starting service", "service", serviceName)

	// Execute systemctl start command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "systemctl", "start", serviceName)
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Error("Failed to start service", "service", serviceName, "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to start service: %v", err),
			Data: map[string]interface{}{
				"service": serviceName,
				"output":  string(output),
			},
		}, nil
	}

	sm.logger.Info("Service started successfully", "service", serviceName)
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Service '%s' started successfully", serviceName),
			"service": serviceName,
			"output":  string(output),
		},
	}, nil
}

// StopService stops a system service
func (sm *ServiceManager) StopService(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	serviceName, ok := args["service_name"].(string)
	if !ok || serviceName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "service_name is required",
		}, nil
	}

	if err := sm.validateServiceName(serviceName); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid service name: %v", err),
		}, nil
	}

	sm.logger.Info("Stopping service", "service", serviceName)

	// Execute systemctl stop command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "systemctl", "stop", serviceName)
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Error("Failed to stop service", "service", serviceName, "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to stop service: %v", err),
			Data: map[string]interface{}{
				"service": serviceName,
				"output":  string(output),
			},
		}, nil
	}

	sm.logger.Info("Service stopped successfully", "service", serviceName)
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Service '%s' stopped successfully", serviceName),
			"service": serviceName,
			"output":  string(output),
		},
	}, nil
}

// GetServiceStatus gets the status of a system service
func (sm *ServiceManager) GetServiceStatus(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	serviceName, ok := args["service_name"].(string)
	if !ok || serviceName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "service_name is required",
		}, nil
	}

	if err := sm.validateServiceName(serviceName); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid service name: %v", err),
		}, nil
	}

	sm.logger.Debug("Getting service status", "service", serviceName)

	// Execute systemctl status command
	cmd := exec.CommandContext(ctx, "systemctl", "status", serviceName, "--no-pager")
	output, err := cmd.CombinedOutput()

	// Note: systemctl status returns non-zero exit code for inactive services,
	// but we still want to return the status information
	statusInfo := string(output)

	// Parse the status to determine if service is active
	isActive := strings.Contains(statusInfo, "Active: active")
	isEnabled := !strings.Contains(statusInfo, "disabled")

	// Determine overall status
	var status string
	var success bool
	if isActive {
		status = "active"
		success = true
	} else if strings.Contains(statusInfo, "Active: inactive") {
		status = "inactive"
		success = true
	} else if strings.Contains(statusInfo, "Active: failed") {
		status = "failed"
		success = true
	} else {
		status = "unknown"
		success = false
	}

	if err != nil && !success {
		sm.logger.Warn("Failed to get service status", "service", serviceName, "error", err)
	}

	sm.logger.Debug("Service status retrieved", "service", serviceName, "status", status, "active", isActive, "enabled", isEnabled)

	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"service":     serviceName,
			"status":      status,
			"active":      isActive,
			"enabled":     isEnabled,
			"status_info": statusInfo,
		},
	}, nil
}

// EnableService enables a system service
func (sm *ServiceManager) EnableService(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	serviceName, ok := args["service_name"].(string)
	if !ok || serviceName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "service_name is required",
		}, nil
	}

	if err := sm.validateServiceName(serviceName); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid service name: %v", err),
		}, nil
	}

	sm.logger.Info("Enabling service", "service", serviceName)

	// Execute systemctl enable command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "systemctl", "enable", serviceName)
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Error("Failed to enable service", "service", serviceName, "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to enable service: %v", err),
			Data: map[string]interface{}{
				"service": serviceName,
				"output":  string(output),
			},
		}, nil
	}

	sm.logger.Info("Service enabled successfully", "service", serviceName)
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Service '%s' enabled successfully", serviceName),
			"service": serviceName,
			"output":  string(output),
		},
	}, nil
}

// DisableService disables a system service
func (sm *ServiceManager) DisableService(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	serviceName, ok := args["service_name"].(string)
	if !ok || serviceName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "service_name is required",
		}, nil
	}

	if err := sm.validateServiceName(serviceName); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid service name: %v", err),
		}, nil
	}

	sm.logger.Info("Disabling service", "service", serviceName)

	// Execute systemctl disable command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "systemctl", "disable", serviceName)
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Error("Failed to disable service", "service", serviceName, "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to disable service: %v", err),
			Data: map[string]interface{}{
				"service": serviceName,
				"output":  string(output),
			},
		}, nil
	}

	sm.logger.Info("Service disabled successfully", "service", serviceName)
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": fmt.Sprintf("Service '%s' disabled successfully", serviceName),
			"service": serviceName,
			"output":  string(output),
		},
	}, nil
}

// ReloadSystemd reloads systemd daemon configuration
func (sm *ServiceManager) ReloadSystemd(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	sm.logger.Info("Reloading systemd daemon")

	// Execute systemctl daemon-reload command (supervisor already runs as root)
	cmd := exec.CommandContext(ctx, "systemctl", "daemon-reload")
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Error("Failed to reload systemd daemon", "error", err, "output", string(output))
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to reload systemd daemon: %v", err),
			Data: map[string]interface{}{
				"output": string(output),
			},
		}, nil
	}

	sm.logger.Info("Systemd daemon reloaded successfully")
	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"message": "Systemd daemon reloaded successfully",
			"output":  string(output),
		},
	}, nil
}

// GetServiceLogs gets logs for a system service
func (sm *ServiceManager) GetServiceLogs(ctx context.Context, args map[string]interface{}) (*ipc.PrivilegedResponse, error) {
	serviceName, ok := args["service_name"].(string)
	if !ok || serviceName == "" {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   "service_name is required",
		}, nil
	}

	if err := sm.validateServiceName(serviceName); err != nil {
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("invalid service name: %v", err),
		}, nil
	}

	sm.logger.Debug("Getting service logs", "service", serviceName)

	// Parse log options
	lines := "100" // Default to last 100 lines
	if linesArg, ok := args["lines"].(string); ok {
		lines = linesArg
	}

	follow := false
	if followArg, ok := args["follow"].(bool); ok {
		follow = followArg
	}

	// Build journalctl command
	cmdArgs := []string{"journalctl", "-u", serviceName, "--no-pager", "-n", lines}
	if follow {
		cmdArgs = append(cmdArgs, "-f")
	}

	// Execute journalctl command
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		sm.logger.Error("Failed to get service logs", "service", serviceName, "error", err)
		return &ipc.PrivilegedResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to get service logs: %v", err),
		}, nil
	}

	logs := string(output)
	sm.logger.Debug("Service logs retrieved", "service", serviceName, "size", len(logs))

	return &ipc.PrivilegedResponse{
		Success: true,
		Data: map[string]interface{}{
			"service": serviceName,
			"logs":    logs,
			"lines":   lines,
			"follow":  follow,
		},
	}, nil
}

// validateServiceName validates a service name for security
func (sm *ServiceManager) validateServiceName(name string) error {
	// Remove .service suffix if present for validation
	cleanName := strings.TrimSuffix(name, ".service")

	// Basic validation to prevent command injection
	if strings.ContainsAny(cleanName, ";|&$`(){}[]<>") {
		return fmt.Errorf("invalid characters in service name: %s", name)
	}

	if len(cleanName) == 0 {
		return fmt.Errorf("empty service name")
	}

	if len(cleanName) > 64 {
		return fmt.Errorf("service name too long: %d characters", len(cleanName))
	}

	// Whitelist of allowed services (extend as needed)
	allowedServices := map[string]bool{
		"docker":             true,
		"caddy":              true,
		"nginx":              true,
		"apache2":            true,
		"httpd":              true,
		"mysql":              true,
		"mariadb":            true,
		"postgresql":         true,
		"postgres":           true,
		"redis":              true,
		"redis-server":       true,
		"mongodb":            true,
		"mongod":             true,
		"elasticsearch":      true,
		"kibana":             true,
		"logstash":           true,
		"prometheus":         true,
		"grafana":            true,
		"node_exporter":      true,
		"pulseup-agent":      true,
		"pulseup-supervisor": true,
		"pulseup-worker":     true,
		"ssh":                true,
		"sshd":               true,
		"fail2ban":           true,
		"ufw":                true,
		"iptables":           true,
		"cron":               true,
		"crontab":            true,
		"rsyslog":            true,
		"systemd-resolved":   true,
		"systemd-networkd":   true,
		"NetworkManager":     true,
		"dnsmasq":            true,
		"chrony":             true,
		"ntp":                true,
		"snapd":              true,
		"containerd":         true,
		"kubelet":            true,
		"k3s":                true,
		"k3s-agent":          true,
		"haproxy":            true,
		"traefik":            true,
		"certbot":            true,
	}

	if !allowedServices[cleanName] {
		return fmt.Errorf("service not in allowlist: %s", cleanName)
	}

	return nil
}

// isSystemdAvailable checks if systemd is available on the system
func (sm *ServiceManager) isSystemdAvailable() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}