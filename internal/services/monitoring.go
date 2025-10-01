package services

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/google/uuid"

	wscontracts "pulseup-agent-go/pkg/contracts/websocket"
	"pulseup-agent-go/pkg/logger"
	pulseuptypes "pulseup-agent-go/pkg/types"
)

// MonitoringServiceImpl implements the MonitoringService interface
type MonitoringServiceImpl struct {
	logger       *logger.Logger
	dockerClient *client.Client
	wsManager    wscontracts.Emitter // WebSocket manager for sending alerts

	// Configuration
	config pulseuptypes.MonitoringConfig

	// State management
	mu               sync.RWMutex
	enabled          bool
	alertRules       map[string]*pulseuptypes.AlertRule
	activeAlerts     map[string]*pulseuptypes.AlertEvent
	logFilters       map[string]*pulseuptypes.LogFilter
	containerMetrics map[string]*pulseuptypes.ContainerMetrics

	// Monitoring controls
	loopCtx        context.Context
	loopCancel     context.CancelFunc
	loopWg         sync.WaitGroup
	startTime      time.Time
	metricsErrors  int
	healthErrors   int
	lastCollection time.Time
}

// NewMonitoringService creates a new monitoring service
func NewMonitoringService(logger *logger.Logger, dockerClient *client.Client) *MonitoringServiceImpl {
	return &MonitoringServiceImpl{
		logger:           logger.With("service", "monitoring"),
		dockerClient:     dockerClient,
		loopCtx:          context.Background(),
		loopCancel:       func() {},
		enabled:          false,
		alertRules:       make(map[string]*pulseuptypes.AlertRule),
		activeAlerts:     make(map[string]*pulseuptypes.AlertEvent),
		logFilters:       make(map[string]*pulseuptypes.LogFilter),
		containerMetrics: make(map[string]*pulseuptypes.ContainerMetrics),
		startTime:        time.Now(),
		config: pulseuptypes.MonitoringConfig{
			MetricsInterval:     30 * time.Second,
			HealthCheckInterval: 60 * time.Second,
			AlertCooldown:       5 * time.Minute,
			LogFilterEnabled:    true,
			ResponseTimeEnabled: true,
		},
	}
}

// SetWebSocketManager sets the WebSocket manager for sending alerts
func (m *MonitoringServiceImpl) SetWebSocketManager(wsManager wscontracts.Emitter) {
	m.wsManager = wsManager
}

// StartMetricsCollection starts the monitoring system
func (m *MonitoringServiceImpl) StartMetricsCollection(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabled {
		return fmt.Errorf("monitoring already started")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	m.logger.Info("Starting monitoring system")
	m.enabled = true
	m.startTime = time.Now()

	loopCtx, loopCancel := context.WithCancel(ctx)
	m.loopCtx = loopCtx
	m.loopCancel = loopCancel

	// Start default alert rules
	m.setupDefaultAlertRules()

	// Start default log filters
	m.setupDefaultLogFilters()

	// Start metrics collection goroutine
	m.loopWg.Add(1)
	go func() {
		defer m.loopWg.Done()
		m.metricsCollectionLoop(loopCtx)
	}()

	// Start health check goroutine
	m.loopWg.Add(1)
	go func() {
		defer m.loopWg.Done()
		m.healthCheckLoop(loopCtx)
	}()

	// Start log monitoring goroutine
	if m.config.LogFilterEnabled {
		m.loopWg.Add(1)
		go func() {
			defer m.loopWg.Done()
			m.logMonitoringLoop(loopCtx)
		}()
	}

	m.logger.Info("Monitoring system started successfully")
	return nil
}

// StopMetricsCollection stops the monitoring system
func (m *MonitoringServiceImpl) StopMetricsCollection(ctx context.Context) error {
	m.mu.Lock()

	if !m.enabled {
		m.mu.Unlock()
		return fmt.Errorf("monitoring not running")
	}

	m.logger.Info("Stopping monitoring system")
	m.enabled = false
	cancel := m.loopCancel
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	m.loopWg.Wait()

	m.mu.Lock()
	m.loopCtx = context.Background()
	m.loopCancel = func() {}
	m.logger.Info("Monitoring system stopped")
	m.mu.Unlock()

	return nil
}

// GetMetrics returns current metrics
func (m *MonitoringServiceImpl) GetMetrics(ctx context.Context, timeRange string) (*pulseuptypes.SystemMetrics, error) {
	// This would be enhanced to support time ranges and historical data
	// For now, return current system metrics
	systemSvc := NewSystemService(m.logger)
	return systemSvc.GetSystemMetrics(ctx)
}

// SetupAlerts configures alert rules
func (m *MonitoringServiceImpl) SetupAlerts(ctx context.Context, rules []pulseuptypes.AlertRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Setting up alert rules", "count", len(rules))

	for _, rule := range rules {
		if rule.ID == "" {
			rule.ID = uuid.New().String()
		}
		m.alertRules[rule.ID] = &rule
		m.logger.Debug("Added alert rule", "id", rule.ID, "name", rule.Name)
	}

	return nil
}

// GetContainerMetrics returns metrics for all monitored containers
func (m *MonitoringServiceImpl) GetContainerMetrics(ctx context.Context) (map[string]*pulseuptypes.ContainerMetrics, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Return copy of metrics to avoid concurrent access issues
	result := make(map[string]*pulseuptypes.ContainerMetrics)
	for k, v := range m.containerMetrics {
		metricsCopy := *v
		result[k] = &metricsCopy
	}

	return result, nil
}

// GetMonitoringStatus returns the current status of the monitoring system
func (m *MonitoringServiceImpl) GetMonitoringStatus(ctx context.Context) (*pulseuptypes.MonitoringStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	activeAlertCount := 0
	for _, alert := range m.activeAlerts {
		if !alert.Resolved {
			activeAlertCount++
		}
	}

	return &pulseuptypes.MonitoringStatus{
		Enabled:               m.enabled,
		ActiveContainers:      len(m.containerMetrics),
		TotalAlerts:           len(m.activeAlerts),
		ActiveAlerts:          activeAlertCount,
		LastMetricsCollection: m.lastCollection,
		MetricsErrors:         m.metricsErrors,
		HealthCheckErrors:     m.healthErrors,
		Uptime:                time.Since(m.startTime),
	}, nil
}

// metricsCollectionLoop runs the metrics collection in a loop
func (m *MonitoringServiceImpl) metricsCollectionLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.collectMetrics(ctx); err != nil {
				// Check if this is a Docker permission error in development
				if strings.Contains(err.Error(), "permission denied") && strings.Contains(err.Error(), "docker.sock") {
					// This is likely a development Docker socket permission issue
					// Log at DEBUG level to avoid alarming the developer
					m.logger.Debug("Docker metrics collection disabled due to socket permissions", "error", err.Error())
				} else {
					// Other errors should still be logged as errors
					m.logger.Error("Error collecting metrics", "error", err)
				}
				m.incrementMetricsErrors()
			}
		}
	}
}

// collectMetrics collects metrics from all containers
func (m *MonitoringServiceImpl) collectMetrics(ctx context.Context) error {
	if m.dockerClient == nil {
		return fmt.Errorf("docker client not available")
	}

	containers, err := m.dockerClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastCollection = now

	for _, container := range containers {
		metrics, err := m.collectContainerMetrics(ctx, container.ID, container.Names[0], container.State)
		if err != nil {
			m.logger.Error("Failed to collect metrics for container", "container", container.ID[:12], "error", err)
			continue
		}

		m.containerMetrics[container.ID] = metrics

		// Check alert rules for this container
		m.checkAlertRules(metrics)
	}

	return nil
}

// collectContainerMetrics collects metrics for a specific container
func (m *MonitoringServiceImpl) collectContainerMetrics(ctx context.Context, containerID, containerName, state string) (*pulseuptypes.ContainerMetrics, error) {
	// Get container inspect info for basic details
	inspect, err := m.dockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	var labelsCopy map[string]string
	if inspect.Config != nil && len(inspect.Config.Labels) > 0 {
		labelsCopy = make(map[string]string, len(inspect.Config.Labels))
		for key, value := range inspect.Config.Labels {
			labelsCopy[key] = value
		}
	}

	// Get uptime
	startTime, _ := time.Parse(time.RFC3339Nano, inspect.State.StartedAt)
	uptime := time.Since(startTime)

	// Determine health status
	healthStatus := m.determineHealthStatus(&inspect)

	// Clean container name
	cleanName := containerName
	if strings.HasPrefix(cleanName, "/") {
		cleanName = cleanName[1:]
	}

	// Create basic metrics (detailed stats collection can be added later)
	metrics := &pulseuptypes.ContainerMetrics{
		ContainerID:   containerID,
		ContainerName: cleanName,
		Status:        pulseuptypes.FromDockerStatus(state),
		CPU: pulseuptypes.ContainerCPUMetrics{
			Usage:     0, // TODO: Implement CPU metrics collection
			Throttled: 0,
			Limit:     0,
		},
		Memory: pulseuptypes.ContainerMemoryMetrics{
			Usage:   0, // TODO: Implement memory metrics collection
			Limit:   0,
			Percent: 0,
			Cache:   0,
			RSS:     0,
		},
		Network: pulseuptypes.ContainerNetworkMetrics{
			RxBytes:   0, // TODO: Implement network metrics collection
			TxBytes:   0,
			RxPackets: 0,
			TxPackets: 0,
			RxErrors:  0,
			TxErrors:  0,
		},
		Disk: pulseuptypes.ContainerDiskMetrics{
			ReadBytes:  0, // TODO: Implement disk metrics collection
			WriteBytes: 0,
			ReadOps:    0,
			WriteOps:   0,
		},
		Health:    healthStatus,
		Uptime:    uptime,
		Timestamp: time.Now(),
	}

	if labelsCopy != nil {
		metrics.Labels = labelsCopy
	}

	if inspect.Config != nil {
		metrics.PulseUpManaged = strings.EqualFold(inspect.Config.Labels[managedLabelKey], "true")
	}

	// Add response time monitoring if enabled
	if m.config.ResponseTimeEnabled {
		metrics.ResponseTime = m.checkResponseTime(&inspect)
	}

	return metrics, nil
}

func (m *MonitoringServiceImpl) incrementMetricsErrors() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metricsErrors++
}

func (m *MonitoringServiceImpl) incrementHealthErrors() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthErrors++
}

// calculateCPUPercent calculates CPU usage percentage from Docker stats
// TODO: Implement when Docker stats API is properly integrated
func calculateCPUPercent() float64 {
	return 0 // Placeholder implementation
}

// determineHealthStatus determines the health status of a container
func (m *MonitoringServiceImpl) determineHealthStatus(inspect *types.ContainerJSON) pulseuptypes.HealthStatus {
	if inspect.State.Health == nil {
		return pulseuptypes.HealthStatusNone
	}

	switch inspect.State.Health.Status {
	case "healthy":
		return pulseuptypes.HealthStatusHealthy
	case "unhealthy":
		return pulseuptypes.HealthStatusUnhealthy
	case "starting":
		return pulseuptypes.HealthStatusStarting
	default:
		return pulseuptypes.HealthStatusNone
	}
}

// checkResponseTime performs response time check for a container
func (m *MonitoringServiceImpl) checkResponseTime(inspect *types.ContainerJSON) *pulseuptypes.ResponseTimeMetrics {
	// Extract exposed ports and check HTTP endpoints
	for port := range inspect.Config.ExposedPorts {
		if strings.Contains(string(port), "80") || strings.Contains(string(port), "8080") || strings.Contains(string(port), "3000") {
			portNum := strings.Split(string(port), "/")[0]
			url := fmt.Sprintf("http://localhost:%s", portNum)

			start := time.Now()
			resp, err := http.Get(url)
			duration := time.Since(start)

			metrics := &pulseuptypes.ResponseTimeMetrics{
				URL:          url,
				ResponseTime: duration,
				LastChecked:  time.Now(),
			}

			if err != nil {
				metrics.Success = false
				metrics.Error = err.Error()
			} else {
				metrics.Success = true
				metrics.StatusCode = resp.StatusCode
				resp.Body.Close()
			}

			return metrics
		}
	}

	return nil
}

// healthCheckLoop runs health checks in a loop
func (m *MonitoringServiceImpl) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.performHealthChecks(); err != nil {
				m.logger.Error("Error performing health checks", "error", err)
				m.incrementHealthErrors()
			}
		}
	}
}

// performHealthChecks performs health checks on all containers
func (m *MonitoringServiceImpl) performHealthChecks() error {
	// This would perform custom health checks beyond Docker's built-in health checks
	m.logger.Debug("Performing health checks")
	return nil
}

// logMonitoringLoop monitors container logs for issues
func (m *MonitoringServiceImpl) logMonitoringLoop(ctx context.Context) {
	// This would monitor container logs using the Docker API and filter for issues
	m.logger.Debug("Starting log monitoring")
	<-ctx.Done()
}

// checkAlertRules checks if any alert rules are triggered by the metrics
func (m *MonitoringServiceImpl) checkAlertRules(metrics *pulseuptypes.ContainerMetrics) {
	for _, rule := range m.alertRules {
		if !rule.Enabled {
			continue
		}

		// Check if rule applies to this container
		if rule.ContainerFilter != "" {
			matched, _ := regexp.MatchString(rule.ContainerFilter, metrics.ContainerName)
			if !matched {
				continue
			}
		}

		// Check if alert should be triggered
		if m.shouldTriggerAlert(rule, metrics) {
			m.triggerAlert(rule, metrics)
		}
	}
}

// shouldTriggerAlert determines if an alert should be triggered
func (m *MonitoringServiceImpl) shouldTriggerAlert(rule *pulseuptypes.AlertRule, metrics *pulseuptypes.ContainerMetrics) bool {
	var value float64

	switch rule.MetricType {
	case pulseuptypes.AlertMetricTypeCPUUsage:
		value = metrics.CPU.Usage
	case pulseuptypes.AlertMetricTypeMemoryUsage:
		value = metrics.Memory.Percent
	case pulseuptypes.AlertMetricTypeContainerDown:
		if !m.shouldEmitContainerDownAlert(metrics) {
			return false
		}
		if metrics.Status != pulseuptypes.ServiceStatusRunning {
			value = 1
		} else {
			value = 0
		}
	case pulseuptypes.AlertMetricTypeResponseTime:
		if metrics.ResponseTime != nil {
			value = float64(metrics.ResponseTime.ResponseTime.Milliseconds())
		}
	default:
		return false
	}

	// Check if threshold is met
	switch rule.Operator {
	case pulseuptypes.AlertOperatorGreaterThan:
		return value > rule.Threshold
	case pulseuptypes.AlertOperatorLessThan:
		return value < rule.Threshold
	case pulseuptypes.AlertOperatorGreaterEqual:
		return value >= rule.Threshold
	case pulseuptypes.AlertOperatorLessEqual:
		return value <= rule.Threshold
	case pulseuptypes.AlertOperatorEqual:
		return value == rule.Threshold
	case pulseuptypes.AlertOperatorNotEqual:
		return value != rule.Threshold
	}

	return false
}

func (m *MonitoringServiceImpl) shouldEmitContainerDownAlert(metrics *pulseuptypes.ContainerMetrics) bool {
	if metrics == nil {
		return false
	}

	if !metrics.PulseUpManaged {
		return false
	}

	if strings.EqualFold(metrics.ContainerName, CaddyContainerName) {
		return false
	}

	if component := metrics.Labels[CaddyComponentLabel]; strings.EqualFold(component, "caddy") {
		return false
	}

	if lifecycleName := metrics.Labels[lifecycleFinalNameLabel]; lifecycleName == CaddyLifecycleName {
		return false
	}

	return true
}

// triggerAlert triggers an alert
func (m *MonitoringServiceImpl) triggerAlert(rule *pulseuptypes.AlertRule, metrics *pulseuptypes.ContainerMetrics) {
	// Check cooldown period
	if rule.LastTriggered != nil && time.Since(*rule.LastTriggered) < m.config.AlertCooldown {
		return
	}

	alertID := uuid.New().String()
	now := time.Now()

	alert := &pulseuptypes.AlertEvent{
		ID:          alertID,
		RuleID:      rule.ID,
		RuleName:    rule.Name,
		ContainerID: metrics.ContainerID,
		Severity:    rule.Severity,
		Message:     m.formatAlertMessage(rule, metrics),
		Timestamp:   now,
		Resolved:    false,
	}

	m.activeAlerts[alertID] = alert
	rule.LastTriggered = &now

	m.logger.Warn("Alert triggered", "rule", rule.Name, "container", metrics.ContainerName, "severity", rule.Severity)

	// Send alert notification
	m.sendAlertNotification(alert)
}

// formatAlertMessage formats an alert message
func (m *MonitoringServiceImpl) formatAlertMessage(rule *pulseuptypes.AlertRule, metrics *pulseuptypes.ContainerMetrics) string {
	return fmt.Sprintf("Alert: %s triggered for container %s", rule.Name, metrics.ContainerName)
}

// sendAlertNotification sends an alert notification
func (m *MonitoringServiceImpl) sendAlertNotification(alert *pulseuptypes.AlertEvent) {
	// Send via WebSocket if available
	if m.wsManager != nil {
		// Send container stopped alert specifically
		if alert.RuleID == "container-down" {
			payload := map[string]interface{}{
				"container_id":   alert.ContainerID,
				"container_name": m.getContainerNameByID(alert.ContainerID),
				"alert_id":       alert.ID,
				"severity":       string(alert.Severity),
				"message":        alert.Message,
				"timestamp":      alert.Timestamp,
			}

			if err := m.wsManager.Emit("container_stopped", payload); err != nil {
				m.logger.Error("Failed to send container stopped alert via WebSocket", "alert_id", alert.ID, "error", err)
			} else {
				m.logger.Info("Container stopped alert sent via WebSocket", "alert_id", alert.ID, "container_id", alert.ContainerID)
			}
		}

		// Send general monitoring alert
		alertPayload := map[string]interface{}{
			"id":           alert.ID,
			"rule_id":      alert.RuleID,
			"rule_name":    alert.RuleName,
			"container_id": alert.ContainerID,
			"severity":     string(alert.Severity),
			"message":      alert.Message,
			"timestamp":    alert.Timestamp,
			"resolved":     alert.Resolved,
		}

		if err := m.wsManager.Emit("monitoring_alert", alertPayload); err != nil {
			m.logger.Error("Failed to send monitoring alert via WebSocket", "alert_id", alert.ID, "error", err)
		} else {
			m.logger.Debug("Monitoring alert sent via WebSocket", "alert_id", alert.ID)
		}
	}

	// Log the alert
	m.logger.Info("Alert triggered", "alert", alert)
}

// setupDefaultAlertRules sets up default alert rules
func (m *MonitoringServiceImpl) setupDefaultAlertRules() {
	defaultRules := []pulseuptypes.AlertRule{
		{
			ID:          "cpu-high",
			Name:        "High CPU Usage",
			Description: "Container CPU usage is above 80%",
			MetricType:  pulseuptypes.AlertMetricTypeCPUUsage,
			Threshold:   80.0,
			Operator:    pulseuptypes.AlertOperatorGreaterThan,
			Duration:    5 * time.Minute,
			Severity:    pulseuptypes.AlertSeverityWarning,
			Enabled:     true,
		},
		{
			ID:          "memory-high",
			Name:        "High Memory Usage",
			Description: "Container memory usage is above 90%",
			MetricType:  pulseuptypes.AlertMetricTypeMemoryUsage,
			Threshold:   90.0,
			Operator:    pulseuptypes.AlertOperatorGreaterThan,
			Duration:    3 * time.Minute,
			Severity:    pulseuptypes.AlertSeverityError,
			Enabled:     true,
		},
		{
			ID:          "container-down",
			Name:        "Container Down",
			Description: "Container is not running",
			MetricType:  pulseuptypes.AlertMetricTypeContainerDown,
			Threshold:   1.0,
			Operator:    pulseuptypes.AlertOperatorEqual,
			Duration:    1 * time.Minute,
			Severity:    pulseuptypes.AlertSeverityCritical,
			Enabled:     true,
		},
	}

	for _, rule := range defaultRules {
		m.alertRules[rule.ID] = &rule
	}
}

// setupDefaultLogFilters sets up default log filters
func (m *MonitoringServiceImpl) setupDefaultLogFilters() {
	defaultFilters := []pulseuptypes.LogFilter{
		{
			Name:     "error-patterns",
			Patterns: []string{"ERROR", "FATAL", "Exception", "panic"},
			LogLevel: "error",
			Enabled:  true,
		},
		{
			Name:     "warning-patterns",
			Patterns: []string{"WARN", "WARNING", "deprecated"},
			LogLevel: "warn",
			Enabled:  true,
		},
	}

	for _, filter := range defaultFilters {
		m.logFilters[filter.Name] = &filter
	}
}

// getContainerNameByID gets the container name from the stored metrics
func (m *MonitoringServiceImpl) getContainerNameByID(containerID string) string {
	m.mu.RLock()
	if metrics, exists := m.containerMetrics[containerID]; exists {
		name := metrics.ContainerName
		m.mu.RUnlock()
		return name
	}
	m.mu.RUnlock()

	// Fallback: try to get name from Docker API
	if m.dockerClient != nil {
		inspect, err := m.dockerClient.ContainerInspect(m.runtimeContext(), containerID)
		if err == nil && len(inspect.Name) > 0 {
			name := inspect.Name
			if strings.HasPrefix(name, "/") {
				name = name[1:]
			}
			return name
		}
	}

	if len(containerID) >= 12 {
		return containerID[:12]
	}

	return containerID
}

func (m *MonitoringServiceImpl) runtimeContext() context.Context {
	m.mu.RLock()
	ctx := m.loopCtx
	m.mu.RUnlock()

	if ctx == nil {
		return context.Background()
	}

	return ctx
}
