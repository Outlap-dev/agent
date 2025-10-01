package types

import (
	"context"
	"encoding/json"
	"time"
)

// WebSocket message types
type WSMessage struct {
	Event  string          `json:"event"`
	Data   json.RawMessage `json:"data"`
	CallID json.RawMessage `json:"call_id"`
}

type WSResponse struct {
	Event   string      `json:"event"`
	Data    interface{} `json:"data"`
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
}

// Call-based WebSocket message types
type WSCallMessage struct {
	Type   string          `json:"type"`
	CallID string          `json:"call_id"`
	Event  string          `json:"event"`
	Data   json.RawMessage `json:"data"`
}

type WSCallResponse struct {
	Type    string      `json:"type"`
	CallID  string      `json:"call_id"`
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Event-based WebSocket message types
type WSEventMessage struct {
	Type  string      `json:"type"`
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

// Service status types
type ServiceStatus string

const (
	ServiceStatusPending    ServiceStatus = "pending"
	ServiceStatusRunning    ServiceStatus = "running"
	ServiceStatusStopped    ServiceStatus = "stopped"
	ServiceStatusFailed     ServiceStatus = "failed"
	ServiceStatusDeploying  ServiceStatus = "deploying"
	ServiceStatusRestarting ServiceStatus = "restarting"
	ServiceStatusReady      ServiceStatus = "ready"
	ServiceStatusStopping   ServiceStatus = "stopping"
)

// GetServiceStatusChoices returns all valid service status values
func GetServiceStatusChoices() []ServiceStatus {
	return []ServiceStatus{
		ServiceStatusPending,
		ServiceStatusRunning,
		ServiceStatusStopped,
		ServiceStatusFailed,
		ServiceStatusDeploying,
		ServiceStatusRestarting,
		ServiceStatusReady,
		ServiceStatusStopping,
	}
}

// GetCompletedServiceStatuses returns statuses that represent a completed state
func GetCompletedServiceStatuses() []ServiceStatus {
	return []ServiceStatus{
		ServiceStatusStopped,
		ServiceStatusFailed,
		ServiceStatusReady,
		ServiceStatusRunning,
	}
}

// FromDockerStatus converts a Docker container status to a service status
func FromDockerStatus(dockerStatus string) ServiceStatus {
	statusMap := map[string]ServiceStatus{
		"running":    ServiceStatusRunning,
		"exited":     ServiceStatusStopped,
		"dead":       ServiceStatusFailed,
		"created":    ServiceStatusPending,
		"restarting": ServiceStatusDeploying,
		"removing":   ServiceStatusStopping,
		"paused":     ServiceStatusStopped,
	}

	if status, exists := statusMap[dockerStatus]; exists {
		return status
	}
	return ServiceStatusFailed
}

type ServiceInfo struct {
	UID         string            `json:"uid"`
	Name        string            `json:"name"`
	Status      ServiceStatus     `json:"status"`
	Port        int               `json:"port,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ContainerInstance represents a managed container instance for a service deployment.
type ContainerInstance struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Version   int               `json:"version"`
	Labels    map[string]string `json:"labels"`
	State     string            `json:"state"`
	CreatedAt time.Time         `json:"created_at"`
}

// Deployment types
type DeploymentStatus string

const (
	DeploymentStatusPending    DeploymentStatus = "pending"
	DeploymentStatusBuilding   DeploymentStatus = "building"
	DeploymentStatusDeploying  DeploymentStatus = "deploying"
	DeploymentStatusRunning    DeploymentStatus = "running"
	DeploymentStatusFailed     DeploymentStatus = "failed"
	DeploymentStatusStopped    DeploymentStatus = "stopped"
	DeploymentStatusInProgress DeploymentStatus = "in_progress"
	DeploymentStatusCompleted  DeploymentStatus = "completed"
	DeploymentStatusCancelled  DeploymentStatus = "cancelled"
)

// GetDeploymentStatusChoices returns all valid deployment status values
func GetDeploymentStatusChoices() []DeploymentStatus {
	return []DeploymentStatus{
		DeploymentStatusPending,
		DeploymentStatusBuilding,
		DeploymentStatusDeploying,
		DeploymentStatusRunning,
		DeploymentStatusFailed,
		DeploymentStatusStopped,
		DeploymentStatusInProgress,
		DeploymentStatusCompleted,
		DeploymentStatusCancelled,
	}
}

// GetCompletedDeploymentStatuses returns statuses that represent a completed state
func GetCompletedDeploymentStatuses() []DeploymentStatus {
	return []DeploymentStatus{
		DeploymentStatusCompleted,
		DeploymentStatusFailed,
		DeploymentStatusCancelled,
		DeploymentStatusStopped,
		DeploymentStatusRunning,
	}
}

// IsDeploymentStatusCompleted reports whether the provided status is considered terminal for a deployment.
func IsDeploymentStatusCompleted(status DeploymentStatus) bool {
	for _, completed := range GetCompletedDeploymentStatuses() {
		if status == completed {
			return true
		}
	}
	return false
}

type DeploymentInfo struct {
	UID       string           `json:"uid"`
	ServiceID string           `json:"service_id"`
	Status    DeploymentStatus `json:"status"`
	GitURL    string           `json:"git_url,omitempty"`
	Branch    string           `json:"branch,omitempty"`
	CommitSHA string           `json:"commit_sha,omitempty"`
	BuildLogs []string         `json:"build_logs,omitempty"`
	CreatedAt time.Time        `json:"created_at"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// DeploymentStepStatus represents the lifecycle state for a deployment timeline step
type DeploymentStepStatus string

const (
	DeploymentStepStatusPending DeploymentStepStatus = "pending"
	DeploymentStepStatusRunning DeploymentStepStatus = "running"
	DeploymentStepStatusSuccess DeploymentStepStatus = "success"
	DeploymentStepStatusError   DeploymentStepStatus = "error"
)

// DeploymentStepLog captures key messages associated with a deployment step
type DeploymentStepLog struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

// DomainProvisionRequest captures the desired routing configuration for a domain.
type DomainProvisionRequest struct {
	Domain             string `json:"domain"`
	ServiceUID         string `json:"service_uid"`
	TargetPort         int    `json:"target_port"`
	TargetProtocol     string `json:"target_protocol"`
	ForceHTTPS         bool   `json:"force_https"`
	RedirectWWW        string `json:"redirect_www"`
	ManagedCertificate bool   `json:"managed_certificate"`
	CertificateEmail   string `json:"certificate_email"`
}

// DomainProxyInfo describes the active proxy routing configuration for a domain.
type DomainProxyInfo struct {
	Domain             string    `json:"domain"`
	ServiceUID         string    `json:"service_uid"`
	UpstreamContainer  string    `json:"upstream_container"`
	TargetPort         int       `json:"target_port"`
	TargetProtocol     string    `json:"target_protocol"`
	ForceHTTPS         bool      `json:"force_https"`
	RedirectWWW        string    `json:"redirect_www"`
	ManagedCertificate bool      `json:"managed_certificate"`
	CertificateEmail   string    `json:"certificate_email"`
	SSLStatus          string    `json:"ssl_status"`
	LastApplied        time.Time `json:"last_applied"`
}

// DeploymentStep provides timeline metadata for deployment progress visualizations
type DeploymentStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Status      DeploymentStepStatus   `json:"status"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	LogType     string                 `json:"log_type,omitempty"`
	Logs        []DeploymentStepLog    `json:"logs,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// DeploymentStepRecorder defines the contract for recording per-step deployment telemetry.
type DeploymentStepRecorder interface {
	AppendLog(stepID, level, message string)
	CompleteStep(stepID string)
	FailStep(stepID, errorMessage string)
	SetMetadata(stepID, key string, value interface{})
}

// System metrics types
type SystemMetrics struct {
	CPU       CPUMetrics     `json:"cpu"`
	Memory    MemoryMetrics  `json:"memory"`
	Disk      DiskMetrics    `json:"disk"`
	Network   NetworkMetrics `json:"network"`
	Uptime    time.Duration  `json:"uptime"`
	Timestamp time.Time      `json:"timestamp"`
}

// LiveStats represents standardized live system statistics for monitoring
type LiveStats struct {
	CPUUsagePercent    float64   `json:"cpu_usage_percent"`
	MemoryUsedGB       float64   `json:"memory_used_gb"`
	MemoryTotalGB      float64   `json:"memory_total_gb"`
	MemoryUsagePercent float64   `json:"memory_usage_percent"`
	DiskUsedGB         float64   `json:"disk_used_gb"`
	DiskTotalGB        float64   `json:"disk_total_gb"`
	DiskUsagePercent   float64   `json:"disk_usage_percent"`
	NetworkBytesIn     uint64    `json:"network_bytes_in"`
	NetworkBytesOut    uint64    `json:"network_bytes_out"`
	UptimeSeconds      int64     `json:"uptime_seconds"`
	LoadAvg1           float64   `json:"load_avg_1"`
	LoadAvg5           float64   `json:"load_avg_5"`
	LoadAvg15          float64   `json:"load_avg_15"`
	Timestamp          time.Time `json:"timestamp"`
}

type CPUMetrics struct {
	Usage     float64 `json:"usage"` // Percentage
	LoadAvg1  float64 `json:"load_avg_1"`
	LoadAvg5  float64 `json:"load_avg_5"`
	LoadAvg15 float64 `json:"load_avg_15"`
}

type MemoryMetrics struct {
	Total     uint64  `json:"total"`     // Bytes
	Used      uint64  `json:"used"`      // Bytes
	Available uint64  `json:"available"` // Bytes
	Usage     float64 `json:"usage"`     // Percentage
}

type DiskMetrics struct {
	Total uint64  `json:"total"` // Bytes
	Used  uint64  `json:"used"`  // Bytes
	Free  uint64  `json:"free"`  // Bytes
	Usage float64 `json:"usage"` // Percentage
}

type NetworkMetrics struct {
	BytesIn  uint64 `json:"bytes_in"`
	BytesOut uint64 `json:"bytes_out"`
}

// Command handler types
type CommandRequest struct {
	Command string          `json:"command"`
	Data    json.RawMessage `json:"data"`
}

type CommandResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Build types
type BuildInfo struct {
	ServiceUID string     `json:"service_uid"`
	Status     string     `json:"status"`
	Logs       []string   `json:"logs"`
	StartTime  time.Time  `json:"start_time"`
	EndTime    *time.Time `json:"end_time,omitempty"`
}

// Hardware info types
type HardwareInfo struct {
	CPU       CPUInfo     `json:"cpu"`
	Memory    MemoryInfo  `json:"memory"`
	Storage   StorageInfo `json:"storage"`
	Network   NetworkInfo `json:"network"`
	OS        OSInfo      `json:"os"`
	Hostname  string      `json:"hostname"`
	PrimaryIP string      `json:"primary_ip,omitempty"`
	// New fields for server information
	PublicIP         string  `json:"public_ip"`
	CPUPhysicalCores int     `json:"cpu_physical_cores"`
	CPULogicalCount  int     `json:"cpu_logical_count"`
	TotalMemoryGB    float64 `json:"total_memory_gb"`
	StorageTotalGB   float64 `json:"storage_total_gb"`
}

type CPUInfo struct {
	Model string `json:"model"`
	Cores int    `json:"cores"`
	Arch  string `json:"arch"`
}

type MemoryInfo struct {
	Total uint64 `json:"total"`
}

type StorageInfo struct {
	Total uint64 `json:"total"`
	Type  string `json:"type"`
}

type NetworkInfo struct {
	Interfaces []NetworkInterface `json:"interfaces"`
}

type NetworkInterface struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	MAC  string `json:"mac"`
}

type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Kernel  string `json:"kernel"`
}

// Database types
type DatabaseDeploymentResult struct {
	ContainerID   string `json:"container_id"`
	Name          string `json:"name"`
	Port          int    `json:"port"`
	Type          string `json:"type"`
	Username      string `json:"username"`
	Database      string `json:"database"`
	VolumePath    string `json:"volume_path"`
	DeploymentUID string `json:"deployment_uid,omitempty"`
}

// Database backup types
type DatabaseBackupResult struct {
	BackupPath string    `json:"backup_path"`
	Database   string    `json:"database"`
	Type       string    `json:"type"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
}

// Container execution types
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
}

// Git types
type GitHubRepoInfo struct {
	RepoURL     string `json:"repo_url"`
	AccessToken string `json:"access_token"`
	Error       string `json:"error,omitempty"`
}

type CloneResult struct {
	Success   bool   `json:"success"`
	ClonePath string `json:"clone_path,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ContextKey is used for storing request-scoped metadata in context.Context values.
type ContextKey string

const (
	ContextKeyBackupUID        ContextKey = "backup_uid"
	ContextKeyBackupServiceUID ContextKey = "backup_service_uid"
	ContextKeyBackupStartTime  ContextKey = "backup_start_time"
)

// BackupAutomationConfig represents automation preferences pushed from the backend.
type BackupAutomationConfig struct {
	Enabled        bool   `json:"enabled"`
	CronExpression string `json:"cron_expression"`
	StoragePath    string `json:"storage_path"`
	RetentionDays  int    `json:"retention_days"`
}

// WebSocketEmitter represents the minimal event emission contract shared between services and handlers.
type WebSocketEmitter interface {
	Emit(event string, data interface{}) error
	IsConnected() bool
}

// Nixpacks types
type NixpacksPlan struct {
	Providers []string               `json:"providers"`
	BuildCmd  []string               `json:"buildCmd,omitempty"`
	StartCmd  string                 `json:"startCmd,omitempty"`
	Install   map[string]interface{} `json:"install,omitempty"`
	Setup     []string               `json:"setup,omitempty"`
	Variables map[string]string      `json:"variables,omitempty"`
}

// BuildCommandInfo contains information needed to execute a build for a service
type BuildCommandInfo struct {
	ServiceUID string      `json:"service_uid"`
	Type       string      `json:"type"`    // "docker", "nixpacks", or "docker-compose"
	Command    string      `json:"command"` // The build command to execute
	CWD        string      `json:"cwd"`     // Working directory for the command
	Plan       interface{} `json:"plan"`    // Nixpacks plan if available
}

// BuildPlan stores build information per service
type BuildPlan struct {
	Type        string      `json:"type"`         // "docker", "nixpacks", or "docker-compose"
	ContextPath string      `json:"context_path"` // Path to the build context
	Plan        interface{} `json:"plan"`         // Nixpacks plan if available
}

// DeploymentMethod represents the strategy to use for application deployment
type DeploymentMethod string

const (
	DeploymentMethodNixpacks      DeploymentMethod = "nixpacks"
	DeploymentMethodDockerfile    DeploymentMethod = "dockerfile"
	DeploymentMethodDockerCompose DeploymentMethod = "docker-compose"
)

// DockerComposeDeploymentRequest describes the input required to deploy using Docker Compose
type DockerComposeDeploymentRequest struct {
	DeploymentUID    string            `json:"deployment_uid"`
	ServiceUID       string            `json:"service_uid"`
	SourcePath       string            `json:"source_path"`
	ComposeFile      string            `json:"compose_file"`
	ServiceMode      string            `json:"service_mode"`
	SelectedServices []string          `json:"selected_services,omitempty"`
	ProjectName      string            `json:"project_name"`
	Environment      map[string]string `json:"environment,omitempty"`
}

// DeployApplicationRequest represents the request structure for app deployment
// Updated to match the new backend format with deployment_data
type DeployApplicationRequest struct {
	ServiceUID         string                 `json:"service_uid"`
	Service            map[string]interface{} `json:"service"`
	DeploymentUID      string                 `json:"deployment_uid"`
	AccessToken        string                 `json:"access_token"`
	GitHubRepo         string                 `json:"github_repo"`
	GitHubBranch       string                 `json:"github_branch,omitempty"`
	LastCommitSHA      string                 `json:"last_commit_sha,omitempty"`
	NixpacksConfig     map[string]interface{} `json:"nixpacks_config,omitempty"`
	InstallCommand     string                 `json:"install_command,omitempty"`
	BuildCommand       string                 `json:"build_command,omitempty"`
	StartCommand       string                 `json:"start_command,omitempty"`
	InternalPort       int                    `json:"internal_port,omitempty"`
	EnvVars            map[string]string      `json:"env_vars,omitempty"`
	CPULimit           string                 `json:"cpu_limit,omitempty"`
	MemoryLimit        string                 `json:"memory_limit,omitempty"`
	DeploymentStrategy string                 `json:"deployment_strategy,omitempty"`
}

// ServiceEnvVarsResponse represents the response from get_service_env_vars
type ServiceEnvVarsResponse struct {
	Success bool              `json:"success"`
	EnvVars map[string]string `json:"env_vars,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// DeploymentResult represents the result of a deployment operation
type DeploymentResult struct {
	Success           bool   `json:"success"`
	ImageName         string `json:"image_name,omitempty"`
	ContainerID       string `json:"container_id,omitempty"`
	ContainerName     string `json:"container_name,omitempty"`
	DeploymentColor   string `json:"deployment_color,omitempty"`
	DeploymentVersion int    `json:"deployment_version,omitempty"`
	Error             string `json:"error,omitempty"`
}

// MonitoringConfig defines the monitoring system configuration
type MonitoringConfig struct {
	MetricsInterval     time.Duration `json:"metrics_interval"`      // How often to collect metrics
	HealthCheckInterval time.Duration `json:"health_check_interval"` // How often to perform health checks
	AlertCooldown       time.Duration `json:"alert_cooldown"`        // Minimum time between same alert types
	LogFilterEnabled    bool          `json:"log_filter_enabled"`    // Enable log filtering for issues
	ResponseTimeEnabled bool          `json:"response_time_enabled"` // Enable response time monitoring
}

// ContainerMetrics contains metrics for a specific container
type ContainerMetrics struct {
	ContainerID    string                  `json:"container_id"`
	ContainerName  string                  `json:"container_name"`
	Status         ServiceStatus           `json:"status"`
	CPU            ContainerCPUMetrics     `json:"cpu"`
	Memory         ContainerMemoryMetrics  `json:"memory"`
	Network        ContainerNetworkMetrics `json:"network"`
	Disk           ContainerDiskMetrics    `json:"disk"`
	Health         HealthStatus            `json:"health"`
	Uptime         time.Duration           `json:"uptime"`
	ResponseTime   *ResponseTimeMetrics    `json:"response_time,omitempty"`
	Labels         map[string]string       `json:"labels,omitempty"`
	PulseUpManaged bool                    `json:"pulseup_managed"`
	Timestamp      time.Time               `json:"timestamp"`
}

// ContainerCPUMetrics contains CPU metrics for a container
type ContainerCPUMetrics struct {
	Usage     float64 `json:"usage"`     // CPU usage percentage
	Throttled uint64  `json:"throttled"` // Number of times CPU was throttled
	Limit     float64 `json:"limit"`     // CPU limit (cores)
}

// ContainerMemoryMetrics contains memory metrics for a container
type ContainerMemoryMetrics struct {
	Usage   uint64  `json:"usage"`   // Memory usage in bytes
	Limit   uint64  `json:"limit"`   // Memory limit in bytes
	Percent float64 `json:"percent"` // Memory usage percentage
	Cache   uint64  `json:"cache"`   // Cache memory in bytes
	RSS     uint64  `json:"rss"`     // RSS memory in bytes
}

// ContainerNetworkMetrics contains network metrics for a container
type ContainerNetworkMetrics struct {
	RxBytes   uint64 `json:"rx_bytes"`   // Bytes received
	TxBytes   uint64 `json:"tx_bytes"`   // Bytes transmitted
	RxPackets uint64 `json:"rx_packets"` // Packets received
	TxPackets uint64 `json:"tx_packets"` // Packets transmitted
	RxErrors  uint64 `json:"rx_errors"`  // Receive errors
	TxErrors  uint64 `json:"tx_errors"`  // Transmit errors
}

// ContainerDiskMetrics contains disk metrics for a container
type ContainerDiskMetrics struct {
	ReadBytes  uint64 `json:"read_bytes"`  // Bytes read from disk
	WriteBytes uint64 `json:"write_bytes"` // Bytes written to disk
	ReadOps    uint64 `json:"read_ops"`    // Read operations
	WriteOps   uint64 `json:"write_ops"`   // Write operations
}

// HealthStatus represents the health status of a container
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusStarting  HealthStatus = "starting"
	HealthStatusNone      HealthStatus = "none" // No health check configured
)

// HealthCheckConfig defines a health check configuration
type HealthCheckConfig struct {
	Type        HealthCheckType `json:"type"`
	Endpoint    string          `json:"endpoint,omitempty"` // For HTTP checks
	Port        int             `json:"port,omitempty"`     // For TCP checks
	Command     []string        `json:"command,omitempty"`  // For exec checks
	Interval    time.Duration   `json:"interval"`
	Timeout     time.Duration   `json:"timeout"`
	Retries     int             `json:"retries"`
	StartPeriod time.Duration   `json:"start_period"`
}

// HealthCheckType defines the type of health check
type HealthCheckType string

const (
	HealthCheckTypeHTTP HealthCheckType = "http"
	HealthCheckTypeTCP  HealthCheckType = "tcp"
	HealthCheckTypeExec HealthCheckType = "exec"
)

// ResponseTimeMetrics contains response time monitoring data
type ResponseTimeMetrics struct {
	URL          string        `json:"url"`
	StatusCode   int           `json:"status_code"`
	ResponseTime time.Duration `json:"response_time"`
	Success      bool          `json:"success"`
	Error        string        `json:"error,omitempty"`
	LastChecked  time.Time     `json:"last_checked"`
}

// AlertRule defines an alert rule
type AlertRule struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	MetricType         AlertMetricType     `json:"metric_type"`
	Threshold          float64             `json:"threshold"`
	Operator           AlertOperator       `json:"operator"`
	Duration           time.Duration       `json:"duration"` // How long condition must be true
	Severity           AlertSeverity       `json:"severity"`
	ContainerFilter    string              `json:"container_filter,omitempty"` // Filter containers by name pattern
	Enabled            bool                `json:"enabled"`
	LastTriggered      *time.Time          `json:"last_triggered,omitempty"`
	NotificationConfig *NotificationConfig `json:"notification_config,omitempty"`
}

// AlertMetricType defines the type of metric to monitor
type AlertMetricType string

const (
	AlertMetricTypeCPUUsage         AlertMetricType = "cpu_usage"
	AlertMetricTypeMemoryUsage      AlertMetricType = "memory_usage"
	AlertMetricTypeMemoryLimit      AlertMetricType = "memory_limit"
	AlertMetricTypeDiskUsage        AlertMetricType = "disk_usage"
	AlertMetricTypeNetworkErrors    AlertMetricType = "network_errors"
	AlertMetricTypeContainerDown    AlertMetricType = "container_down"
	AlertMetricTypeContainerRestart AlertMetricType = "container_restart"
	AlertMetricTypeResponseTime     AlertMetricType = "response_time"
	AlertMetricTypeHealthCheck      AlertMetricType = "health_check"
)

// AlertOperator defines the comparison operator for alerts
type AlertOperator string

const (
	AlertOperatorGreaterThan  AlertOperator = "gt"
	AlertOperatorLessThan     AlertOperator = "lt"
	AlertOperatorGreaterEqual AlertOperator = "gte"
	AlertOperatorLessEqual    AlertOperator = "lte"
	AlertOperatorEqual        AlertOperator = "eq"
	AlertOperatorNotEqual     AlertOperator = "ne"
)

// AlertSeverity defines the severity of an alert
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertEvent represents an alert that has been triggered
type AlertEvent struct {
	ID          string                 `json:"id"`
	RuleID      string                 `json:"rule_id"`
	RuleName    string                 `json:"rule_name"`
	ContainerID string                 `json:"container_id,omitempty"`
	Severity    AlertSeverity          `json:"severity"`
	Message     string                 `json:"message"`
	Value       float64                `json:"value"`
	Threshold   float64                `json:"threshold"`
	Timestamp   time.Time              `json:"timestamp"`
	Resolved    bool                   `json:"resolved"`
	ResolvedAt  *time.Time             `json:"resolved_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NotificationConfig defines how alerts should be sent
type NotificationConfig struct {
	WebSocketEvent bool   `json:"websocket_event"`       // Send via WebSocket
	LogEvent       bool   `json:"log_event"`             // Log the event
	WebhookURL     string `json:"webhook_url,omitempty"` // Send to webhook
}

// MonitoringStatus represents the overall status of the monitoring system
type MonitoringStatus struct {
	Enabled               bool          `json:"enabled"`
	ActiveContainers      int           `json:"active_containers"`
	TotalAlerts           int           `json:"total_alerts"`
	ActiveAlerts          int           `json:"active_alerts"`
	LastMetricsCollection time.Time     `json:"last_metrics_collection"`
	MetricsErrors         int           `json:"metrics_errors"`
	HealthCheckErrors     int           `json:"health_check_errors"`
	Uptime                time.Duration `json:"uptime"`
}

// LogFilter defines patterns to filter container logs for issues
type LogFilter struct {
	Name            string   `json:"name"`
	Patterns        []string `json:"patterns"`                   // Regex patterns to match
	LogLevel        string   `json:"log_level"`                  // error, warn, fatal, etc.
	ContainerFilter string   `json:"container_filter,omitempty"` // Filter containers
	Enabled         bool     `json:"enabled"`
}

// LogIssue represents a detected issue in container logs
type LogIssue struct {
	ID          string        `json:"id"`
	ContainerID string        `json:"container_id"`
	FilterName  string        `json:"filter_name"`
	LogLine     string        `json:"log_line"`
	Pattern     string        `json:"pattern"`
	Timestamp   time.Time     `json:"timestamp"`
	Severity    AlertSeverity `json:"severity"`
}

// VersionCheckResult represents the result of a version check
type VersionCheckResult struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	UpdateNeeded   bool   `json:"update_needed"`
	Error          string `json:"error,omitempty"`
}

// WhitelistedCommand represents a command that can be executed by the agent
type WhitelistedCommand struct {
	ID                   string                                                                    `json:"id"`
	Name                 string                                                                    `json:"name"`
	Description          string                                                                    `json:"description"`
	Category             string                                                                    `json:"category"`
	RequiresConfirmation bool                                                                      `json:"requires_confirmation"`
	Args                 []CommandArgument                                                         `json:"args,omitempty"`
	Handler              func(ctx context.Context, args map[string]string) (*CommandResult, error) `json:"-"`
}

// ContainerStatsRequest represents the request for getting container live stats
type ContainerStatsRequest struct {
	ContainerID string `json:"container_id,omitempty"` // Specific container ID or name
	ServiceUID  string `json:"service_uid,omitempty"`  // Service identifier to resolve the active container
}

// CommandArgument represents an argument for a whitelisted command
type CommandArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Type        string `json:"type"` // string, int, bool
}

// CommandResult represents the result of executing a whitelisted command
type CommandResult struct {
	Success   bool      `json:"success"`
	Output    string    `json:"output"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// UpdateMetadata represents the metadata for an agent update
type UpdateMetadata struct {
	Version   string    `json:"version"`
	URL       string    `json:"url"`
	SHA256    string    `json:"sha256"`
	Signature string    `json:"signature"`
	SignedAt  time.Time `json:"signed_at"`
	Changelog string    `json:"changelog,omitempty"`
}

// UpdateConfig represents configuration for agent updates
type UpdateConfig struct {
	Enabled             bool   `json:"enabled"`
	AutoUpdate          bool   `json:"auto_update"`
	UpdateIntervalHours int    `json:"update_interval_hours"`
	UpdateURL           string `json:"update_url"`
	PublicKeyPath       string `json:"public_key_path"`
}
