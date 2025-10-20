package services

import (
	"context"

	"pulseup-agent-go/internal/ipc"
	wscontracts "pulseup-agent-go/pkg/contracts/websocket"
	"pulseup-agent-go/pkg/types"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
)

// IPCClient interface for IPC operations (used in worker processes)
type IPCClient interface {
	SendPrivilegedRequest(ctx context.Context, operation ipc.OperationType, args map[string]interface{}) (*ipc.PrivilegedResponse, error)
	IsConnected() bool
}

// WebSocketEmitter provides minimal capabilities for sending events to the backend.
type WebSocketEmitter = types.WebSocketEmitter

// StatusSocket captures the websocket capabilities required by the status service.
type StatusSocket interface {
	wscontracts.StatefulEmitter
	wscontracts.Caller
}

// DockerService handles Docker container operations
type DockerService interface {
	ListContainers(ctx context.Context) ([]types.ServiceInfo, error)
	StartContainer(ctx context.Context, serviceUID string) error
	StopContainer(ctx context.Context, serviceUID string) error
	RestartContainer(ctx context.Context, serviceUID string) error
	GetContainerLogs(ctx context.Context, serviceUID string) ([]string, error)
	GetContainerLogsByName(ctx context.Context, containerName string) ([]string, error)
	StreamContainerLogs(ctx context.Context, serviceUID string) (<-chan string, error)
	BuildImage(ctx context.Context, buildContext string, tags []string) error
	RemoveContainer(ctx context.Context, serviceUID string) error
	GetContainerStatus(ctx context.Context, serviceUID string) (types.ServiceStatus, error)
	CreateContainer(ctx context.Context, config *container.Config, hostConfig *container.HostConfig, containerName string) (string, error)
	PullImage(ctx context.Context, imageName string) error
	TagImage(ctx context.Context, source, target string) error

	// Blue-green deployment methods
	ContainerExists(ctx context.Context, containerName string) (bool, error)
	FindContainersByLabel(ctx context.Context, labelKey, labelValue string) ([]string, error)
	RenameContainer(ctx context.Context, oldName, newName string) error
	StopContainerByName(ctx context.Context, containerName string) error
	RemoveContainerByName(ctx context.Context, containerName string) error
	StartContainerByName(ctx context.Context, containerName string) error

	// Volume management methods
	CreateVolume(ctx context.Context, volumeName string, labels map[string]string) error
	VolumeExists(ctx context.Context, volumeName string) (bool, error)

	// Container execution methods
	ExecContainer(ctx context.Context, containerID string, cmd []string) (*types.ExecResult, error)

	// Image cleanup methods
	CleanupOldDeploymentImages(ctx context.Context, serviceUID string) error

	// Container stats methods
	GetContainerStats(ctx context.Context, containerID string) (*types.ContainerMetrics, error)

	// Container inspect
	InspectContainer(ctx context.Context, containerID string) (dockertypes.ContainerJSON, error)
}

// GitService handles Git repository operations
type GitService interface {
	CloneRepository(ctx context.Context, gitURL, branch, destination string) error
	GetCommitSHA(ctx context.Context, repoPath string) (string, error)
	GetCommitMessage(ctx context.Context, repoPath, sha string) (string, error)
	PullLatest(ctx context.Context, repoPath string) error
	GetBranches(ctx context.Context, repoPath string) ([]string, error)
	CheckoutBranch(ctx context.Context, repoPath, branch string) error

	// GitHub-specific methods
	CloneGitHubRepo(ctx context.Context, serviceUID string) (*types.CloneResult, error)
	PullGitHubRepo(ctx context.Context, serviceUID string) (*types.CloneResult, error)
	GetGitHubRepoInfo(ctx context.Context, serviceUID string) (*types.GitHubRepoInfo, error)

	// New methods that accept repo info directly (avoiding server calls)
	CloneGitHubRepoDirectly(ctx context.Context, repoURL, accessToken, clonePath, branch string) (*types.CloneResult, error)
	PullGitHubRepoDirectly(ctx context.Context, clonePath, accessToken, branch string) (*types.CloneResult, error)

	SetWebSocketManager(wsManager wscontracts.Caller)
}

// BuildService handles application building and deployment
type BuildService interface {
	BuildApplication(ctx context.Context, config *types.BuildConfig) (*types.BuildResult, error)
	DeployApplication(ctx context.Context, config *types.DeployConfig) (*types.DeployResult, error)
	GetBuildHistory(ctx context.Context, appName string) ([]types.BuildResult, error)
	GetDeploymentStatus(ctx context.Context, appName string) (*types.AppDeploymentStatus, error)

	// Build preparation methods
	PrepareBuild(ctx context.Context, clonePath, serviceUID string, isInitialClone bool) error
	GetBuildCommandInfo(ctx context.Context, serviceUID string) (*types.BuildCommandInfo, error)
	RecordBuildResult(ctx context.Context, serviceUID string, result *types.BuildResult) error
	SetWebSocketManager(wsManager wscontracts.Emitter)
}

// SystemService handles system-level operations
type SystemService interface {
	GetSystemMetrics(ctx context.Context) (*types.SystemMetrics, error)
	GetHardwareInfo(ctx context.Context) (*types.HardwareInfo, error)
	GetDiskUsage(ctx context.Context) (*types.DiskMetrics, error)
	GetNetworkInfo(ctx context.Context) (*types.NetworkInfo, error)
}

// DatabaseService handles database operations
type DatabaseService interface {
	DeployDatabase(ctx context.Context, dbType, password, name string, port *int, username, database, deploymentUID string) (*types.DatabaseDeploymentResult, error)
	CreateDatabase(ctx context.Context, dbType, name string) error
	DeleteDatabase(ctx context.Context, name string) error
	BackupDatabase(ctx context.Context, name string) (*types.DatabaseBackupResult, error)
	RestoreDatabase(ctx context.Context, name, backupPath string) error
	GetDatabaseStatus(ctx context.Context, name string) (types.ServiceStatus, error)
	ListBackups(ctx context.Context, name string) ([]types.DatabaseBackupResult, error)
	ConfigureAutomation(ctx context.Context, serviceUID string, config types.BackupAutomationConfig) error
	VerifyBackupStoragePath(ctx context.Context, serviceUID, storagePath string) (*types.BackupStorageVerificationResult, error)
	SetWebSocketEmitter(emitter WebSocketEmitter)
}

// CaddyService handles reverse proxy and SSL operations
type CaddyService interface {
	AddRoute(ctx context.Context, domain, target string) error
	RemoveRoute(ctx context.Context, domain string) error
	ReloadConfig(ctx context.Context) error
	GetSSLStatus(ctx context.Context, domain string) (string, error)
	GenerateSSL(ctx context.Context, domain string) error

	// Extended methods for full Caddy functionality
	Initialize(ctx context.Context) error
	InstallCaddy(ctx context.Context) error
	IsCaddyRunning(ctx context.Context) (bool, error)
	AddSite(ctx context.Context, domain, target string, ssl bool, options map[string]string, port *int, email string) error
	RemoveSite(ctx context.Context, domain string) error
	EnsureContainerInNetwork(ctx context.Context, containerName, networkName string) error
}

// MonitoringService handles system monitoring and metrics collection
type MonitoringService interface {
	StartMetricsCollection(ctx context.Context) error
	StopMetricsCollection(ctx context.Context) error
	GetMetrics(ctx context.Context, timeRange string) (*types.SystemMetrics, error)
	SetupAlerts(ctx context.Context, rules []types.AlertRule) error
	GetContainerMetrics(ctx context.Context) (map[string]*types.ContainerMetrics, error)
	GetMonitoringStatus(ctx context.Context) (*types.MonitoringStatus, error)
	SetWebSocketManager(wsManager wscontracts.Emitter)
}

// ContainerEventService handles container lifecycle event streaming
type ContainerEventService interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	SetWebSocketManager(wsManager wscontracts.Emitter)
}

// StatusService handles service and deployment status updates
type StatusService interface {
	UpdateServiceStatus(ctx context.Context, serviceUID string, status types.ServiceStatus, errorMessage string) error
	UpdateDeploymentStatus(ctx context.Context, deploymentUID string, status types.DeploymentStatus, errorMessage string, metadata map[string]interface{}) error
	SendPendingInstallations(ctx context.Context, pendingTools map[string]interface{}) error
	GetServiceEnvVars(ctx context.Context, serviceUID string) (map[string]interface{}, error)
	SetWebSocketManager(wsManager StatusSocket)
}

// WebSocketManager handles WebSocket communication
type WebSocketManager = wscontracts.Manager

// EnvironmentService handles environment variable operations
type EnvironmentService interface {
	GetServiceEnvVars(ctx context.Context, serviceUID string) (*types.ServiceEnvVarsResponse, error)
	SetWebSocketManager(wsManager wscontracts.Emitter)
}

// DeploymentService handles deployment orchestration
type DeploymentService interface {
	DeployContainer(ctx context.Context, serviceUID, imageName, deploymentUID string, envVars map[string]string, recorder types.DeploymentStepRecorder, stepID string) (*types.DeploymentResult, error)
	CleanupContainer(ctx context.Context, containerName string) error
	ListServiceContainers(ctx context.Context, serviceUID string) ([]types.ContainerInstance, error)
	GetActiveContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error)
	GetDeployingContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error)
}

// DockerfileService handles Dockerfile-based deployments
type DockerfileService interface {
	Deploy(ctx context.Context, deploymentUID, sourcePath, serviceUID string, config map[string]interface{}, envVars map[string]string, networks []string) (*types.DeploymentResult, error)
	GetDockerfileConfig(ctx context.Context, sourcePath string) (map[string]interface{}, error)
}

// NixpacksService handles Nixpacks build system integration
type NixpacksService interface {
	Deploy(ctx context.Context, deploymentUID, sourcePath, serviceUID string, planData map[string]interface{}, networks []string) (*types.DeploymentResult, error)
	GeneratePlan(ctx context.Context, sourcePath string) (*types.NixpacksPlan, error)
}

// DockerComposeService handles docker-compose based deployments
type DockerComposeService interface {
	Deploy(ctx context.Context, req *types.DockerComposeDeploymentRequest) (*types.DeploymentResult, error)
}

// UpdateService handles agent self-updates
type UpdateService interface {
	CheckForUpdate(ctx context.Context) (*types.UpdateMetadata, error)
	DownloadUpdate(ctx context.Context, metadata *types.UpdateMetadata) (string, error)
	ValidateUpdate(ctx context.Context, filePath string, metadata *types.UpdateMetadata) error
	ApplyUpdate(ctx context.Context, metadata *types.UpdateMetadata, filePath string) error
	StartAutoUpdateLoop(ctx context.Context) error
	StopAutoUpdateLoop() error
}

// CommandService handles whitelisted command execution
type CommandService interface {
	ExecuteWhitelistedCommand(ctx context.Context, commandID string, args map[string]string) (*types.CommandResult, error)
	GetAvailableCommands() []types.WhitelistedCommand
	IsCommandWhitelisted(commandID string) bool
}

// AgentLogService handles agent log operations
type AgentLogService interface {
	GetAgentLogs(ctx context.Context, lines int) ([]string, error)
}
