package handlers

import (
	"context"
	"encoding/json"
	"fmt"

	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// Handler defines the interface for all command handlers
type Handler interface {
	// GetCommand returns the command name this handler handles
	GetCommand() string

	// Handle processes the command with the given data
	Handle(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error)
}

// CommandFunc represents the signature for controller method handlers.
type CommandFunc func(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error)

// Controller represents a component that exposes a BaseHandler for routing helpers.
type Controller interface {
	Base() *BaseHandler
}

// BaseHandler provides common functionality for all handlers
type BaseHandler struct {
	logger   *logger.Logger
	services ServiceProvider
	command  string
}

// ServiceProvider interface for accessing services
type ServiceProvider interface {
	GetDockerService() DockerService
	GetGitService() GitService
	GetBuildService() BuildService
	GetSystemService() SystemService
	GetDatabaseService() DatabaseService
	GetStatusService() StatusService
	GetWebSocketManager() WebSocketManager
	GetCaddyService() CaddyService
	GetEnvironmentService() EnvironmentService
	GetDeploymentService() DeploymentService
	GetDockerfileService() DockerfileService
	GetNixpacksService() NixpacksService
	GetDockerComposeService() DockerComposeService
	GetMonitoringService() MonitoringService
	GetUpdateService() UpdateService
	GetCommandService() CommandService
	GetAgentLogService() AgentLogService
	GetDomainService() DomainService
}

// Service interfaces
type DockerService interface {
	ListContainers(ctx context.Context) ([]types.ServiceInfo, error)
	StartContainer(ctx context.Context, serviceUID string) error
	StopContainer(ctx context.Context, serviceUID string) error
	RestartContainer(ctx context.Context, serviceUID string) error
	GetContainerLogs(ctx context.Context, serviceUID string) ([]string, error)
	GetContainerLogsByName(ctx context.Context, containerName string) ([]string, error)
	StartContainerByName(ctx context.Context, containerName string) error
	StopContainerByName(ctx context.Context, containerName string) error
	StreamContainerLogs(ctx context.Context, serviceUID string) (<-chan string, error)
	GetContainerStatus(ctx context.Context, serviceUID string) (types.ServiceStatus, error)
	RemoveContainer(ctx context.Context, serviceUID string) error
	ContainerExists(ctx context.Context, containerName string) (bool, error)
	FindContainersByLabel(ctx context.Context, labelKey, labelValue string) ([]string, error)
	CleanupOldDeploymentImages(ctx context.Context, serviceUID string) error
	GetContainerStats(ctx context.Context, containerID string) (*types.ContainerMetrics, error)
	TagImage(ctx context.Context, source, target string) error
}

type GitService interface {
	CloneRepository(ctx context.Context, gitURL, branch, destination string) error
	GetCommitSHA(ctx context.Context, repoPath string) (string, error)
	GetCommitMessage(ctx context.Context, repoPath, sha string) (string, error)
	CloneGitHubRepo(ctx context.Context, serviceUID string) (*types.CloneResult, error)
	PullGitHubRepo(ctx context.Context, serviceUID string) (*types.CloneResult, error)
	GetGitHubRepoInfo(ctx context.Context, serviceUID string) (*types.GitHubRepoInfo, error)
	CloneGitHubRepoDirectly(ctx context.Context, repoURL, accessToken, clonePath, branch string) (*types.CloneResult, error)
	PullGitHubRepoDirectly(ctx context.Context, clonePath, accessToken, branch string) (*types.CloneResult, error)
}

type BuildService interface {
	BuildApplication(ctx context.Context, config *types.BuildConfig) (*types.BuildResult, error)
	DeployApplication(ctx context.Context, config *types.DeployConfig) (*types.DeployResult, error)
	GetBuildHistory(ctx context.Context, appName string) ([]types.BuildResult, error)
	GetDeploymentStatus(ctx context.Context, appName string) (*types.AppDeploymentStatus, error)
	PrepareBuild(ctx context.Context, clonePath, serviceUID string, isInitialClone bool) error
	GetBuildCommandInfo(ctx context.Context, serviceUID string) (*types.BuildCommandInfo, error)
	RecordBuildResult(ctx context.Context, serviceUID string, result *types.BuildResult) error
}

type SystemService interface {
	GetSystemMetrics(ctx context.Context) (*types.SystemMetrics, error)
	GetHardwareInfo(ctx context.Context) (*types.HardwareInfo, error)
}

type WebSocketManager interface {
	Send(event string, data interface{}) error
	Emit(event string, data interface{}) error
	Call(event string, data interface{}) (map[string]interface{}, error)
	SendCallResponse(callID string, success bool, data interface{}, errorMsg string) error
	IsConnected() bool
}

type StatusService interface {
	UpdateServiceStatus(ctx context.Context, serviceUID string, status types.ServiceStatus, errorMessage string) error
	UpdateDeploymentStatus(ctx context.Context, deploymentUID string, status types.DeploymentStatus, errorMessage string, metadata map[string]interface{}) error
	SendPendingInstallations(ctx context.Context, pendingTools map[string]interface{}) error
	GetServiceEnvVars(ctx context.Context, serviceUID string) (map[string]interface{}, error)
}

type CaddyService interface {
	AddRoute(ctx context.Context, domain, target string) error
	RemoveRoute(ctx context.Context, domain string) error
	ReloadConfig(ctx context.Context) error
	GetSSLStatus(ctx context.Context, domain string) (string, error)
	GenerateSSL(ctx context.Context, domain string) error
}

type EnvironmentService interface {
	GetServiceEnvVars(ctx context.Context, serviceUID string) (*types.ServiceEnvVarsResponse, error)
}

type DeploymentService interface {
	DeployContainer(ctx context.Context, serviceUID, imageName, deploymentUID string, envVars map[string]string, recorder types.DeploymentStepRecorder, stepID string) (*types.DeploymentResult, error)
	CleanupContainer(ctx context.Context, containerName string) error
	ListServiceContainers(ctx context.Context, serviceUID string) ([]types.ContainerInstance, error)
	GetActiveContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error)
	GetDeployingContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error)
}

type DockerfileService interface {
	Deploy(ctx context.Context, deploymentUID, sourcePath, serviceUID string, config map[string]interface{}, envVars map[string]string, networks []string) (*types.DeploymentResult, error)
}

type NixpacksService interface {
	Deploy(ctx context.Context, deploymentUID, sourcePath, serviceUID string, planData map[string]interface{}, networks []string) (*types.DeploymentResult, error)
	GeneratePlan(ctx context.Context, sourcePath string) (*types.NixpacksPlan, error)
}

type DockerComposeService interface {
	Deploy(ctx context.Context, req *types.DockerComposeDeploymentRequest) (*types.DeploymentResult, error)
}

type MonitoringService interface {
	StartMetricsCollection(ctx context.Context) error
	StopMetricsCollection(ctx context.Context) error
	GetMetrics(ctx context.Context, timeRange string) (*types.SystemMetrics, error)
	SetupAlerts(ctx context.Context, rules []types.AlertRule) error
	GetContainerMetrics(ctx context.Context) (map[string]*types.ContainerMetrics, error)
	GetMonitoringStatus(ctx context.Context) (*types.MonitoringStatus, error)
}

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
	SetWebSocketEmitter(emitter types.WebSocketEmitter)
}

type UpdateService interface {
	CheckForUpdate(ctx context.Context) (*types.UpdateMetadata, error)
	DownloadUpdate(ctx context.Context, metadata *types.UpdateMetadata) (string, error)
	ValidateUpdate(ctx context.Context, filePath string, metadata *types.UpdateMetadata) error
	ApplyUpdate(ctx context.Context, metadata *types.UpdateMetadata, filePath string) error
	StartAutoUpdateLoop(ctx context.Context) error
	StopAutoUpdateLoop() error
}

type CommandService interface {
	ExecuteWhitelistedCommand(ctx context.Context, commandID string, args map[string]string) (*types.CommandResult, error)
	GetAvailableCommands() []types.WhitelistedCommand
	IsCommandWhitelisted(commandID string) bool
}

type DomainService interface {
	UpsertDomain(ctx context.Context, request types.DomainProvisionRequest) (*types.DomainProxyInfo, error)
	RemoveDomain(ctx context.Context, domain string) error
	GetDomain(ctx context.Context, domain string) (*types.DomainProxyInfo, error)
	RefreshService(ctx context.Context, serviceUID string) error
}

// AgentLogService handles agent log operations
type AgentLogService interface {
	GetAgentLogs(ctx context.Context, lines int) ([]string, error)
}

// NewBaseHandler creates a new base handler
func NewBaseHandler(logger *logger.Logger, services ServiceProvider) *BaseHandler {
	return &BaseHandler{
		logger:   logger,
		services: services,
	}
}

// GetLogger returns the logger instance
func (h *BaseHandler) GetLogger() *logger.Logger {
	return h.logger
}

// GetServices returns the service provider
func (h *BaseHandler) GetServices() ServiceProvider {
	return h.services
}

// Clone creates a shallow copy of the base handler, preserving logger and services references
// while isolating command state for independent route registrations.
func (h *BaseHandler) Clone() *BaseHandler {
	if h == nil {
		return nil
	}

	clone := *h
	clone.command = ""
	return &clone
}

// SetCommand assigns the command name handled by this handler.
func (h *BaseHandler) SetCommand(command string) {
	if command == "" {
		return
	}

	if h.command == command {
		return
	}

	h.command = command

	if h.logger != nil {
		h.logger = h.logger.With("command", command)
	}
}

// GetCommand returns the command name this handler handles.
func (h *BaseHandler) GetCommand() string {
	return h.command
}

// MethodHandler adapts a controller method to the Handler interface, allowing
// controller methods to be registered directly as command handlers.
type MethodHandler struct {
	base    *BaseHandler
	method  CommandFunc
	command string
}

// NewMethodHandler creates a new handler that wraps the provided controller method.
func NewMethodHandler(base *BaseHandler, method CommandFunc) *MethodHandler {
	if method == nil {
		return nil
	}

	var cloned *BaseHandler
	if base != nil {
		cloned = base.Clone()
	}

	return &MethodHandler{
		base:   cloned,
		method: method,
	}
}

// SetCommand assigns the command name for this method handler.
func (m *MethodHandler) SetCommand(command string) {
	m.command = command
}

// GetCommand returns the command name assigned to this handler.
func (m *MethodHandler) GetCommand() string {
	return m.command
}

// Handle delegates execution to the wrapped controller method.
func (m *MethodHandler) Handle(ctx context.Context, data json.RawMessage) (*types.CommandResponse, error) {
	if m.method == nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "handler method not configured",
		}, nil
	}

	if m.base != nil {
		m.base.SetCommand(m.command)
	}

	return m.method(ctx, data)
}

// resolveActiveContainer locates the currently active container for the provided service UID.
func (h *BaseHandler) resolveActiveContainer(ctx context.Context, serviceUID string) (*types.ContainerInstance, error) {
	if serviceUID == "" {
		return nil, fmt.Errorf("service_uid is required")
	}

	deploymentService := h.services.GetDeploymentService()
	if deploymentService == nil {
		return nil, fmt.Errorf("deployment service not available")
	}

	container, err := deploymentService.GetActiveContainer(ctx, serviceUID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve active container: %w", err)
	}

	if container == nil {
		return nil, fmt.Errorf("no active container for service %s", serviceUID)
	}

	return container, nil
}

// Registry manages all command handlers
type Registry struct {
	handlers map[string]Handler
	logger   *logger.Logger
}

// NewRegistry creates a new handler registry
func NewRegistry(logger *logger.Logger) *Registry {
	return &Registry{
		handlers: make(map[string]Handler),
		logger:   logger.With("component", "handler_registry"),
	}
}

// Register adds a handler to the registry
func (r *Registry) Register(handler Handler) {
	command := handler.GetCommand()
	if command == "" {
		r.logger.Warn("attempted to register handler without command", "handler", fmt.Sprintf("%T", handler))
		return
	}

	if existing, exists := r.handlers[command]; exists {
		r.logger.Warn("overwriting handler registration", "command", command, "existing", fmt.Sprintf("%T", existing), "replacement", fmt.Sprintf("%T", handler))
	}

	r.handlers[command] = handler
}

// GetHandler returns a handler for the given command
func (r *Registry) GetHandler(command string) (Handler, bool) {
	handler, exists := r.handlers[command]
	return handler, exists
}

// GetAllHandlers returns all registered handlers
func (r *Registry) GetAllHandlers() map[string]Handler {
	return r.handlers
}

// HandleCommand processes a command using the appropriate handler
func (r *Registry) HandleCommand(ctx context.Context, command string, data json.RawMessage) (*types.CommandResponse, error) {
	handler, exists := r.GetHandler(command)
	if !exists {
		return &types.CommandResponse{
			Success: false,
			Error:   "unknown command: " + command,
		}, nil
	}

	return handler.Handle(ctx, data)
}
