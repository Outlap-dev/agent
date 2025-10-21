package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"pulseup-agent-go/internal/bootstrap"
	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/internal/enrollment"
	enrollmentbootstrap "pulseup-agent-go/internal/enrollment/bootstrap"
	"pulseup-agent-go/internal/handlers"
	"pulseup-agent-go/internal/handlers/routes"
	"pulseup-agent-go/internal/security"
	"pulseup-agent-go/internal/websocket"
	wsbootstrap "pulseup-agent-go/internal/websocket/bootstrap"
	wsclient "pulseup-agent-go/internal/websocket/client"
	"pulseup-agent-go/pkg/logger"
	"pulseup-agent-go/pkg/types"
)

// ServiceContainer manages all services and their dependencies
type ServiceContainer struct {
	config     *config.Config
	logger     *logger.Logger // Logger for container's own logs
	baseLogger *logger.Logger // Clean logger to pass to services

	runtime        *bootstrap.RuntimeEnvironment
	servicesBundle *serviceBundle

	// Core services
	handlerRegistry *handlers.Registry

	// mTLS and enrollment services
	certManager *security.CertificateManager
	enroller    *enrollment.Enroller
	mtlsClient  *websocket.MTLSClient
	wsAdapter   *wsbootstrap.Adapter

	// Business services
	dockerService         DockerService
	gitService            GitService
	buildService          BuildService
	systemService         SystemService
	databaseService       DatabaseService
	caddyService          CaddyService
	statusService         StatusService
	deploymentService     DeploymentService
	domainService         handlers.DomainService
	dockerfileService     DockerfileService
	nixpacksService       NixpacksService
	dockerComposeService  DockerComposeService
	monitoringService     MonitoringService
	containerEventService ContainerEventService
	updateService         UpdateService
	commandService        CommandService
	agentLogService       AgentLogService
	sessionManager        *AgentSession

	// Service implementations
	dockerSvc         *DockerServiceImpl
	gitSvc            *GitServiceImpl
	buildSvc          *BuildServiceImpl
	systemSvc         *SystemServiceImpl
	databaseSvc       *DatabaseServiceImpl
	caddySvc          *caddyService
	statusSvc         *StatusServiceImpl
	deploymentSvc     *DeploymentServiceImpl
	dockerfileSvc     *DockerfileServiceImpl
	nixpacksSvc       *NixpacksServiceImpl
	dockerComposeSvc  *DockerComposeServiceImpl
	monitoringSvc     *MonitoringServiceImpl
	containerEventSvc *ContainerEventServiceImpl
	updateSvc         *updateService
	commandSvc        *commandService
	hardwareReporter  *HardwareReporter
	domainMgr         *DomainManager
}

// NewServiceContainer creates a new service container
func NewServiceContainer(cfg *config.Config, logger *logger.Logger) (*ServiceContainer, error) {
	runtimeEnv := bootstrap.NewRuntimeEnvironment(cfg, logger)

	container := &ServiceContainer{
		config:     cfg,
		logger:     logger.With("service", "service_container"),
		baseLogger: logger,
		runtime:    runtimeEnv,
	}

	return container, nil
}

// Initialize sets up all services and their dependencies
func (c *ServiceContainer) Initialize(ctx context.Context) error {
	c.logger.Info("Initializing service container")

	// Ensure runtime environment is ready
	if c.runtime == nil {
		c.runtime = bootstrap.NewRuntimeEnvironment(c.config, c.baseLogger)
	}

	if c.runtime != nil {
		c.runtime.LogJoinTokenStatus(c.logger)
		c.certManager = c.runtime.CertManager
		c.handlerRegistry = c.runtime.HandlerRegistry

		if bundle := c.runtime.WebsocketBundle; bundle != nil {
			c.mtlsClient = bundle.Client
			c.wsAdapter = bundle.Adapter
		}
	}

	// Initialize business services via bundle
	c.servicesBundle = newServiceBundle(c.config, c.baseLogger, c.wsAdapter, c.logger)
	c.servicesBundle.apply(c)

	if c.sessionManager == nil && c.updateService != nil {
		c.sessionManager = NewAgentSession(c.config, c.updateService, c.baseLogger)
	}

	// Prepare hardware reporter to publish inventory details on initial connection
	c.hardwareReporter = NewHardwareReporter(c.baseLogger, c.systemService, c.wsAdapter)
	if c.mtlsClient != nil {
		c.mtlsClient.RegisterOnConnected(func(connCtx context.Context, _ *wsclient.WebSocketClient) error {
			if c.hardwareReporter == nil {
				return nil
			}
			return c.hardwareReporter.Report(connCtx)
		})
	}

	// Initialize enroller if join token is provided (after services for system info provider)
	if c.runtime != nil && c.runtime.JoinTokenProvided {
		apiURL := bootstrap.ConvertWebSocketToHTTP(c.config.WebSocketURL)
		c.enroller = enrollmentbootstrap.NewEnroller(c.config, apiURL, c.baseLogger, c.systemService)
	}

	// Register handlers
	if err := c.registerHandlers(); err != nil {
		return fmt.Errorf("failed to register handlers: %w", err)
	}

	// Register WebSocket handlers
	c.registerWebSocketHandlers()

	return nil
}

// Start starts all services
func (c *ServiceContainer) Start(ctx context.Context) error {
	// Handle enrollment if join token is provided and no valid certificate exists yet
	if c.sessionManager != nil {
		c.sessionManager.SetContext(ctx)
	}

	hasCertificate := c.certManager != nil && c.certManager.HasCertificate()
	if hasCertificate {
		_, err := c.certManager.GetCertificateInfo()
		if err != nil {
			c.logger.Warn("Failed to read existing certificate info", "error", err)
		}
	} else if c.enroller != nil {
		c.logger.Info("Join token provided, attempting agent enrollment")
		result, err := c.enroller.Enroll()
		if err != nil {
			return fmt.Errorf("agent enrollment failed: %w", err)
		}

		if result.Enrolled {
			c.logger.Info("Agent enrolled successfully",
				"server_uid", result.ServerUID,
				"serial_number", result.SerialNumber,
				"expires", result.NotAfter)
		} else {
			c.logger.Info("Agent already enrolled", "message", result.Message)
		}
		hasCertificate = c.certManager.HasCertificate()
	}

	if !hasCertificate {
		return fmt.Errorf("no client certificate available; provide a join token to enroll the agent")
	}

	c.logger.Info("Starting WebSocket client with mTLS", "url", c.config.WebSocketURL)
	
	if err := c.mtlsClient.StartWithAutoRenewal(ctx); err != nil {
		return fmt.Errorf("failed to establish mTLS websocket connection: %w", err)
	}

	c.logger.Info("Waiting for WebSocket connection to establish...")
	
	// Wait for initial connection to be established, continuing to retry until success or context cancellation
	warningInterval := 30 * time.Second
	waitTicker := time.NewTicker(100 * time.Millisecond)
	defer waitTicker.Stop()

	firstAttempt := time.Now()
	lastWarning := firstAttempt

	for {
		if c.mtlsClient.IsConnected() {
			c.logger.Info("WebSocket connection established", 
				"elapsed", time.Since(firstAttempt).Round(time.Second))
			break
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled while waiting for connection")
		case <-waitTicker.C:
			if time.Since(lastWarning) >= warningInterval {
				c.logger.Warn("Still waiting for WebSocket connection", 
					"elapsed", time.Since(firstAttempt).Round(time.Second))
				lastWarning = time.Now()
			}
		}
	}

	// Start background services
	go c.startBackgroundServices(ctx)

	// Keep the main goroutine alive
	<-ctx.Done()
	return nil
}

// Shutdown gracefully shuts down all services
func (c *ServiceContainer) Shutdown(ctx context.Context) error {
	c.logger.Info("Shutting down services")

	// Stop version check service
	// Stop update service
	if c.updateService != nil {
		if err := c.updateService.StopAutoUpdateLoop(); err != nil {
			c.logger.Error("Error stopping update service", "error", err)
		}
	}

	// Stop container event service
	if c.containerEventService != nil {
		if err := c.containerEventService.Stop(ctx); err != nil {
			c.logger.Error("Error stopping container event service", "error", err)
		}
	}

	// Stop monitoring service
	if c.monitoringService != nil {
		if err := c.monitoringService.StopMetricsCollection(ctx); err != nil {
			c.logger.Error("Error stopping monitoring service", "error", err)
		}
	}

	// Disconnect WebSocket clients
	if c.mtlsClient != nil {
		if err := c.mtlsClient.Disconnect(); err != nil {
			c.logger.Error("Error disconnecting mTLS websocket", "error", err)
		}
	}

	c.logger.Info("All services shut down")
	return nil
}

// registerHandlers registers all command handlers
func (c *ServiceContainer) registerHandlers() error {
	// Create service provider for handlers
	serviceProvider := &serviceProviderImpl{
		dockerService:        c.dockerService,
		gitService:           c.gitService,
		buildService:         c.buildService,
		systemService:        c.systemService,
		databaseService:      c.databaseService,
		caddyService:         c.caddyService,
		statusService:        c.statusService,
		deploymentService:    c.deploymentService,
		domainService:        c.domainService,
		dockerfileService:    c.dockerfileService,
		nixpacksService:      c.nixpacksService,
		dockerComposeService: c.dockerComposeService,
		monitoringService:    c.monitoringService,
		updateService:        c.updateService,
		commandService:       c.commandService,
		agentLogService:      c.agentLogService,
		wsManager:            c.wsAdapter,
	}

	// Register handlers
	routes.RegisterAll(c, serviceProvider)

	return nil
}

// registerWebSocketHandlers registers WebSocket message handlers
func (c *ServiceContainer) registerWebSocketHandlers() {
	register := func(event string, handler func(json.RawMessage) (*types.CommandResponse, error)) {
		if c.wsAdapter == nil {
			return
		}
		c.wsAdapter.RegisterHandler(event, handler)
	}

	// Register command handler for wrapped commands
	register("command", c.handleCommand)
	// Register call handler for call-based messages
	register("call", c.handleCall)
	register("agent.config_updated", c.handleAgentConfigUpdate)

	// Register direct event handlers for each command
	allHandlers := c.handlerRegistry.GetAllHandlers()
	for command, handler := range allHandlers {
		// Create a closure to capture the handler
		h := handler
		register(command, func(data json.RawMessage) (*types.CommandResponse, error) {
			ctx := context.Background()
			return h.Handle(ctx, data)
		})
	}
}

// handleCommand processes incoming commands
func (c *ServiceContainer) handleCommand(data json.RawMessage) (*types.CommandResponse, error) {
	var request types.CommandRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid command format",
		}, nil
	}

	ctx := context.Background()
	return c.handlerRegistry.HandleCommand(ctx, request.Command, request.Data)
}

// handleCall processes incoming call-based messages
func (c *ServiceContainer) handleCall(data json.RawMessage) (*types.CommandResponse, error) {
	var callMessage types.WSCallMessage
	if err := json.Unmarshal(data, &callMessage); err != nil {
		c.logger.Error("Failed to unmarshal call message", "error", err, "data", string(data))
		return &types.CommandResponse{
			Success: false,
			Error:   "invalid call message format",
		}, nil
	}

	c.logger.Debug("Processing call message", "call_id", callMessage.CallID, "event", callMessage.Event)

	// Route the call to the appropriate handler based on the event
	ctx := context.Background()
	response, err := c.handlerRegistry.HandleCommand(ctx, callMessage.Event, callMessage.Data)

	if err != nil {
		c.logger.Error("Handler error", "event", callMessage.Event, "call_id", callMessage.CallID, "error", err)
		return &types.CommandResponse{
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return response, nil
}

// startBackgroundServices starts services that run in the background
func (c *ServiceContainer) startBackgroundServices(ctx context.Context) {
	// Start container event watcher
	if c.containerEventService != nil {
		if err := c.containerEventService.Start(ctx); err != nil {
			c.logger.Error("Failed to start container event service", "error", err)
		}
	}

	// Start monitoring service
	if err := c.monitoringService.StartMetricsCollection(ctx); err != nil {
		c.logger.Error("Failed to start monitoring service", "error", err)
	}

}

func (c *ServiceContainer) handleAgentConfigUpdate(data json.RawMessage) (*types.CommandResponse, error) {
	if c.sessionManager == nil {
		return &types.CommandResponse{Success: true}, nil
	}

	var payload types.AgentConfigPayload
	if len(data) > 0 {
		if err := json.Unmarshal(data, &payload); err != nil {
			c.logger.Error("Failed to parse agent config payload", "error", err)
			return &types.CommandResponse{Success: false, Error: "invalid agent config payload"}, nil
		}
	}

	c.sessionManager.ApplyConfig(payload)
	return &types.CommandResponse{Success: true}, nil
}

// serviceProviderImpl implements the ServiceProvider interface
type serviceProviderImpl struct {
	dockerService        DockerService
	gitService           GitService
	buildService         BuildService
	systemService        SystemService
	databaseService      DatabaseService
	caddyService         CaddyService
	statusService        StatusService
	deploymentService    DeploymentService
	domainService        handlers.DomainService
	dockerfileService    DockerfileService
	nixpacksService      NixpacksService
	dockerComposeService DockerComposeService
	monitoringService    MonitoringService
	updateService        UpdateService
	commandService       CommandService
	agentLogService      AgentLogService
	wsManager            handlers.WebSocketManager
}

func (sp *serviceProviderImpl) GetDockerService() handlers.DockerService {
	return sp.dockerService
}

func (sp *serviceProviderImpl) GetGitService() handlers.GitService {
	return sp.gitService
}

func (sp *serviceProviderImpl) GetBuildService() handlers.BuildService {
	return sp.buildService
}

func (sp *serviceProviderImpl) GetSystemService() handlers.SystemService {
	return sp.systemService
}

func (sp *serviceProviderImpl) GetWebSocketManager() handlers.WebSocketManager {
	return sp.wsManager
}

func (sp *serviceProviderImpl) GetStatusService() handlers.StatusService {
	return sp.statusService
}

func (sp *serviceProviderImpl) GetCaddyService() handlers.CaddyService {
	return sp.caddyService
}

func (sp *serviceProviderImpl) GetDomainService() handlers.DomainService {
	return sp.domainService
}

func (sp *serviceProviderImpl) GetEnvironmentService() handlers.EnvironmentService {
	// TODO: Implement Environment service
	return nil
}

func (sp *serviceProviderImpl) GetDeploymentService() handlers.DeploymentService {
	return sp.deploymentService
}

func (sp *serviceProviderImpl) GetDockerfileService() handlers.DockerfileService {
	return sp.dockerfileService
}

func (sp *serviceProviderImpl) GetNixpacksService() handlers.NixpacksService {
	return sp.nixpacksService
}

func (sp *serviceProviderImpl) GetDockerComposeService() handlers.DockerComposeService {
	return sp.dockerComposeService
}

func (sp *serviceProviderImpl) GetMonitoringService() handlers.MonitoringService {
	return sp.monitoringService
}

func (sp *serviceProviderImpl) GetDatabaseService() handlers.DatabaseService {
	return sp.databaseService
}

func (sp *serviceProviderImpl) GetUpdateService() handlers.UpdateService {
	return sp.updateService
}

func (sp *serviceProviderImpl) GetCommandService() handlers.CommandService {
	return sp.commandService
}

func (sp *serviceProviderImpl) GetAgentLogService() handlers.AgentLogService {
	return sp.agentLogService
}

// HandlerRegistry exposes the handler registry for route registration.
func (c *ServiceContainer) HandlerRegistry() *handlers.Registry {
	return c.handlerRegistry
}

// BaseLogger provides the base logger for route registration.
func (c *ServiceContainer) BaseLogger() *logger.Logger {
	return c.baseLogger
}

// APIBaseURL returns the base API URL for controller helpers.
func (c *ServiceContainer) APIBaseURL() string {
	return bootstrap.APIBaseURL(c.config)
}
