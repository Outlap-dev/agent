package services

import (
	"pulseup-agent-go/internal/config"
	"pulseup-agent-go/pkg/logger"
)

type serviceBundle struct {
	dockerImpl            *DockerServiceImpl
	dockerService         DockerService
	gitImpl               *GitServiceImpl
	gitService            GitService
	buildImpl             *BuildServiceImpl
	buildService          BuildService
	systemImpl            *SystemServiceImpl
	systemService         SystemService
	databaseImpl          *DatabaseServiceImpl
	databaseService       DatabaseService
	caddyImpl             *caddyService
	caddyService          CaddyService
	statusImpl            *StatusServiceImpl
	statusService         StatusService
	containerEventImpl    *ContainerEventServiceImpl
	containerEventService ContainerEventService
	deploymentImpl        *DeploymentServiceImpl
	deploymentService     DeploymentService
	domainManager         *DomainManager
	dockerfileImpl        *DockerfileServiceImpl
	dockerfileService     DockerfileService
	nixpacksImpl          *NixpacksServiceImpl
	nixpacksService       NixpacksService
	dockerComposeImpl     *DockerComposeServiceImpl
	dockerComposeService  DockerComposeService
	monitoringImpl        *MonitoringServiceImpl
	monitoringService     MonitoringService
	versionCheckImpl      *versionCheckService
	versionCheckService   VersionCheckService
	commandImpl           *commandService
	commandService        CommandService
	updateImpl            *updateService
	updateService         UpdateService
	packageImpl           *PackageServiceImpl
	packageService        PackageService
	agentLogService       AgentLogService
}

func newServiceBundle(cfg *config.Config, baseLogger *logger.Logger, wsManager WebSocketManager, containerLogger *logger.Logger, ipcClient IPCClient) *serviceBundle {
	bundle := &serviceBundle{}

	bundle.dockerImpl = NewDockerService(baseLogger)
	bundle.dockerService = bundle.dockerImpl

	bundle.gitImpl = NewGitService(baseLogger)
	bundle.gitImpl.SetWebSocketManager(wsManager)
	bundle.gitService = bundle.gitImpl

	bundle.buildImpl = NewBuildService(baseLogger, bundle.dockerService)
	bundle.buildImpl.SetWebSocketManager(wsManager)
	bundle.buildService = bundle.buildImpl

	bundle.systemImpl = NewSystemService(baseLogger)
	bundle.systemService = bundle.systemImpl

	bundle.databaseImpl = NewDatabaseService(baseLogger, bundle.dockerService)
	bundle.databaseImpl.SetWebSocketEmitter(wsManager)
	bundle.databaseService = bundle.databaseImpl

	bundle.caddyImpl = NewCaddyService(bundle.dockerImpl.client, baseLogger).(*caddyService)
	bundle.caddyService = bundle.caddyImpl

	bundle.statusImpl = NewStatusService(baseLogger)
	bundle.statusImpl.SetWebSocketManager(wsManager)
	bundle.statusService = bundle.statusImpl

	bundle.containerEventImpl = NewContainerEventService(baseLogger, bundle.dockerImpl.client, bundle.statusService)
	bundle.containerEventImpl.SetWebSocketManager(wsManager)
	bundle.containerEventService = bundle.containerEventImpl

	bundle.deploymentImpl = NewDeploymentService(baseLogger, bundle.dockerService)
	bundle.deploymentService = bundle.deploymentImpl

	if mgr, err := NewDomainManager(baseLogger, bundle.caddyService, bundle.deploymentService); err != nil {
		if containerLogger != nil {
			containerLogger.Warn("Failed to initialize domain manager", "error", err)
		}
	} else {
		bundle.domainManager = mgr
		bundle.deploymentImpl.SetDomainRefresher(mgr)
	}

	bundle.dockerfileImpl = NewDockerfileService(baseLogger, bundle.dockerService, bundle.deploymentService, bundle.statusService)
	bundle.dockerfileService = bundle.dockerfileImpl

	bundle.nixpacksImpl = NewNixpacksService(baseLogger, wsManager, bundle.deploymentService)
	bundle.nixpacksService = bundle.nixpacksImpl

	bundle.dockerComposeImpl = NewDockerComposeService(baseLogger)
	bundle.dockerComposeService = bundle.dockerComposeImpl

	bundle.monitoringImpl = NewMonitoringService(baseLogger, bundle.dockerImpl.client)
	bundle.monitoringImpl.SetWebSocketManager(wsManager)
	bundle.monitoringService = bundle.monitoringImpl

	bundle.versionCheckImpl = NewVersionCheckService(cfg, baseLogger).(*versionCheckService)
	bundle.versionCheckService = bundle.versionCheckImpl

	bundle.commandImpl = NewCommandService(baseLogger, bundle.dockerService, bundle.systemService).(*commandService)
	bundle.commandService = bundle.commandImpl

	bundle.updateImpl = NewUpdateService(cfg, baseLogger, bundle.commandService).(*updateService)
	bundle.updateService = bundle.updateImpl

	if ipcClient != nil {
		bundle.packageService = NewPackageServiceIPC(baseLogger, ipcClient)
	} else {
		bundle.packageImpl = NewPackageService(baseLogger)
		bundle.packageService = bundle.packageImpl
	}

	bundle.agentLogService = NewAgentLogService(baseLogger)

	return bundle
}

func (b *serviceBundle) apply(c *ServiceContainer) {
	if b == nil {
		return
	}

	c.dockerSvc = b.dockerImpl
	c.dockerService = b.dockerService

	c.gitSvc = b.gitImpl
	c.gitService = b.gitService

	c.buildSvc = b.buildImpl
	c.buildService = b.buildService

	c.systemSvc = b.systemImpl
	c.systemService = b.systemService

	c.databaseSvc = b.databaseImpl
	c.databaseService = b.databaseService

	c.caddySvc = b.caddyImpl
	c.caddyService = b.caddyService

	c.statusSvc = b.statusImpl
	c.statusService = b.statusService

	c.containerEventSvc = b.containerEventImpl
	c.containerEventService = b.containerEventService

	c.deploymentSvc = b.deploymentImpl
	c.deploymentService = b.deploymentService

	if b.domainManager != nil {
		c.domainMgr = b.domainManager
		c.domainService = b.domainManager
	}

	c.dockerfileSvc = b.dockerfileImpl
	c.dockerfileService = b.dockerfileService

	c.nixpacksSvc = b.nixpacksImpl
	c.nixpacksService = b.nixpacksService

	c.dockerComposeSvc = b.dockerComposeImpl
	c.dockerComposeService = b.dockerComposeService

	c.monitoringSvc = b.monitoringImpl
	c.monitoringService = b.monitoringService

	c.versionCheckSvc = b.versionCheckImpl
	c.versionCheckService = b.versionCheckService

	c.commandSvc = b.commandImpl
	c.commandService = b.commandService

	c.updateSvc = b.updateImpl
	c.updateService = b.updateService

	c.packageSvc = b.packageImpl
	c.packageService = b.packageService

	c.agentLogService = b.agentLogService
}
