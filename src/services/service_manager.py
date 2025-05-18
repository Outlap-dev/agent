import logging
from typing import Dict, Any, Optional, List

from src.services.database_service import DatabaseService
from src.services.github_clone_service import GithubCloneService
from src.services.build_service import BuildService
from src.services.nixpacks_service import NixpacksService
from src.services.docker_service import DockerService
from src.services.dockerfile_service import DockerfileService
from src.services.status_service import StatusService
from src.services.system_metrics_service import SystemMetricsService
from src.services.ssh_key_service import SSHKeyService
from src.services.setup_service import SetupService
from src.services.caddy_service import CaddyService
from src.services.deployment_service import DeploymentService
from src.services.environment_service import EnvironmentService
from src.services.container_monitor_service import ContainerMonitorService
from src.services.version_check_service import VersionCheckService
from src.websocket.socket_manager import SocketManager
from src.utils.command_registry import CommandRegistry
from src.handlers.base_handler import CommandHandler

logger = logging.getLogger(__name__)

class ServiceManager:
    """
    Centralizes the initialization and management of all services.
    Provides access to services through properties to ensure they are properly initialized.
    """
    
    def __init__(self, base_url: str, token: str, config_path: str = '/etc/pulseup-agent/config'):
        """
        Initialize the service manager.
        
        Args:
            base_url: Base URL for the websocket connection
            token: Authentication token for the websocket
            config_path: Path to the configuration directory
        """
        self.base_url = base_url
        self.token = token
        self.config_path = config_path
        
        self._command_registry = None
        self._github_clone_service = None
        self._nixpacks_service = None
        self._docker_service = None
        self._dockerfile_service = None
        self._build_service = None
        self._system_metrics_service = None
        self._ssh_key_service = None
        self._setup_service = None
        self._socket_manager = None
        self._status_service = None
        self._caddy_service = None
        self._deployment_service = None
        self._environment_service = None
        self._container_monitor_service = None
        self._database_service = None
        self._version_check_service = None

        # Auto-discovered and registered handlers
        self._auto_registered_handlers = []
        
        # Initialize all services
        self._initialize_services()
        
    def _initialize_services(self):
        """Initialize all services in the correct order."""
        
        # Initialize services that don't depend on others first
        self._command_registry = CommandRegistry()
        self._github_clone_service = GithubCloneService()
        self._nixpacks_service = NixpacksService()
        self._docker_service = DockerService()
        self._dockerfile_service = DockerfileService()
        self._setup_service = SetupService()
        self._ssh_key_service = SSHKeyService()
        self._caddy_service = CaddyService()
        self._environment_service = EnvironmentService()
        self._container_monitor_service = ContainerMonitorService()
        self._database_service = DatabaseService()
        self._version_check_service = VersionCheckService()

        # Initialize services with dependencies
        self._build_service = BuildService(
            docker_service=self.docker_service,
            nixpacks_service=self.nixpacks_service
        )
        
        self._system_metrics_service = SystemMetricsService()
        
        # Set the service manager reference in the base handler class
        # This allows all handlers to access services through the CommandHandler.get_service_manager() method
        CommandHandler.set_service_manager(self)
        
        # Register handlers
        self._register_handlers()
        
        # Initialize socket manager last since it depends on other services
        self._socket_manager = SocketManager(
            base_url=self.base_url,
            token=self.token,
        )
        
        # Initialize the status service now that we have socket_manager
        self._status_service = StatusService(
            sio=self._socket_manager.sio,
            namespace=self._socket_manager.namespace
        )

        # Initialize deployment service
        self._deployment_service = DeploymentService(
            docker_service=self.docker_service,
            caddy_service=self.caddy_service,
            status_service=self.status_service
        )
        
        # Set build_service on github_clone_service
        self._github_clone_service.set_build_service(self._build_service)
        
        # Set deployment service on nixpacks service
        self._nixpacks_service.set_deployment_service(self._deployment_service)
        
        # Set deployment service on dockerfile service
        self._dockerfile_service.set_deployment_service(self._deployment_service)
        
        # Set socket manager on services that need it
        self._build_service.set_socket_manager(self._socket_manager)
        self._environment_service.socket_manager = self._socket_manager
        self._container_monitor_service.set_socket_manager(self._socket_manager)
        self._container_monitor_service.set_docker_service(self._docker_service)
        self._version_check_service.set_socket_manager(self._socket_manager)
        
        # Set status service on nixpacks service
        self._nixpacks_service.set_status_service(self._status_service)
        
        # Set status service on dockerfile service
        self._dockerfile_service.set_status_service(self._status_service)
        
        # Set socket manager on dockerfile service
        self._dockerfile_service.set_socket_manager(self._socket_manager)
        
        # Now that socket_manager is initialized, update any handlers that need it
        self._update_handlers_with_socket_manager()
    
    def _register_handlers(self):
        """
        Register all command handlers.
        This explicit approach ensures all handlers are properly registered regardless of environment.
        """
        
        # Import handler classes
        from src.handlers.app_installation_handler import AppInstallationHandler
        from src.handlers.app_deployment_handler import AppDeploymentHandler
        from src.handlers.app_deployment_rollback_handler import AppDeploymentRollbackHandler
        from src.handlers.domain_handler import DomainHandler
        from src.handlers.stream_container_logs_handler import StreamContainerLogsHandler
        from src.handlers.stop_stream_container_logs_handler import StopStreamContainerLogsHandler
        from src.handlers.get_build_info_handler import GetBuildInfoHandler
        from src.handlers.tools_install_handler import ToolsInstallHandler
        from src.handlers.add_ssh_key_handler import AddSSHKeyHandler
        from src.handlers.restart_server_handler import RestartServerHandler
        from src.handlers.db_restart_handler import DBRestartHandler
        from src.handlers.get_hardware_info_handler import GetHardwareInfoHandler
        from src.handlers.get_live_stats_handler import GetLiveStatsHandler

        from src.handlers.get_service_logs_handler import GetServiceLogsHandler
        from src.handlers.get_deployment_logs_handler import GetDeploymentLogsHandler

        from src.handlers.mysql_backup_handler import MySQLBackupHandler
        from src.handlers.database_deployment_handler import DatabaseDeploymentHandler
        from src.handlers.service_deletion_handler import ServiceDeletionHandler
        from src.handlers.get_service_status_handler import GetServiceStatusHandler
        
        # Define list of handler classes
        handler_classes = [
            AppInstallationHandler,
            AppDeploymentHandler,
            AppDeploymentRollbackHandler,
            DomainHandler,
            StreamContainerLogsHandler, 
            StopStreamContainerLogsHandler,
            GetBuildInfoHandler,
            ToolsInstallHandler,
            AddSSHKeyHandler,
            RestartServerHandler,
            DBRestartHandler,
            GetHardwareInfoHandler,
            GetLiveStatsHandler,
            GetServiceLogsHandler,
            GetDeploymentLogsHandler,
            MySQLBackupHandler,
            DatabaseDeploymentHandler,
            ServiceDeletionHandler,
            GetServiceStatusHandler
        ]
        
        # Register each handler
        for handler_class in handler_classes:
            try:
                # Create an instance of the handler
                handler = handler_class()
                
                # Register it with the command registry
                command_name = handler.get_command_name()
                self._command_registry.register_handler(handler)
                self._auto_registered_handlers.append(handler)
                
            except Exception as e:
                logger.error(f"Error registering handler {handler_class.__name__}: {e}", exc_info=True)
        
        # Handle special inter-handler dependencies
        self._handle_handler_dependencies()        
    
    def _handle_handler_dependencies(self):
        """Handle dependencies between handlers that need references to each other"""
        try:
            # Find the stream_container_logs and stop_stream_container_logs handlers
            stream_handler = None
            stop_handler = None
            
            for handler in self._auto_registered_handlers:
                if handler.get_command_name() == 'stream_container_logs':
                    stream_handler = handler
                elif handler.get_command_name() == 'stop_stream_container_logs':
                    stop_handler = handler
            
            # Set up the dependency if both handlers are present
            if stream_handler and stop_handler and hasattr(stop_handler, 'stream_handler'):
                stop_handler.stream_handler = stream_handler
        except Exception as e:
            logger.warning(f"Error handling inter-handler dependencies: {e}")
    
    def _update_handlers_with_socket_manager(self):
        """Update any handlers that need socket_manager after it's initialized."""
        for handler in self._auto_registered_handlers:
            # Use the common pattern for handlers that need socket_manager
            if hasattr(handler, '_socket_manager'):
                handler._socket_manager = self._socket_manager
                logger.debug(f"Updated socket_manager for handler: {handler.get_command_name()}")
    
    def register_handler(self, handler: CommandHandler) -> None:
        """
        Register a command handler with the command registry.
        
        Args:
            handler: Handler instance to register
        """
        if self._command_registry:
            self._command_registry.register_handler(handler)
        else:
            logger.error("Cannot register handler: Command registry not initialized")
    
    @property
    def command_registry(self) -> CommandRegistry:
        """Get the command registry."""
        return self._command_registry
    
    @property
    def github_clone_service(self) -> GithubCloneService:
        """Get the GitHub clone service."""
        return self._github_clone_service
    
    @property
    def nixpacks_service(self) -> NixpacksService:
        """Get the Nixpacks service."""
        return self._nixpacks_service
    
    @property
    def dockerfile_service(self) -> DockerfileService:
        """Get the Dockerfile service."""
        return self._dockerfile_service
    
    @property
    def docker_service(self) -> DockerService:
        """Get the Docker service."""
        return self._docker_service
    
    @property
    def build_service(self) -> BuildService:
        """Get the build service."""
        return self._build_service
    
    @property
    def system_metrics_service(self) -> SystemMetricsService:
        """Get the system metrics service."""
        return self._system_metrics_service
    
    @property
    def ssh_key_service(self) -> SSHKeyService:
        """Get the SSH key service."""
        return self._ssh_key_service
    
    @property
    def setup_service(self) -> SetupService:
        """Get the setup service."""
        return self._setup_service
    
    @property
    def caddy_service(self) -> CaddyService:
        """Get the Caddy service."""
        return self._caddy_service
    
    @property
    def socket_manager(self) -> SocketManager:
        """Get the socket manager."""
        return self._socket_manager
    
    @property
    def auto_registered_handlers(self) -> List[CommandHandler]:
        """Get the list of auto-registered handlers."""
        return list(self._auto_registered_handlers)
    
    @property
    def deployment_service(self) -> DeploymentService:
        """Get the deployment service."""
        return self._deployment_service
    
    @property
    def environment_service(self) -> EnvironmentService:
        """Get the environment service."""
        return self._environment_service
    
    @property
    def container_monitor_service(self) -> ContainerMonitorService:
        """Get the container monitor service."""
        return self._container_monitor_service
    
    @property
    def status_service(self) -> StatusService:
        """Get the status service."""
        return self._status_service
    
    @property
    def database_service(self) -> DatabaseService:
        """Get the database service."""
        return self._database_service
    
    @property
    def version_check_service(self) -> VersionCheckService:
        """Get the version check service."""
        return self._version_check_service
    
    async def connect(self):
        """
        Connect to the WebSocket server.
        This starts the main connection loop.
        """
        # Initialize Caddy service
        if self._caddy_service:
            try:
                await self._caddy_service.initialize()
            except Exception as e:
                logger.error(f"Error initializing Caddy service: {e}")
        
        # Start container monitor service
        if self._container_monitor_service:
            try:
                await self._container_monitor_service.start()
            except Exception as e:
                logger.error(f"Error starting container monitor service: {e}")

        # Start version check service
        if self._version_check_service:
            try:
                await self._version_check_service.start()
            except Exception as e:
                logger.error(f"Error starting version check service: {e}")
        
        if self._socket_manager:
            await self._socket_manager.connect()
        else:
            logger.error("No socket manager available to connect")
            
    async def disconnect(self):
        """
        Disconnect from the WebSocket server.
        """
        # Stop container monitor service
        if self._container_monitor_service:
            try:
                await self._container_monitor_service.stop()
            except Exception as e:
                logger.error(f"Error stopping container monitor service: {e}")

        # Stop version check service
        if self._version_check_service:
            try:
                await self._version_check_service.stop()
            except Exception as e:
                logger.error(f"Error stopping version check service: {e}")
        
        if self._socket_manager:
            await self._socket_manager.disconnect()
        else:
            logger.error("No socket manager available to disconnect") 