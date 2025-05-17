from typing import Optional
import logging
from src.config.config_manager import ConfigManager
from src.services.service_registry import ServiceRegistry
from src.services.service_manager import ServiceManager
from src.services.setup_service import SetupService
from src.installations.installation_manager import InstallationManager
from src.utils.command_registry import CommandRegistry
from src.services.github_clone_service import GithubCloneService
from src.services.build_service import BuildService
from src.services.docker_service import DockerService
from src.services.nixpacks_service import NixpacksService
from src.utils.singleton import Singleton
from src.services.status_service import StatusService

logger = logging.getLogger(__name__)

class ServiceContainer(Singleton):
    """Container for initializing and managing core services."""
    
    def __init__(self):
        super().__init__()
        self._config = ConfigManager()
        self._registry = ServiceRegistry()
    
    def _initialize_base_services(self) -> bool:
        """Initialize services with no dependencies."""
        try:
            # Initialize installation manager
            installation_manager = InstallationManager(self._config.config_path)
            self._registry.register(InstallationManager, installation_manager)
            
            # Initialize command registry
            command_registry = CommandRegistry()
            self._registry.register(CommandRegistry, command_registry)
            
            # Initialize setup service
            setup_service = SetupService()
            self._registry.register(SetupService, setup_service)
            
            # Initialize GitHub clone service
            github_clone_service = GithubCloneService()
            self._registry.register(GithubCloneService, github_clone_service)
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize base services: {e}")
            logger.exception(e)
            return False
    
    def _initialize_dependent_services(self) -> bool:
        """Initialize services that depend on other services."""
        try:
            # Initialize Docker service first
            docker_service = DockerService()
            self._registry.register(DockerService, docker_service)
            
            # Initialize Nixpacks service
            nixpacks_service = NixpacksService()
            self._registry.register(NixpacksService, nixpacks_service)
            
            # Initialize build service (depends on Docker and Nixpacks)
            build_service = BuildService(docker_service, nixpacks_service)
            self._registry.register(BuildService, build_service)
            
            # Set build service on github clone service
            github_clone_service = self._registry.get(GithubCloneService)
            if github_clone_service:
                github_clone_service.set_build_service(build_service)
            else:
                logger.error("GitHub clone service not found in registry")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize dependent services: {e}")
            logger.exception(e)
            return False
        
    async def initialize(self) -> bool:
        """Initialize all core services."""
        try:
            # Load configuration first
            if not self._config.load_configuration():
                return False
                
            if not self._config.validate_config():
                logger.error("Invalid configuration. Please check required environment variables.")
                return False
            
            # Initialize services in dependency order
            if not self._initialize_base_services():
                return False
                
            if not self._initialize_dependent_services():
                return False
            
            # Initialize service manager last (depends on all other services)
            service_manager = ServiceManager(
                self._config.websocket_url,
                self._config.agent_token,
                self._config.config_path
            )
            self._registry.register(ServiceManager, service_manager)
            
            # Ensure the BuildService in the registry gets the SocketManager 
            # from the initialized ServiceManager.
            build_service_in_registry = self._registry.get(BuildService)
            if build_service_in_registry:
                if service_manager.socket_manager:
                    build_service_in_registry.set_socket_manager(service_manager.socket_manager)
                    logger.info("Successfully set SocketManager on the BuildService instance in the global registry.")
                else:
                    logger.error("ServiceManager's SocketManager is None. Cannot configure BuildService in registry.")
                    return False
            else:
                logger.error("BuildService not found in registry. Cannot set SocketManager.")
                return False
            
            # Register the StatusService from the ServiceManager in the registry
            if service_manager.status_service:
                self._registry.register(StatusService, service_manager.status_service)
                logger.info("Successfully registered StatusService from ServiceManager in the global registry.")
            else:
                logger.error("ServiceManager's StatusService is None. Cannot register in global registry.")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize services: {e}")
            logger.exception(e)
            return False
    
    @property
    def config(self) -> ConfigManager:
        """Get the config manager instance."""
        return self._config
    
    @property
    def registry(self) -> ServiceRegistry:
        """Get the service registry instance."""
        return self._registry
    
    @property
    def service_manager(self) -> Optional[ServiceManager]:
        """Get the service manager instance."""
        return self._registry.get(ServiceManager)
    
    @property
    def installation_manager(self) -> Optional[InstallationManager]:
        """Get the installation manager instance."""
        return self._registry.get(InstallationManager)
    
    @property
    def setup_service(self) -> Optional[SetupService]:
        """Get the setup service instance."""
        return self._registry.get(SetupService) 