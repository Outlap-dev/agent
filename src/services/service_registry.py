from typing import Dict, Any, Optional, Type, TypeVar
import logging
from src.services.github_clone_service import GithubCloneService
from src.services.build_service import BuildService
from src.services.setup_service import SetupService
from src.services.status_service import StatusService
from src.services.version_check_service import VersionCheckService
from src.utils.command_registry import CommandRegistry
from src.installations.installation_manager import InstallationManager
from src.services.docker_service import DockerService
from src.services.nixpacks_service import NixpacksService
from src.services.dockerfile_service import DockerfileService

logger = logging.getLogger(__name__)

T = TypeVar('T')

class ServiceRegistry:
    """
    Singleton registry for managing service instances.
    Provides centralized access to all services in the application.
    """
    _instance: Optional['ServiceRegistry'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        self._services: Dict[str, Any] = {}
        
    def register(self, service_class: Type[T], instance: T) -> None:
        """Register a service instance."""
        service_name = service_class.__name__
        self._services[service_name] = instance
    
    def get(self, service_class: Type[T]) -> Optional[T]:
        """Get a service instance by its class."""
        return self._services.get(service_class.__name__)
    
    @property
    def github_clone_service(self) -> Optional[GithubCloneService]:
        """Get the GitHub clone service instance."""
        return self.get(GithubCloneService)
    
    @property
    def build_service(self) -> Optional[BuildService]:
        """Get the build service instance."""
        return self.get(BuildService)
    
    @property
    def setup_service(self) -> Optional[SetupService]:
        """Get the setup service instance."""
        return self.get(SetupService)
    
    @property
    def status_service(self) -> Optional[StatusService]:
        """Get the status service instance."""
        return self.get(StatusService)
    
    @property
    def command_registry(self) -> Optional[CommandRegistry]:
        """Get the command registry instance."""
        return self.get(CommandRegistry)
    
    @property
    def installation_manager(self) -> Optional[InstallationManager]:
        """Get the installation manager instance."""
        return self.get(InstallationManager)
    
    @property
    def docker_service(self) -> Optional[DockerService]:
        """Get the Docker service instance."""
        return self.get(DockerService)
    
    @property
    def nixpacks_service(self) -> Optional[NixpacksService]:
        """Get the Nixpacks service instance."""
        return self.get(NixpacksService)
    
    @property
    def dockerfile_service(self) -> Optional[DockerfileService]:
        """Get the Dockerfile service instance."""
        return self.get(DockerfileService)
    
    @property
    def version_check_service(self) -> Optional[VersionCheckService]:
        """Get the version check service instance."""
        return self.get(VersionCheckService)
    
    def clear(self) -> None:
        """Clear all registered services."""
        self._services.clear()
        
    def has_service(self, service_class: Type[T]) -> bool:
        """Check if a service is registered."""
        return service_class.__name__ in self._services 