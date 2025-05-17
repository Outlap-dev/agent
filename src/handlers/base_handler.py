from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, TYPE_CHECKING, Type, TypeVar

# Use TYPE_CHECKING to avoid circular imports
if TYPE_CHECKING:
    from src.services.service_manager import ServiceManager

T = TypeVar('T')

class CommandHandler(ABC):
    """Base class for all command handlers"""
    
    # Class variable to store service manager reference
    _service_manager = None
    
    @classmethod
    def set_service_manager(cls, service_manager: 'ServiceManager') -> None:
        """Set the service manager for all handlers"""
        cls._service_manager = service_manager
    
    @classmethod
    def get_service_manager(cls) -> Optional['ServiceManager']:
        """Get the service manager instance"""
        return cls._service_manager
    
    def get_service(self, service_type: Type[T]) -> Optional[T]:
        """
        Get a service of the specified type from the service manager
        
        Args:
            service_type: The type of service to retrieve
            
        Returns:
            The service instance or None if not available
        """
        service_manager = self.get_service_manager()
        if not service_manager:
            return None
        
        # Use getattr to safely access the service
        service_name = service_type.__name__.lower()
        if not service_name.endswith('_service'):
            service_name = f"{service_name}_service"
            
        return getattr(service_manager, service_name, None)
    
    @abstractmethod
    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle the command with the given data
        
        Args:
            data: Dictionary containing command parameters
            
        Returns:
            Dictionary containing the command result
        """
        pass
    
    @abstractmethod
    def get_command_name(self) -> str:
        """
        Get the name of the command this handler handles
        
        Returns:
            String name of the command
        """
        pass 