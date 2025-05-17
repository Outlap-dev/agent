import logging
from typing import Dict, Any, Optional
from src.handlers.base_handler import CommandHandler
from src.services.service_status import ServiceStatus

logger = logging.getLogger(__name__)

class GetServiceStatusHandler(CommandHandler):
    """Handles requests to get the status of a service container"""
    
    def __init__(self):
        """Initialize the handler"""
        service_manager = self.get_service_manager()
        self.docker_service = service_manager.docker_service
        self.database_service = service_manager.database_service
    
    def get_command_name(self) -> str:
        return "get_service_status"
    
    async def _get_container_status(self, container_name: str) -> Optional[Dict[str, Any]]:
        """
        Get status information for a container
        
        Args:
            container_name: Name of the container to check
            
        Returns:
            Dict containing status information or None if container not found
        """
        try:
            if not self.docker_service:
                logger.error("Docker service not available")
                return None
                
            # Check if container exists
            exists = await self.docker_service.container_exists(container_name)
            if not exists:
                return None
                
            # Get container object
            container = self.docker_service.client.containers.get(container_name)
            
            # Convert Docker status to service status
            service_status = ServiceStatus.from_docker_status(container.status)
            
            return {
                "id": container.id,
                "status": service_status,  # Use converted status
                "name": container.name,
                "created": container.attrs['Created'],
                "state": container.attrs['State']
            }
        except Exception as e:
            logger.error(f"Error getting container status for {container_name}: {e}")
            return None
    
    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle the get service status request
        
        Args:
            data: Dictionary containing:
                - service_uid: The service UID to check
                
        Returns:
            Dictionary containing:
                - success: Whether the operation was successful
                - app_status: Status of the app container (if exists)
                - db_status: Status of the db container (if exists)
                - error: Error message if operation failed
        """
        service_uid = data.get('service_uid')
        if not service_uid:
            return {'success': False, 'error': 'service_uid is required'}
            
        try:
            # Check app container
            app_container_name = f"pulseup-app-{service_uid}-blue"
            app_status = await self._get_container_status(app_container_name)
            
            if not app_status:
                # Try green container if blue doesn't exist
                app_container_name = f"pulseup-app-{service_uid}-green"
                app_status = await self._get_container_status(app_container_name)
            
            # Check db container
            db_container_name = f"pulseup-db-{service_uid}"
            db_status = await self._get_container_status(db_container_name)
            
            return {
                'success': True,
                'app_status': app_status,
                'db_status': db_status
            }
            
        except Exception as e:
            logger.error(f"Error getting service status: {e}")
            return {'success': False, 'error': str(e)} 