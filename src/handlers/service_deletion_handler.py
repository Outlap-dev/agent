from typing import Dict, Any
import logging

from .base_handler import CommandHandler
from src.services.service_manager import ServiceManager

logger = logging.getLogger(__name__)

class ServiceDeletionHandler(CommandHandler):
    """Handles service deletion requests for both apps and databases"""
    
    def __init__(self):
        """Initialize the service deletion handler."""
        # Get service_manager from base class
        service_manager = self.get_service_manager()
        if not service_manager:
            logger.error("No service manager available for ServiceDeletionHandler")
            self.docker_service = None
            return
            
        self.docker_service = service_manager.docker_service

    def get_command_name(self) -> str:
        """Get the command name for this handler."""
        return "delete_service"

    def _get_container_names(self, service_uid: str) -> list[str]:
        """
        Get all possible container names for a service.
        
        Args:
            service_uid: The service UID
            
        Returns:
            List of possible container names
        """
        return [
            f"pulseup-app-{service_uid}",  # Standard app container
            f"pulseup-app-{service_uid}-blue",  # Blue deployment
            f"pulseup-app-{service_uid}-green",  # Green deployment
            f"pulseup-db-{service_uid}"  # Database container
        ]

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle service deletion request
        
        Expected data format:
        {
            "service_uid": "svc_1234567890"
        }
        """
        if not self.docker_service:
            return {'success': False, 'error': 'Docker service not available'}

        # Validate required fields
        if 'service_uid' not in data:
            raise ValueError("Missing required field: service_uid")

        service_uid = data['service_uid']
        containers_deleted = []
        errors = []

        # Get all possible container names for this service
        container_names = self._get_container_names(service_uid)

        # Try to stop and remove each possible container
        for container_name in container_names:
            try:
                # Check if container exists
                exists = await self.docker_service.container_exists(container_name)
                if not exists:
                    continue

                # Stop the container
                stop_success = await self.docker_service.stop_container(container_name)
                if not stop_success:
                    errors.append(f"Failed to stop container {container_name}")
                    continue

                # Remove the container
                remove_success = await self.docker_service.remove_container(container_name)
                if remove_success:
                    containers_deleted.append(container_name)
                else:
                    errors.append(f"Failed to remove container {container_name}")

            except Exception as e:
                errors.append(f"Error processing container {container_name}: {str(e)}")
                logger.error(f"Error deleting container {container_name}: {e}")

        # Clean up any deployment images for this service
        try:
            await self.docker_service.cleanup_old_deployment_images(service_uid)
        except Exception as e:
            errors.append(f"Error cleaning up deployment images: {str(e)}")
            logger.error(f"Error cleaning up deployment images for {service_uid}: {e}")

        # Determine overall success
        success = len(containers_deleted) > 0 and len(errors) == 0

        return {
            "success": success,
            "containers_deleted": containers_deleted,
            "errors": errors,
            "message": (
                f"Successfully deleted {len(containers_deleted)} containers" if success
                else f"Encountered {len(errors)} errors during deletion"
            )
        } 