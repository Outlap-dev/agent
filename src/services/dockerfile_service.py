import logging
import os
from typing import Dict, Any, Optional

from src.services.docker_service import DockerService
from src.services.service_status import ServiceStatus
from src.services.deployment_status import DeploymentStatus

logger = logging.getLogger(__name__)

class DockerfileService:
    """Service for handling Dockerfile-based deployments"""
    
    def __init__(self):
        self.socket_manager = None
        self.docker_service = None
        self.deployment_service = None
        self.status_service = None

    def set_socket_manager(self, socket_manager):
        """Sets the SocketManager instance for sending status updates."""
        self.socket_manager = socket_manager
        self.docker_service = DockerService()

    def set_deployment_service(self, deployment_service):
        """Sets the DeploymentService instance for container deployment."""
        self.deployment_service = deployment_service

    def set_status_service(self, status_service):
        """Sets the StatusService instance for sending deployment status updates."""
        self.status_service = status_service

    async def _update_status(self, service_uid: str, status: str, message: str = None):
        """Helper to update status via SocketManager."""
        if status not in ServiceStatus.get_choices():
            raise ValueError(f"Invalid service status: {status}")
        
        if self.socket_manager:
            await self.socket_manager._update_service_status(service_uid, status, message)
        else:
            logger.warning(f"SocketManager not set in DockerfileService. Cannot send status update for {service_uid}: {status}")

    async def get_dockerfile_config(self, source_path: str) -> Dict[str, Any] | None:
        """
        Gets the Dockerfile configuration for a source path.
        This could involve parsing the Dockerfile to understand its configuration.
        
        Args:
            source_path: Path to the source code directory containing Dockerfile
            
        Returns:
            Dictionary containing Dockerfile configuration or None if not found
        """
        dockerfile_path = os.path.join(source_path, 'Dockerfile')
        if not os.path.exists(dockerfile_path):
            logger.error(f"No Dockerfile found at {dockerfile_path}")
            return None
            
        try:
            # For now, we'll just return basic info
            # TODO: Add Dockerfile parsing to extract more configuration
            return {
                'type': 'dockerfile',
                'path': dockerfile_path,
                'context_path': source_path
            }
        except Exception as e:
            logger.error(f"Error getting Dockerfile config: {e}")
            return None

    async def deploy(self, 
                    deployment_uid: str,
                    source_path: str, 
                    service_uid: str, 
                    config: Dict[str, Any],
                    env_vars: Optional[Dict[str, str]] = None,
                    networks: Optional[list] = None) -> Dict[str, Any]:
        """
        Deploys an application using a Dockerfile.
        
        Args:
            deployment_uid: Unique identifier for this deployment
            source_path: Path to the source code
            service_uid: Unique identifier for the service
            config: Configuration for the deployment (resource limits, etc)
            env_vars: Environment variables to pass to the container
            networks: Optional list of Docker networks to connect to
            
        Returns:
            Dictionary containing deployment result
        """
        try:
            # Update deployment status to indicate deployment started
            await self.status_service.update_deployment_status(
                deployment_uid, 
                DeploymentStatus.IN_PROGRESS,
                "Starting Dockerfile deployment"
            )

            # Build the image
            await self.status_service.update_deployment_status(
                deployment_uid,
                DeploymentStatus.IN_PROGRESS,
                "Building container image"
            )

            build_result = await self.docker_service.build_image(
                context_path=source_path,
                service_uid=service_uid,
                deployment_uid=deployment_uid
            )
            
            if not build_result.get('success'):
                error_msg = build_result.get('error', 'Unknown build error')
                logger.error(f"Build failed: {error_msg}")
                await self.status_service.update_deployment_status(
                    deployment_uid,
                    DeploymentStatus.FAILED,
                    error_msg
                )
                return {'success': False, 'error': error_msg}

            image_name = build_result['image_name']

            # Use the deployment service to handle container deployment
            try:
                if not self.deployment_service:
                    raise ValueError("Deployment service not initialized")
                    
                deployment_result = await self.deployment_service.deploy_container(
                    service_uid=service_uid,
                    image_name=image_name,
                    deployment_uid=deployment_uid,
                    env_vars=env_vars
                )
                
                if not deployment_result.get('success'):
                    error_msg = deployment_result.get('error', 'Unknown deployment error')
                    logger.error(f"Deployment failed: {error_msg}")
                    await self.status_service.update_deployment_status(
                        deployment_uid,
                        DeploymentStatus.FAILED,
                        error_msg
                    )
                    return {'success': False, 'error': error_msg}
                
                # Update status to indicate successful deployment
                await self.status_service.update_deployment_status(
                    deployment_uid,
                    DeploymentStatus.COMPLETED,
                    f"Container ID: {deployment_result.get('container_id')}"
                )
                
                return {
                    'success': True,
                    'image_name': image_name,
                    'container_id': deployment_result.get('container_id'),
                    'container_name': deployment_result.get('container_name'),
                    'deployment_color': deployment_result.get('deployment_color')
                }
                
            except Exception as e:
                error_msg = f"Unexpected error during deployment: {str(e)}"
                logger.error(error_msg)
                await self.status_service.update_deployment_status(
                    deployment_uid,
                    DeploymentStatus.FAILED,
                    error_msg
                )
                return {'success': False, 'error': error_msg}

        except Exception as e:
            error_msg = f"Error during Dockerfile deployment: {str(e)}"
            logger.error(error_msg)
            await self.status_service.update_deployment_status(
                deployment_uid,
                DeploymentStatus.FAILED,
                error_msg
            )
            return {'success': False, 'error': error_msg} 