import logging
import os
from typing import Dict, Any, Optional, Tuple
import datetime
import aiofiles

from src.services.deployment_status import DeploymentStatus

logger = logging.getLogger(__name__)

class DeploymentService:
    """Service for handling deployment operations"""
    
    def __init__(self, docker_service, caddy_service, status_service):
        """
        Initialize the deployment service.
        
        Args:
            docker_service: Docker service instance
            caddy_service: Caddy service instance
        """
        self.docker_service = docker_service
        self.caddy_service = caddy_service
        self.status_service = status_service
        self.logs_dir = "/var/log/pulseup/deployments"
        # Ensure logs directory exists
        os.makedirs(self.logs_dir, exist_ok=True)
        
    async def _log_deployment_step(self, deployment_uid: str, message: str, error: bool = False) -> None:
        """
        Log a deployment step to the deployment-specific log file.
        
        Args:
            deployment_uid: The deployment UID
            message: The message to log
            error: Whether this is an error message
        """
        timestamp = datetime.datetime.now().isoformat()
        log_file = os.path.join(self.logs_dir, f"{deployment_uid}.log")
        level = "ERROR" if error else "INFO"
        
        async with aiofiles.open(log_file, mode='a') as f:
            await f.write(f"{timestamp} - {level} - {message}\n")
            
        # Also log to system logger
        if error:
            logger.error(f"[{deployment_uid}] {message}")
        else:
            logger.info(f"[{deployment_uid}] {message}")

    def _generate_container_name(self, service_uid: str, suffix: Optional[str] = None) -> str:
        """
        Generate a container name for deployment with optional suffix for blue-green deployments.
        
        Args:
            service_uid: The service UID
            suffix: Optional suffix to add (e.g., 'blue', 'green')
            
        Returns:
            Container name string
        """
        base_name = f"pulseup-app-{service_uid}"
        if suffix:
            return f"{base_name}-{suffix}"
        return base_name
    
    async def _get_deployment_color(self, service_uid: str) -> Tuple[str, str]:
        """
        Determine which color (blue/green) to use for deployment based on what's currently running.
        
        Args:
            service_uid: The service UID
            
        Returns:
            Tuple of (new_color, old_color) to use for deployment
        """
        base_name = f"pulseup-app-{service_uid}"
        current_blue = f"{base_name}-blue"
        current_green = f"{base_name}-green"
        
        # Check if blue container exists
        blue_exists = await self.docker_service.container_exists(current_blue)
        # Check if green container exists
        green_exists = await self.docker_service.container_exists(current_green)
        
        if blue_exists:
            # Blue exists, so deploy to green
            return "green", "blue"
        else:
            # Blue doesn't exist, deploy to green (we'll rename to blue after)
            return "green", None
    
    async def _cleanup_container(self, container_name: str) -> bool:
        """
        Stop and remove a container.
        
        Args:
            container_name: The container name to stop and remove
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.docker_service:
                logger.error("Docker service not available to clean up container")
                return False
                
            # Stop the container first
            stop_success = await self.docker_service.stop_container(container_name)
            if not stop_success:
                logger.warning(f"Failed to stop container {container_name}, attempting to remove anyway")
                
            # Then remove it
            remove_success = await self.docker_service.remove_container(container_name)
            
            return remove_success
        except Exception as e:
            logger.error(f"Error cleaning up container {container_name}: {e}")
            return False
    
    async def deploy_container(self, service_uid: str, image_name: str, deployment_uid: str, env_vars: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Deploy a container using blue-green deployment strategy.
        
        Args:
            service_uid: The service UID
            image_name: Name of the Docker image to deploy
            deployment_uid: Unique identifier for this deployment
            env_vars: Optional environment variables for the container
            
        Returns:
            Dictionary containing deployment result
        """
        try:
            await self._log_deployment_step(deployment_uid, f"Starting deployment of {image_name} for service {service_uid}")
            
            # Determine which color to use for deployment
            new_color, old_color = await self._get_deployment_color(service_uid)
            await self._log_deployment_step(deployment_uid, f"Using blue-green deployment strategy: Deploying to {new_color}, existing deployment on {old_color if old_color else 'none'}")
            
            # Generate container name with color suffix
            container_name = self._generate_container_name(service_uid, new_color)
            await self._log_deployment_step(deployment_uid, f"Generated container name: {container_name}")
            
            # Stop and remove any existing container with the new name
            if await self.docker_service.container_exists(container_name):
                await self._log_deployment_step(deployment_uid, f"Stopping and removing existing container {container_name}")
                await self._cleanup_container(container_name)
            
            # Run the container
            import docker
            client = docker.from_env()
            
            try:
                # Run the container with standard configuration
                await self._log_deployment_step(deployment_uid, f"Starting container with image {image_name}")
                container = client.containers.run(
                    image_name,
                    name=container_name,
                    detach=True,
                    network="caddy-net",  # Always use Caddy network
                    environment=env_vars or {},
                )
                
                await self._log_deployment_step(deployment_uid, f"Successfully started container: {container_name}")
                
                rename_success = True # Assume true if no rename is needed
                final_new_color = new_color # Color after this block, assuming no rename first

                # Handle renaming and cleanup for blue-green
                if new_color == "green": # This covers initial "green then to blue" and "blue to green to blue"
                    target_blue_name = self._generate_container_name(service_uid, "blue")
                    current_green_name = container_name # This is the newly started green one

                    # If old_color was "blue", it means we are replacing an existing blue container.
                    # Clean it up BEFORE renaming green to blue.
                    if old_color == "blue":
                        # Ensure we are targeting the actual old blue container name
                        if await self.docker_service.container_exists(target_blue_name):
                            await self._log_deployment_step(deployment_uid, f"Blue-green switch: Cleaning up old blue container {target_blue_name}")
                            await self._cleanup_container(target_blue_name)
                        else:
                            await self._log_deployment_step(deployment_uid, f"Blue-green switch: Expected old blue container {target_blue_name} not found for cleanup.")
                    elif await self.docker_service.container_exists(target_blue_name):
                         await self._log_deployment_step(deployment_uid, f"Found existing blue container {target_blue_name} during green deployment. Cleaning it up before rename.")
                         await self._cleanup_container(target_blue_name)

                    await self._log_deployment_step(deployment_uid, f"Renaming new container from {current_green_name} to {target_blue_name}")
                    rename_success = await self.docker_service.rename_container(current_green_name, target_blue_name)

                    if rename_success:
                        container_name = target_blue_name # Update container_name to the new blue name
                        final_new_color = "blue"
                        await self._log_deployment_step(deployment_uid, f"Successfully renamed container to {target_blue_name}")
                    else:
                        # Rename failed. Clean up the green container we just started.
                        error_msg = f"Failed to rename container {current_green_name} to {target_blue_name}"
                        await self._log_deployment_step(deployment_uid, error_msg, error=True)
                        await self._cleanup_container(current_green_name)
                        return {
                            'success': False,
                            'error': error_msg
                        }
                elif old_color:
                    old_container_to_cleanup = self._generate_container_name(service_uid, old_color)
                    if old_container_to_cleanup != container_name:
                         await self._log_deployment_step(deployment_uid, f"Cleaning up old container: {old_container_to_cleanup}")
                         await self._cleanup_container(old_container_to_cleanup)

                # Set deployment status to completed
                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.COMPLETED, f"Container ID: {container.id}")

                # # Start capturing container logs
                # logs = container.logs(stream=True, follow=True)
                # log_file = os.path.join(self.logs_dir, f"{deployment_uid}_container.log")
                
                # # Write initial container logs
                # try:
                #     async with aiofiles.open(log_file, mode='a') as f:
                #         await f.write(f"=== Container Logs for {container_name} ===\n")
                #         for line in logs:
                #             await f.write(line.decode('utf-8'))
                # except Exception as log_e:
                #     await self._log_deployment_step(deployment_uid, f"Warning: Failed to capture container logs: {str(log_e)}", error=True)

                # await self._log_deployment_step(deployment_uid, "Deployment completed successfully")
                return {
                    'success': True,
                    'container_id': container.id,
                    'container_name': container_name,
                    'deployment_color': final_new_color,
                    # 'deployment_logs': log_file
                }
                
            except Exception as e:
                error_msg = f"Error running container from image {image_name}: {str(e)}"
                await self._log_deployment_step(deployment_uid, error_msg, error=True)
                # Clean up the container if it was created
                if await self.docker_service.container_exists(container_name):
                    await self._cleanup_container(container_name)
                return {'success': False, 'error': error_msg}
            
        except Exception as e:
            error_msg = f"Error during deployment: {str(e)}"
            await self._log_deployment_step(deployment_uid, error_msg, error=True)
            return {'success': False, 'error': error_msg} 