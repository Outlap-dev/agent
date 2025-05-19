import logging
import os
import asyncio
from typing import Optional
import datetime

logger = logging.getLogger(__name__)

# Convention for container names based on service_uid
CONTAINER_NAME_PREFIX = "pulseup-app-"

class DockerService:
    def __init__(self):
        import docker # Import docker here
        from docker.errors import APIError # Import specific errors here too
        try:
            self.client = docker.from_env()
            # Check connection
            self.client.ping()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}", exc_info=True)
            # Depending on requirements, either raise the error or set client to None
            self.client = None

    def _get_container_name(self, service_uid: str) -> str:
        """Generates the expected container name for a given service UID."""
        return f"{CONTAINER_NAME_PREFIX}{service_uid}-blue"

    async def get_container_by_service_uid(self, service_uid: str) -> 'docker.models.containers.Container | None':
        """Gets the Docker container object corresponding to a service UID."""
        from docker.errors import NotFound, APIError # Import here for exception handling
        if not self.client:
            logger.error("Docker client not available.")
            return None
            
        container_name = self._get_container_name(service_uid)
        try:
            # Run blocking Docker SDK calls in a separate thread
            container = await asyncio.to_thread(self.client.containers.get, container_name)
            return container
        except NotFound:
            logger.warning(f"Container '{container_name}' not found for service {service_uid}.")
            return None
        except APIError as e:
            logger.error(f"Docker API error getting container '{container_name}': {e}")
            return None
        except Exception as e:
             logger.error(f"Unexpected error getting container '{container_name}': {e}", exc_info=True)
             return None

    async def build_image(self, context_path: str, service_uid: str, deployment_uid: str = None):
        """Builds a container image using a Dockerfile and logs output if deployment_uid is provided."""
        if not self.client:
             logger.error("Docker client not available for build.")
             return {"success": False, "error": "Docker client not available"}

        logger.info(f"Initiating Docker build for service {service_uid} using context {context_path}")
        
        dockerfile_path = os.path.join(context_path, 'Dockerfile')
        if not os.path.exists(dockerfile_path):
             logger.error(f"Dockerfile not found at expected path: {dockerfile_path}")
             return {"success": False, "error": "Dockerfile not found"}
        
        image_name = f"pulseup-app:{service_uid}"
        logs_dir = "/var/log/pulseup/deployments"
        if deployment_uid:
            os.makedirs(logs_dir, exist_ok=True)
            log_file_path = os.path.join(logs_dir, f"{deployment_uid}_build.log")
        else:
            log_file_path = None
        
        try:
            def build_with_logs():
                # This runs in a thread, so no async file IO
                image, build_log = self.client.images.build(
                    path=context_path,
                    tag=image_name,
                    rm=True,
                    forcerm=True
                )
                return image, list(build_log)
            
            image, build_log = await asyncio.to_thread(build_with_logs)
            
            # Write logs to file if needed
            if log_file_path:
                try:
                    with open(log_file_path, 'a') as f:
                        f.write(f"{datetime.datetime.now().isoformat()} - INFO - Log file initialized for Docker build.\n")
                        for entry in build_log:
                            line = entry.get('stream') or entry.get('status') or str(entry)
                            if line:
                                timestamp = datetime.datetime.now().isoformat()
                                f.write(f"{timestamp} - INFO - {line.strip()}\n")
                except Exception as e:
                    logger.error(f"Failed to write Docker build log to {log_file_path}: {e}")
            
            logger.info(f"Docker build completed successfully for {image_name}")
            
            return {
                "success": True, 
                "image_name": image_name,
                "image_id": image.id,
                "message": "Build via Dockerfile completed successfully"
            }
            
        except Exception as e:
            error_msg = f"Unexpected error during Docker build for {image_name}: {e}"
            logger.error(error_msg)
            # Log error to file if needed
            if log_file_path:
                try:
                    with open(log_file_path, 'a') as f:
                        timestamp = datetime.datetime.now().isoformat()
                        f.write(f"{timestamp} - ERROR - {error_msg}\n")
                except Exception as e2:
                    logger.error(f"Failed to write error to Docker build log {log_file_path}: {e2}")
            return {"success": False, "error": error_msg}

    async def container_exists(self, container_name: str) -> bool:
        """
        Check if a container with the given name exists.
        
        Args:
            container_name: The container name to check
            
        Returns:
            True if the container exists, False otherwise
        """
        from docker.errors import NotFound, APIError # Added this line

        if not self.client:
            logger.error("Docker client not available")
            return False

        try:
            # Run blocking Docker SDK calls in a separate thread
            await asyncio.to_thread(self.client.containers.get, container_name)
            return True
        except NotFound: # Changed from docker.errors.NotFound
            return False
        except APIError as e: # Changed from docker.errors.APIError
            logger.error(f"Docker API error checking container existence for {container_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error checking container existence for {container_name}: {e}")
            return False
    
    async def stop_container(self, container_name: str) -> bool:
        """
        Stop a container.
        
        Args:
            container_name: The container name to stop
            
        Returns:
            True if successful, False otherwise
        """

        import docker

        client = docker.from_env()
        try:
            container = client.containers.get(container_name)
            container.stop()
            return True
        except docker.errors.NotFound:
            return False
    
    async def remove_container(self, container_name: str) -> bool:
        """
        Remove a container.
        
        Args:
            container_name: The container name to remove
            
        Returns:
            True if successful, False otherwise
        """
        import docker

        client = docker.from_env()
        try:
            container = client.containers.get(container_name)
            container.remove()
            return True
        except docker.errors.NotFound:
            return False
            
    async def rename_container(self, old_name: str, new_name: str) -> bool:
        """
        Rename a container.
        
        Args:
            old_name: The current container name
            new_name: The new container name
            
        Returns:
            True if successful, False otherwise
        """
        import docker

        client = docker.from_env()
        try:
            container = client.containers.get(old_name)
            container.rename(new_name)
            logger.info(f"Successfully renamed container from {old_name} to {new_name}")
            return True
        except docker.errors.NotFound:
            logger.error(f"Container {old_name} not found for renaming")
            return False
        except docker.errors.APIError as e:
            logger.error(f"Docker API error renaming container {old_name} to {new_name}: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error renaming container {old_name} to {new_name}: {e}")
            return False
    
    async def tag_image_with_deployment(self, service_uid: str, deployment_uid: str) -> bool:
        """
        Tag an existing image with deployment information.
        
        Args:
            service_uid: The service UID
            deployment_uid: The deployment UID to tag with
            
        Returns:
            True if successful, False otherwise
        """
        import docker
        from docker.errors import ImageNotFound, APIError
        
        if not self.client:
            logger.error("Docker client not available for tagging image.")
            return False
        
        try:
            # Source image name (the one created during deployment)
            source_image = f"pulseup-app:{service_uid}"
            
            # Tag with deployment UID
            deployment_tag = f"pulseup-app:{service_uid}-deploy-{deployment_uid}"
            
            # Get the image
            image = await asyncio.to_thread(self.client.images.get, source_image)
            
            # Tag with deployment UID
            await asyncio.to_thread(image.tag, deployment_tag)
            logger.info(f"Tagged image {source_image} with deployment tag {deployment_tag}")
            
            return True
        except ImageNotFound:
            logger.error(f"Image not found: {source_image}")
            return False
        except APIError as e:
            logger.error(f"Docker API error tagging image: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error tagging image: {e}")
            return False
    
    async def get_image_by_deployment_uid(self, service_uid: str, deployment_uid: str) -> Optional[str]:
        """
        Get image name by deployment UID.
        
        Args:
            service_uid: The service UID
            deployment_uid: The deployment UID to find
            
        Returns:
            Image name if found, None otherwise
        """
        import docker
        from docker.errors import APIError
        
        if not self.client:
            logger.error("Docker client not available for finding image.")
            return None
        
        try:
            # Construct the deployment tag to search for
            deployment_tag = f"pulseup-app:{service_uid}-deploy-{deployment_uid}"
            
            # List all images and filter by tag
            images = await asyncio.to_thread(self.client.images.list)
            
            # Find the image with the matching tag
            for image in images:
                if deployment_tag in image.tags:
                    logger.info(f"Found image for deployment {deployment_uid}: {deployment_tag}")
                    return deployment_tag
            
            logger.warning(f"No image found for deployment {deployment_uid}")
            return None
        except APIError as e:
            logger.error(f"Docker API error finding image for deployment {deployment_uid}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error finding image for deployment {deployment_uid}: {e}")
            return None
    
    async def cleanup_old_deployment_images(self, service_uid: str, keep_count: int = 5) -> bool:
        """
        Clean up old deployment images, keeping only the most recent ones.
        
        Args:
            service_uid: The service UID
            keep_count: Number of recent deployment images to keep
            
        Returns:
            True if the cleanup was successful, False otherwise
        """
        import docker
        from docker.errors import APIError
        import re
        
        if not self.client:
            logger.error("Docker client not available for cleanup.")
            return False
        
        try:
            # Pattern to match deployment tags
            pattern = f"pulseup-app:{service_uid}-deploy-"
            
            # List all images
            images = await asyncio.to_thread(self.client.images.list)
            
            # Find all deployment images for this service
            deployment_images = []
            
            for image in images:
                for tag in image.tags:
                    if pattern in tag:
                        # Extract the deployment UID
                        match = re.search(f"{pattern}([^:]+)$", tag)
                        if match:
                            deployment_uid = match.group(1)
                            # Add to list with created time for sorting
                            deployment_images.append({
                                'tag': tag,
                                'created': image.attrs.get('Created', ''),
                                'deployment_uid': deployment_uid,
                                'id': image.id
                            })
            
            # Sort by creation time (newest first)
            deployment_images.sort(key=lambda x: x['created'], reverse=True)
            
            # Keep the most recent ones and remove the rest
            if len(deployment_images) > keep_count:
                images_to_remove = deployment_images[keep_count:]
                logger.info(f"Cleaning up {len(images_to_remove)} old deployment images for service {service_uid}")
                
                for image_info in images_to_remove:
                    try:
                        await asyncio.to_thread(self.client.images.remove, image_info['tag'])
                        logger.info(f"Removed old deployment image: {image_info['tag']}")
                    except Exception as e:
                        logger.warning(f"Failed to remove image {image_info['tag']}: {e}")
            
            return True
        except APIError as e:
            logger.error(f"Docker API error during cleanup of deployment images: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during cleanup of deployment images: {e}")
            return False