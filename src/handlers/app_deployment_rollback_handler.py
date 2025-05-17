import logging
import os
from typing import Dict, Any, Optional, Tuple
from src.handlers.base_handler import CommandHandler
from src.services.build_service import DeploymentStatus

logger = logging.getLogger(__name__)

class AppDeploymentRollbackHandler(CommandHandler):
    """Handles deployment rollback requests"""
    
    def __init__(self):
        """
        Initialize the app deployment rollback handler.
        """
        # Get service_manager from base class
        service_manager = self.get_service_manager()
        if not service_manager:
            logger.error("No service manager available for AppDeploymentRollbackHandler")
            self.service_manager = None
            self.build_service = None
            self.docker_service = None
            self._socket_manager = None
            self.deployment_service = None
            self.environment_service = None
            self.github_clone_service = None
            return
            
        self.service_manager = service_manager
        self.build_service = service_manager.build_service
        self.docker_service = service_manager.docker_service
        self._socket_manager = service_manager.socket_manager
        self.deployment_service = service_manager.deployment_service
        self.environment_service = service_manager.environment_service
        self.github_clone_service = service_manager.github_clone_service
        self.status_service = service_manager.status_service
        
    def get_command_name(self) -> str:
        return "rollback_deployment"
    
    @property
    def socket_manager(self):
        """
        Gets the socket manager, trying to refresh from service_manager if it's None.
        
        Returns:
            The socket manager instance or None if not available
        """
        if self._socket_manager is None:
            # Try to get socket_manager from service_manager
            service_manager = self.get_service_manager()
            if service_manager:
                self._socket_manager = service_manager.socket_manager
        return self._socket_manager
    
    @socket_manager.setter
    def socket_manager(self, socket_manager):
        """
        Sets the socket manager.
        
        Args:
            socket_manager: The socket manager instance
        """
        self._socket_manager = socket_manager
    
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
    
    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle the rollback command.
        
        Args:
            data: Dictionary containing command parameters, including:
                - deployment_uid: UID of the deployment to roll back to
                - commit_sha: SHA of the commit to roll back to
                - service_uid: UID of the service
                
        Returns:
            Dictionary containing the command result
        """
        deployment_uid = data.get('deployment_uid')
        service_uid = data.get('service_uid')
        commit_sha = data.get('commit_sha')
        
        
        if not deployment_uid or not service_uid or not commit_sha:
            error_msg = f"Missing required parameter(s): deployment_uid={deployment_uid}, service_uid={service_uid}, commit_sha={commit_sha}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
        
        try:
            logger.info(f"Starting rollback to deployment {deployment_uid} for service {service_uid} at commit {commit_sha}")
            
            # Update status to indicate rollback in progress
            await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.IN_PROGRESS, 
                                               f"Initiating rollback to deployment {deployment_uid}")
            
            # Get the repository path
            clone_path = os.path.join(self.github_clone_service.base_clone_dir, service_uid)
            if not os.path.exists(clone_path):
                error_msg = f"Repository not found at {clone_path}"
                logger.error(error_msg)
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            
            import git
            
            try:
                # Checkout the specific commit
                repo = git.Repo(clone_path)
                current_branch = repo.active_branch.name
                logger.info(f"Current branch: {current_branch}")
                
                # Fetch latest changes to ensure we have the commit
                logger.info("Fetching latest changes...")
                repo.remotes.origin.fetch()
                
                # Checkout the specific commit
                logger.info(f"Checking out commit {commit_sha}...")
                repo.git.checkout(commit_sha)
                
            except git.GitCommandError as e:
                error_msg = f"Git operation failed: {str(e)}"
                logger.error(error_msg)
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            
            # Find the deployment image
            deployment_image = await self.docker_service.get_image_by_deployment_uid(service_uid, deployment_uid)
            
            if not deployment_image:
                error_msg = f"Deployment image not found for deployment {deployment_uid}"
                logger.error(error_msg)
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            
            # Get environment variables for the service
            env_vars_result = await self.environment_service.get_service_env_vars(service_uid)
            env_vars = env_vars_result.get('env_vars', {}) if env_vars_result.get('success', False) else {}
            
            # Deploy the container using the deployment service
            deployment_result = await self.service_manager.deployment_service.deploy_container(
                service_uid=service_uid,
                image_name=deployment_image,
                deployment_uid=deployment_uid,
                env_vars=env_vars
            )
            
            if not deployment_result.get('success'):
                error_msg = deployment_result.get('error', 'Unknown deployment error')
                logger.error(error_msg)
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            
            # Update status to indicate rollback completed
            await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.COMPLETED, 
                                              f"Rollback to deployment {deployment_uid} completed successfully")
            
            return {
                'success': True,
                'message': f"Successfully rolled back to deployment {deployment_uid}",
                'deployment_uid': deployment_uid,
                'service_uid': service_uid,
                'container_name': deployment_result.get('container_name'),
                'container_id': deployment_result.get('container_id'),
                'deployment_color': deployment_result.get('deployment_color'),
                'commit_sha': commit_sha
            }
            
        except Exception as e:
            error_msg = f"Error rolling back to deployment {deployment_uid}: {str(e)}"
            logger.error(error_msg)
            await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
            return {'success': False, 'error': error_msg}
    
    async def get_service_env_vars(self, service_uid: str) -> Dict[str, Any]:
        """
        Gets environment variables for a service from the server.
        
        Args:
            service_uid: ID of the service to get environment variables for
            
        Returns:
            Dictionary containing the environment variables or error information
        """
        socket_manager = self.socket_manager
        if not socket_manager or not hasattr(socket_manager, 'sio'):
            logger.warning(f"No socket manager available to get environment variables for {service_uid}")
            return {'success': False, 'error': "Socket manager not available"}
            
        try:
            result = await socket_manager.sio.call(
                'get_service_env_vars',
                {'service_uid': service_uid},
                namespace=socket_manager.namespace,
                timeout=30
            )
            
            # Simplified error check: Allow empty dict, only check for explicit error
            if isinstance(result, dict) and 'error' in result:
                error_msg = result.get('error')
                logger.error(f"Error getting env vars for service {service_uid}: {error_msg}")
                # Return error structure consistent with failure
                return {'success': False, 'error': error_msg}
                
            # On success, return the expected structure
            return {'success': True, 'env_vars': result}
            
        except Exception as e:
            error_msg = f"Failed to get env vars: {str(e)}"
            logger.error(f"Error getting env vars for service {service_uid}: {e}")
            return {'success': False, 'error': error_msg}
    
    async def _get_domain_info(self, service_uid: str) -> Dict[str, Any]:
        """
        Get domain information for a service.
        
        Args:
            service_uid: The service UID
            
        Returns:
            Dictionary containing domain information or None if not found
        """
        socket_manager = self.socket_manager
        if not socket_manager or not hasattr(socket_manager, 'sio'):
            logger.warning(f"No socket manager available to get domain info for {service_uid}")
            return None
            
        try:
            result = await socket_manager.sio.call(
                'get_service_domain',
                {'service_uid': service_uid},
                namespace=socket_manager.namespace,
                timeout=30
            )
            
            return result
        except Exception as e:
            logger.error(f"Error getting domain info for service {service_uid}: {e}")
            return None 