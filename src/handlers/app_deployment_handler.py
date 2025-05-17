import logging
import os
import json
from typing import Dict, Any, Optional, Tuple
from src.handlers.base_handler import CommandHandler
from src.services.build_service import DeploymentStatus
import socketio

logger = logging.getLogger(__name__)

class AppDeploymentHandler(CommandHandler):
    """Handles app deployment requests using either Dockerfile or Nixpacks"""
    
    def __init__(self):
        """
        Initialize the app deployment handler.
        """
        # Get service_manager from base class
        self.service_manager = self.get_service_manager()
            
        self.build_service = self.service_manager.build_service
        self.docker_service = self.service_manager.docker_service
        self.github_clone_service = self.service_manager.github_clone_service
        self.environment_service = self.service_manager.environment_service
        self.caddy_service = self.service_manager.caddy_service
        self.nixpacks_service = self.service_manager.nixpacks_service
        self.dockerfile_service = self.service_manager.dockerfile_service

    def get_command_name(self) -> str:
        return "deploy_app"
    
    @property
    def socket_manager(self):
        """
        Get the socket manager from the service manager.
        
        Returns:
            The socket manager instance or None if not available
        """
        service_manager = self.get_service_manager()
        if not service_manager:
            return None
        return service_manager.socket_manager
    
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
                return {'success': False, 'error': error_msg}
                
            # On success, return the expected structure
            return {'success': True, 'env_vars': result}
            
        except socketio.exceptions.TimeoutError:
            error_msg = f"Timeout getting env vars for service {service_uid}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = f"Failed to get env vars: {str(e)}"
            logger.error(f"Error getting env vars for service {service_uid}: {e}")
            return {'success': False, 'error': error_msg}
        
    async def get_github_repo_info(self, service_uid: str) -> Dict[str, Any]:
        """
        Gets GitHub repository information for a service from the server.
        
        Args:
            service_uid: ID of the service to get GitHub repo info for
            
        Returns:
            Dictionary containing the GitHub repo info or error information
        """
        socket_manager = self.socket_manager
        if not socket_manager or not hasattr(socket_manager, 'sio'):
            logger.warning(f"No socket manager available to get GitHub repo info for {service_uid}")
            return {'error': "Socket manager not available"}
            
        try:
            result = await socket_manager.sio.call(
                'get_github_repo',
                {'service_uid': service_uid},
                namespace=socket_manager.namespace,
                timeout=30
            )
            
            # Return the result directly - error checking happens in the caller
            return result
            
        except socketio.exceptions.TimeoutError:
            error_msg = f"Timeout getting GitHub repo info for {service_uid}"
            logger.error(error_msg)
            return {'error': error_msg}
        except Exception as e:
            error_msg = f"Failed to get GitHub repo info: {str(e)}"
            logger.error(f"Error getting GitHub repo info for {service_uid}: {e}")
            return {'error': error_msg}
        
    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle the app deployment request
        
        Args:
            data: Dictionary containing deployment parameters:
                - service_uid: ID of the service to deploy
                - github_repo: GitHub repository URL
                - github_branch: Branch to deploy
                - last_commit_sha: Last commit SHA
                - nixpacks_config: Nixpacks configuration
                - install_command: Install command
                - build_command: Build command
                - start_command: Start command
                - internal_port: Internal port
                - env_vars: Environment variables
                - cpu_limit: CPU limit
                - memory_limit: Memory limit
                - deployment_strategy: Deployment strategy
                
        Returns:
            Dictionary containing the deployment result
        """
        if not self.build_service:
            return {'success': False, 'error': 'Service manager not available'}
        
        deployment_uid = data.get('deployment_uid')
        if not deployment_uid:
            raise ValueError("Missing required parameter: deployment_uid")
            
        try:
            service = data.get('service', {})
            service_uid = data.get('service_uid')
            if not service_uid:
                raise ValueError("Missing required parameter: service_uid")
                
            # Update status to indicate deployment started
            await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.IN_PROGRESS)
            
            # Check if repo is already cloned
            clone_path = os.path.join(self.github_clone_service.base_clone_dir, service_uid)
            is_initial_clone = not os.path.exists(clone_path)
            
            if is_initial_clone:
                # If not cloned, get repo info and clone
                try:
                    repo_info = await self.get_github_repo_info(service_uid)
                    
                    if not repo_info or not isinstance(repo_info, dict) or 'error' in repo_info:
                        error_msg = repo_info.get('error') if isinstance(repo_info, dict) else "Invalid response"
                        logger.error(f"Error getting GitHub repo info for {service_uid}: {error_msg}")

                        await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, f"Failed to get repo info: {error_msg}")
                        return {'success': False, 'error': error_msg}

                    repo_url = repo_info.get('repo_url')
                    access_token = repo_info.get('access_token')
                    if not repo_url or not access_token:
                        error_msg = f"Missing repo_url or access_token in response for {service_uid}"
                        logger.error(f"{error_msg}: {repo_info}")

                        await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                        return {'success': False, 'error': error_msg}
                        
                    # Clone Repo
                    clone_result = await self.github_clone_service.clone_repo(repo_url, access_token, service_uid)
                    
                    if not clone_result or not clone_result.get("success"):
                        error_msg = clone_result.get('error', 'Unknown clone error')
                        logger.error(f"Clone failed for {service_uid}: {error_msg}")

                        await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                        return {'success': False, 'error': error_msg}
                    
                    retrieved_clone_path = clone_result.get('clone_path')
                    if retrieved_clone_path:
                        clone_path = retrieved_clone_path
                        
                except Exception as e:
                    error_msg = f"Error cloning repo for {service_uid}: {str(e)}"
                    logger.error(error_msg)

                    await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                    return {'success': False, 'error': error_msg}
                
            # If repo already cloned, pull the latest changes
            if os.path.exists(clone_path):
                await self.github_clone_service.pull_repo(service_uid)
                
            # Get the build info for this service
            build_info = self.build_service.get_build_command_info(service_uid)
            if not build_info:
                # Try preparing the build if build info doesn't exist
                await self.build_service.prepare_build(clone_path, service_uid, is_initial_clone=is_initial_clone)
                build_info = self.build_service.get_build_command_info(service_uid)
                if not build_info:
                    raise ValueError(f"No build info found for service {service_uid}")
                
            # Get environment variables from the server
            env_vars_result = await self.environment_service.get_service_env_vars(service_uid)
            env_vars = env_vars_result.get('env_vars', {}) if env_vars_result.get('success', False) else {}

            # Merge/override with any environment variables provided directly in the request
            request_env_vars = data.get('env_vars')
            if request_env_vars and isinstance(request_env_vars, dict):
                env_vars.update(request_env_vars) # Request vars override server vars
                
            # Use Caddy network for deployment to avoid having to connect it later
            networks = ["bridge"]
            if self.caddy_service:
                networks.append(self.caddy_service.CADDY_NETWORK)
                logger.info(f"Adding container to Caddy network during deployment")
                
            # Deploy based on build type
            if build_info['type'] == 'docker':
                # Build and deploy using Dockerfile
                deployment_result = await self.dockerfile_service.deploy(
                    deployment_uid=deployment_uid,
                    source_path=build_info['cwd'],
                    service_uid=service_uid,
                    config={
                        'cpu_limit': data.get('cpu_limit'),
                        'memory_limit': data.get('memory_limit'),
                        'internal_port': data.get('internal_port')
                    },
                    env_vars=env_vars,
                    networks=networks
                )
            elif build_info['type'] == 'nixpacks':
                # Build and deploy using Nixpacks
                # Prepare Nixpacks plan data
                plan_data = {}
                if build_info.get('plan'):
                    plan_data = json.loads(build_info['plan'])
                
                # Override plan with provided config if available
                if data.get('nixpacks_config'):
                    plan_data.update(data['nixpacks_config'])
                    
                # Override commands if provided
                if service.get('install_command'):
                    plan_data.setdefault('phases', {})['setup'] = {'cmd': service['install_command']}
                if service.get('build_command'):
                    plan_data.setdefault('phases', {})['build'] = {'cmd': service['build_command']}
                if service.get('start_command'):
                    plan_data.setdefault('phases', {})['start'] = {'cmd': service['start_command']}
                    
                # Add environment variables to plan
                if env_vars:
                    plan_data['env'] = env_vars
                    
                # Add resource limits
                if data.get('cpu_limit') or data.get('memory_limit'):
                    plan_data['resources'] = {}
                    if data.get('cpu_limit'):
                        plan_data['resources']['cpu'] = data['cpu_limit']
                    if data.get('memory_limit'):
                        plan_data['resources']['memory'] = data['memory_limit']
                        
                # Add port configuration
                if data.get('internal_port'):
                    plan_data['ports'] = [data['internal_port']]
                    
                deployment_result = await self.nixpacks_service.deploy(
                    deployment_uid=deployment_uid,
                    source_path=build_info['cwd'],
                    service_uid=service_uid,
                    plan_data=plan_data,
                    networks=networks
                )
            else:
                error_msg = f"Unsupported build type: {build_info['type']}"
                logger.error(error_msg)
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            
            if not deployment_result or not deployment_result.get('success'):
                error_msg = deployment_result.get('error', 'Unknown deployment error') if deployment_result else 'Deployment failed'
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            
            # Tag the image with deployment UID
            await self.docker_service.tag_image_with_deployment(service_uid, deployment_uid)
            # Clean up old deployment images
            await self.docker_service.cleanup_old_deployment_images(service_uid)
            
            # Deploy the container using the deployment service
            deployment_result = await self.service_manager.deployment_service.deploy_container(
                service_uid=service_uid,
                image_name=deployment_result['image_name'],
                deployment_uid=deployment_uid,
                env_vars=env_vars
            )
            
            if not deployment_result.get('success'):
                error_msg = deployment_result.get('error', 'Unknown deployment error')
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            
            # Update status to indicate successful deployment
            await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.COMPLETED)
            
            return {
                'success': True,
                'image': deployment_result.get('image_name'),
                'container': deployment_result.get('container_id'),
                'container_name': deployment_result.get('container_name'),
                'deployment_color': deployment_result.get('deployment_color')
            }
            
        except Exception as e:
            logger.error(f"Error deploying app: {str(e)}")
            logger.exception(e)
            if service_uid:
                await self.service_manager.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, str(e))
            return {'success': False, 'error': str(e)} 