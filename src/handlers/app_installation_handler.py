import logging
import os
from typing import Dict, Any
from src.handlers.base_handler import CommandHandler
import socketio
from src.services.service_status import ServiceStatus

logger = logging.getLogger(__name__)

class AppInstallationHandler(CommandHandler):
    """Handles app installation requests - clones and prepares build setup without building"""
    
    def __init__(self):
        """
        Initialize the app installation handler.
        """
        # Get service_manager from base class
        service_manager = self.get_service_manager()
        if not service_manager:
            logger.error("No service manager available for AppInstallationHandler")
            self.service_manager = None
            self.build_service = None
            self._socket_manager = None
            self.github_clone_service = None
            return
            
        self.service_manager = service_manager
        self.build_service = service_manager.build_service
        self._socket_manager = service_manager.socket_manager
        self.github_clone_service = service_manager.github_clone_service
        
    def get_command_name(self) -> str:
        return "install_app"
    
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
        """
        Handle the app installation request - clones and prepares build without building
        
        Args:
            data: Dictionary containing:
                - service_uid: ID of the service to install
                - service: Service data
                
        Returns:
            Dictionary containing the installation result
        """
        if not self.service_manager:
            return {'success': False, 'error': 'Service manager not available'}
            
        try:
            logger.info(f"Installing app with data: {data}")
            service_uid = data.get('service_uid')
            
            if not service_uid:
                raise ValueError("Missing required parameter: service_uid")                
            
            # Check if repo is already cloned
            clone_path = os.path.join(self.github_clone_service.base_clone_dir, service_uid)
            if os.path.exists(clone_path):
                logger.info(f"Repository for service {service_uid} already exists at {clone_path}")
                # Refresh the build setup - not an initial clone
                await self.build_service.prepare_build(clone_path, service_uid, is_initial_clone=False)
                return {'success': True, 'clone_path': clone_path}
            
            # Repository doesn't exist, get repo info and clone
            try:
                repo_info = await self.get_github_repo_info(service_uid)
                
                if not repo_info or not isinstance(repo_info, dict) or 'error' in repo_info:
                    error_msg = repo_info.get('error') if isinstance(repo_info, dict) else "Invalid response"
                    logger.error(f"Error getting GitHub repo info for {service_uid}: {error_msg}")
                    await self.service_manager.status_service.update_service_status(service_uid, ServiceStatus.FAILED, f"Failed to get repo info: {error_msg}")
                    return {'success': False, 'error': error_msg}

                repo_url = repo_info.get('repo_url')
                access_token = repo_info.get('access_token')
                if not repo_url or not access_token:
                    error_msg = f"Missing repo_url or access_token in response for {service_uid}"
                    logger.error(f"{error_msg}: {repo_info}")
                    await self.service_manager.status_service.update_service_status(service_uid, ServiceStatus.FAILED, error_msg)
                    return {'success': False, 'error': error_msg}
                    
                # Clone Repo
                clone_result = await self.github_clone_service.clone_repo(repo_url, access_token, service_uid)
                
                if not clone_result or not clone_result.get("success"):
                    error_msg = clone_result.get('error', 'Unknown clone error')
                    logger.error(f"Clone failed for {service_uid}: {error_msg}")
                    await self.service_manager.status_service.update_service_status(service_uid, ServiceStatus.FAILED, error_msg)
                    return {'success': False, 'error': error_msg}
                
                retrieved_clone_path = clone_result.get('clone_path')
                
                # The GitHub clone service typically calls prepare_build automatically, 
                # but we'll ensure it happens for consistent behavior
                # Since this is a fresh clone, set is_initial_clone=True
                if retrieved_clone_path:
                    await self.build_service.prepare_build(retrieved_clone_path, service_uid, is_initial_clone=True)
                
                return {
                    'success': True,
                    'clone_path': retrieved_clone_path
                }
                    
            except Exception as e:
                error_msg = f"Error installing app for {service_uid}: {str(e)}"
                logger.error(error_msg)
                logger.exception(e)
                await self.service_manager.status_service.update_service_status(service_uid, ServiceStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            logger.error(f"Error in app installation: {str(e)}")
            logger.exception(e)
            if 'service_uid' in locals():
                await self.service_manager.status_service.update_service_status(service_uid, ServiceStatus.FAILED, str(e))
            return {'success': False, 'error': str(e)} 