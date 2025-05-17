import logging
from typing import Dict, Any, Optional
import socketio
from src.services.service_registry import ServiceRegistry
from src.services.github_clone_service import GithubCloneService
from src.services.build_service import BuildService
from src.services.service_status import ServiceStatus
from src.utils.command_registry import CommandRegistry

logger = logging.getLogger(__name__)

class WebSocketEventHandler:
    def __init__(self, sio: socketio.AsyncClient, namespace: str):
        """Initialize the event handler with Socket.IO client and namespace."""
        self.sio = sio
        self.namespace = namespace
        self.services = ServiceRegistry()
        
    @property
    def command_registry(self) -> CommandRegistry:
        registry = self.services.command_registry
        if not registry:
            raise RuntimeError("CommandRegistry not initialized")
        return registry
    
    @property
    def github_clone_service(self) -> GithubCloneService:
        service = self.services.github_clone_service
        if not service:
            raise RuntimeError("GithubCloneService not initialized")
        return service
    
    @property
    def build_service(self) -> BuildService:
        service = self.services.build_service
        if not service:
            raise RuntimeError("BuildService not initialized")
        return service
    
    @property
    def status_service(self):
        service = self.services.status_service
        if not service:
            raise RuntimeError("StatusService not initialized")
        return service
        
    async def _handle_command(self, command_name: str, command_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a command and return the result."""
        try:            
            if not command_name:
                raise ValueError("No command specified in the message")
            
            handler = self.command_registry.get_handler(command_name)
            result = await handler.handle(command_data)
            return result 
            
        except Exception as e:
            logger.error(f"Error executing command '{command_name}': {str(e)}")
            return {
                'command': command_name,
                'success': False,
                'error': f"Agent error processing command: {str(e)}"
            }
    
    def register_handlers(self):
        """Register all event handlers."""
        
        @self.sio.event(namespace=self.namespace)
        async def connect():
            """Handle connection event."""
            logger.info("Connected to PulseUp.")
            try:
                response = await self.sio.call('init', {}, namespace=self.namespace)
                await self._handle_init_response(response)
            except Exception as e:
                logger.error(f"Failed to call /init event or receive response: {e}")
        
        @self.sio.event(namespace=self.namespace)
        async def disconnect():
            """Handle disconnection event."""
            logger.warning("Disconnected from PulseUp.")
        
        @self.sio.on('agent_message', namespace=self.namespace)
        async def on_agent_message(data: Dict[str, Any]):
            """Handle agent messages."""
            command_name = data.get('command')
            command_data = data.get('data', {})
            return await self._handle_command(command_name, command_data)
        
        @self.sio.on('command', namespace=self.namespace)
        async def on_command(data: Dict[str, Any]):
            """Handle generic commands."""
            command_name = data.get('command')
            return await self._handle_command(command_name, data)
        
        # Register dynamic command handlers
        self._register_command_handlers()
    
    def _register_command_handlers(self):
        """Register command-specific handlers."""
        if not self.command_registry._handlers:
            logger.warning("No command handlers to register.")
            return
        
        for command_name in self.command_registry._handlers:
            async def dynamic_handler(data: Dict[str, Any] = None, cmd_name=command_name):
                try:
                    return await self._handle_command(cmd_name, data or {})
                except Exception as e:
                    return {
                        'command': cmd_name,
                        'success': False,
                        'error': f"Agent internal error: {str(e)}"
                    }
            
            self.sio.on(command_name, namespace=self.namespace)(dynamic_handler)
    
    async def _handle_init_response(self, data: Dict[str, Any]):
        """Handle the initialization response from server."""
        services = data.get('services', [])
        if not services:
            return
            
        for service in services:
            service_uid = service.get('uid')
            if not service_uid or service.get('type') != 'app':
                continue
                
            try:
                await self._ensure_repo_cloned(service_uid)
            except Exception as e:
                logger.error(f"Error processing service {service_uid}: {e}")
                logger.exception(e)
                await self.status_service.update_service_status(service_uid, ServiceStatus.FAILED, f"Agent error: {str(e)}")
    
    async def _ensure_repo_cloned(self, service_uid: str):
        """Ensure repository is cloned and build is prepared."""
        try:
            repo_info = await self._get_repo_info(service_uid)
            if not repo_info:
                return
                
            clone_result = await self.github_clone_service.clone_repo(
                repo_info['repo_url'],
                repo_info['access_token'],
                service_uid
            )
            
            if not clone_result or not clone_result.get("success"):
                error_msg = clone_result.get('error', 'Unknown clone error')
                logger.error(f"Clone failed for {service_uid}: {error_msg}")
                await self.status_service.update_service_status(service_uid, ServiceStatus.FAILED, error_msg)
                return
            
            # Prepare build if clone was successful
            clone_path = clone_result.get('clone_path')
            await self.build_service.prepare_build(clone_path, service_uid, is_initial_clone=True)
            
        except Exception as e:
            logger.error(f"Error ensuring repo clone for {service_uid}: {e}")
            await self.status_service.update_service_status(service_uid, ServiceStatus.FAILED, str(e))
    
    async def _get_repo_info(self, service_uid: str) -> Optional[Dict[str, str]]:
        """Get repository information from server."""
        try:
            repo_info = await self.sio.call(
                'get_github_repo',
                {'service_uid': service_uid},
                namespace=self.namespace,
                timeout=30
            )
            
            if not isinstance(repo_info, dict) or 'error' in repo_info:
                error_msg = repo_info.get('error') if isinstance(repo_info, dict) else "Invalid response"
                logger.error(f"Error getting GitHub repo info: {error_msg}")
                await self.status_service.update_service_status(service_uid, ServiceStatus.FAILED, f"Failed to get repo info: {error_msg}")
                return None
            
            repo_url = repo_info.get('repo_url')
            access_token = repo_info.get('access_token')
            
            if not repo_url or not access_token:
                error_msg = "Missing repo_url or access_token in response"
                logger.error(f"{error_msg}: {repo_info}")
                await self.status_service.update_service_status(service_uid, ServiceStatus.FAILED, error_msg)
                return None
            
            return {'repo_url': repo_url, 'access_token': access_token}
            
        except socketio.exceptions.TimeoutError:
            logger.error(f"Timeout getting repo info for {service_uid}")
            await self.status_service.update_service_status(service_uid, ServiceStatus.FAILED, "Timeout waiting for server response")
            return None 