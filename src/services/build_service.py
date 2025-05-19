import logging
import os
import json
from .docker_service import DockerService 
from .nixpacks_service import NixpacksService
from .service_status import ServiceStatus
from typing import TYPE_CHECKING, Dict, Any, List
if TYPE_CHECKING:
    from src.websocket.socket_manager import SocketManager 

logger = logging.getLogger(__name__)

class DeploymentStatus:
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

    @classmethod
    def choices(cls) -> List[str]:
        return [
            cls.PENDING,
            cls.IN_PROGRESS,
            cls.COMPLETED,
            cls.FAILED,
            cls.CANCELLED
        ]

class BuildService:
    # Inject DockerService and NixpacksService
    def __init__(self, docker_service: DockerService, nixpacks_service: NixpacksService):
        self.docker_service = docker_service
        self.nixpacks_service = nixpacks_service
        self.socket_manager = None # Will be set via setter
        # Store build information per service_uid
        self.build_plans: Dict[str, Dict[str, Any]] = {}

    def set_socket_manager(self, socket_manager: 'SocketManager'):
        """Sets the SocketManager instance for sending status updates."""
        self.socket_manager = socket_manager
        self.nixpacks_service.set_socket_manager(socket_manager)

    def _find_dockerfile_paths(self, base_path: str) -> List[str]:
        """
        Finds all Dockerfile paths in a repository.
        
        Args:
            base_path: Root path to start searching from
            
        Returns:
            List of relative Dockerfile paths
        """
        dockerfile_paths = []
        
        for root, dirs, files in os.walk(base_path):
            # Skip common directories that shouldn't contain Dockerfiles to build
            if ('.git' in root or 'node_modules' in root or 
                'dist' in root or '.cache' in root or 
                '__pycache__' in root):
                continue
                
            for file in files:
                if 'dockerfile' in file.lower():
                    # Get the relative path from the base_path
                    abs_path = os.path.join(root, file)
                    rel_path = os.path.relpath(abs_path, base_path)
                    dockerfile_paths.append(rel_path)
        
        return dockerfile_paths

    async def _send_docker_config(self, service_uid: str, dockerfile_paths: List[str]):
        """
        Sends the detected Dockerfile paths to the server.
        
        Args:
            service_uid: Service UID to identify the service
            dockerfile_paths: List of relative Dockerfile paths
        """
        if not self.socket_manager:
            logger.error("Cannot send Docker config: SocketManager not set.")
            return
        
        try:
            payload = {
                'service_uid': service_uid,
                'dockerfile_paths': dockerfile_paths
            }
            
            await self.socket_manager.sio.emit(
                'update_docker_config',
                payload,
                namespace=self.socket_manager.namespace
            )            
        except Exception as e:
            logger.error(f"Failed to send Docker config update for {service_uid}: {e}")
            # Don't necessarily fail the whole prep for this, but log it.

    async def _send_nixpacks_config(self, service_uid: str, plan_json_str: str):
        """Sends the generated Nixpacks configuration plan to the server."""
        if not self.socket_manager:
            logger.error("Cannot send Nixpacks config: SocketManager not set.")
            return
        
        try:
            # Parse the JSON string into a dictionary
            config_data = json.loads(plan_json_str)            
            
            payload = {
                'service_uid': service_uid,
                'config': config_data  # Send the parsed dictionary
            }
            await self.socket_manager.sio.emit(
                'update_nixpacks_config', 
                payload,
                namespace=self.socket_manager.namespace
            )
        except json.JSONDecodeError:
            logger.error(f"Failed to parse Nixpacks plan JSON for {service_uid}: {plan_json_str}")
        except Exception as e:
            logger.error(f"Failed to send Nixpacks config update for {service_uid}: {e}")


    async def prepare_build(self, clone_path: str, service_uid: str, is_initial_clone: bool = False):
        """Checks for Dockerfile or prepares Nixpacks plan, but does not build."""
        self.build_plans.pop(service_uid, None) # Clear any previous plan

        try:
            # Find all Dockerfile paths in the repository
            dockerfile_paths = self._find_dockerfile_paths(clone_path)
            
            # Send docker config even if we'll use Nixpacks
            if dockerfile_paths:
                await self._send_docker_config(service_uid, dockerfile_paths)
                
            dockerfile_path = os.path.join(clone_path, 'Dockerfile')
            
            if os.path.exists(dockerfile_path):
                self.build_plans[service_uid] = {
                    'type': 'docker',
                    'context_path': clone_path,
                    'plan': None
                }
            else:
                # Ensure Nixpacks is ready before getting plan
                suggested_plan = await self.nixpacks_service.get_suggested_config(clone_path)
                
                if suggested_plan:
                    self.build_plans[service_uid] = {
                        'type': 'nixpacks',
                        'context_path': clone_path,
                        'plan': suggested_plan
                    }
                    # Only send the nixpacks config to the server on initial clone
                    if is_initial_clone:
                        # Send the full plan back to the server
                        await self._send_nixpacks_config(service_uid, suggested_plan)
                else:
                    logger.error(f"Failed to generate Nixpacks plan for {service_uid}. Cannot determine build type.")
        except Exception as e:
            logger.error(f"Exception during build preparation for {service_uid}: {e}")
            logger.exception(e)
            
    def get_build_command_info(self, service_uid: str) -> Dict[str, Any] | None:
        """Returns information needed to execute the build for a service."""
        plan_info = self.build_plans.get(service_uid)
        if not plan_info:
            logger.warning(f"No build plan found for service {service_uid}")
            return None

        build_type = plan_info.get('type')
        context_path = plan_info.get('context_path')
        image_name = f"pulseup-app:{service_uid}"
        command = None

        if build_type == 'docker':
            command = f"docker build -t {image_name} ."
        elif build_type == 'nixpacks':
            command = f"nixpacks build . --name {image_name}"
        else:
             logger.error(f"Unknown build type '{build_type}' for service {service_uid}")
             return None

        return {
            "service_uid": service_uid,
            "type": build_type,
            "command": command,
            "cwd": context_path,
            "plan": plan_info.get('plan') # Include Nixpacks plan if available
        }