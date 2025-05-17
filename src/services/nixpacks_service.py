import logging
import shutil
import asyncio
from typing import Dict, Any, Optional

from src.services.docker_service import DockerService
from src.services.service_status import ServiceStatus

logger = logging.getLogger(__name__)

class NixpacksService:
    def __init__(self):
        # No checks/installation in __init__
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
            logger.warning(f"SocketManager not set in NixpacksService. Cannot send status update for {service_uid}: {status}")

    async def initialize(self):
        """Checks for Nixpacks and attempts installation if missing."""
        if not self._is_nixpacks_installed():
            logger.warning("Nixpacks command not found. Attempting installation...")
            # Moved the try...except block here to wrap the relevant operations
            try:
                # Await the installation coroutine directly
                await self._install_nixpacks()
                if not self._is_nixpacks_installed():
                    raise EnvironmentError("Nixpacks installation attempt finished, but command is still not found.")
            except Exception as e:
                logger.error(f"Failed during Nixpacks installation attempt: {e}")
                raise EnvironmentError("Nixpacks command not found and installation failed. Please install Nixpacks manually or check prerequisites.")

    def _is_nixpacks_installed(self) -> bool:
        return shutil.which("nixpacks") is not None

    async def _run_shell_command(self, command: str, cwd: str = None):
        # (Similar helper as in GithubCloneService, might refactor later)
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd # Set working directory if provided
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_msg = f"Command '{command}' failed with return code {process.returncode}"
            logger.error(error_msg)
            if stderr:
                 error_msg += f"\nstderr: {stderr.decode().strip()}"
            raise RuntimeError(error_msg)

        return stdout.decode().strip() if stdout else "" # Return stdout

    async def _install_nixpacks(self):
        """Installs Nixpacks using the official script. Requires curl."""
        if not shutil.which("curl"):
             raise EnvironmentError("curl is required to install Nixpacks automatically. Please install curl.")

        # Nixpacks official install script
        install_script_url = "https://nixpacks.com/install.sh"
        # Command to download and execute the script
        # Ensure the user running the agent has permissions to install to /usr/local/bin or similar
        command = f"curl -sSL {install_script_url} | bash"

        try:
            await self._run_shell_command(command)
            # Verify installation path if needed, though _is_nixpacks_installed should work
        except Exception as e:
            logger.error(f"Error during Nixpacks installation script execution: {e}")
            raise

    async def build_image(self, source_path: str, service_uid: str):
        """Builds a container image using Nixpacks."""

        # Define the image name (e.g., pulseup-app:service_uid)
        image_name = f"pulseup-app:{service_uid}"
        # Example build command
        # We need to build *within* the source directory for Nixpacks context
        build_command = f"nixpacks build . --name {image_name}"

        try:
            # Run the command within the source directory
            build_output = await self._run_shell_command(build_command, cwd=source_path)
            return {"success": True, "image_name": image_name}
        except Exception as e:
            logger.error(f"Nixpacks build failed for service {service_uid}: {e}")
            return {"success": False, "error": str(e)}

    async def get_suggested_config(self, source_path: str) -> str | None:
        """Gets the suggested Nixpacks configuration (plan) for a source path."""
        plan_command = "nixpacks plan ."

        try:
            # Run the command within the source directory
            plan_output = await self._run_shell_command(plan_command, cwd=source_path)
            return plan_output
        except Exception as e:
            logger.error(f"Failed to get Nixpacks plan for {source_path}: {e}")
            return None # Return None on failure

    async def deploy(self, deployment_uid: str, source_path: str, service_uid: str, plan_data: Dict[str, Any], container_name: Optional[str] = None, networks: Optional[list] = None) -> Dict[str, Any]:
        """Deploys an application using Nixpacks with the given plan configuration.

        Args:
            source_path: Path to the source code
            service_uid: Unique identifier for the service
            plan_data: Nixpacks plan configuration
            container_name: Optional custom container name for blue-green deployment
            networks: Optional list of Docker networks to connect the container to

        Returns:
            Dictionary containing deployment result
        """
        from src.services.deployment_status import DeploymentStatus
        # Ensure the main logic is within a try block
        try:
            # Update deployment status to indicate deployment started


            await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.IN_PROGRESS, "Starting Nixpacks deployment")

            # Get the start command from the plan
            start_cmd = None
            if 'phases' in plan_data and 'start' in plan_data['phases']:
                start_cmd = plan_data['phases']['start'].get('cmd')

            if not start_cmd:
                raise ValueError("No start command found in Nixpacks plan")

            # Build the image using Nixpacks
            image_name = f"pulseup-app:{service_uid}"

            # Let Nixpacks detect and build the application with the start command
            build_command = f"nixpacks build . --name {image_name} --start-cmd '{start_cmd}'"

            # Optionally update deployment status to indicate building (optional, can be commented out)
            await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.IN_PROGRESS, "Building container image")

            # Run the build command
            build_output = await self._run_shell_command(build_command, cwd=source_path)            

            # Prepare environment variables for docker run, quoting values
            env_vars = {}
            if plan_data.get('env'):
                logger.info(f"Found plan_data['env']: {plan_data['env']}") # DEBUG LOG
                for k, v in plan_data['env'].items():
                    env_vars[k] = str(v)

            # Use the deployment service to handle container deployment
            from docker.errors import APIError
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

                    await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                    return {'success': False, 'error': error_msg}
                
                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.COMPLETED, f"Container ID: {deployment_result.get('container_id')}")
                
                return {
                    'success': True,
                    'image_name': image_name,
                    'container_id': deployment_result.get('container_id'),
                    'container_name': deployment_result.get('container_name'),
                    'deployment_color': deployment_result.get('deployment_color')
                }
                
            except APIError as e:
                error_msg = f"Docker API error during deployment: {e}"
                logger.error(error_msg)

                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            except Exception as e:
                error_msg = f"Unexpected error during deployment: {e}"
                logger.error(error_msg)

                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}

        except Exception as e:
            error_msg = f"Error during Nixpacks deployment: {str(e)}"
            logger.error(error_msg)

            await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
            return {'success': False, 'error': error_msg} 