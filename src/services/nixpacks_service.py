import logging
import shutil
import asyncio
import os
import json
from typing import Dict, Any, Optional
import aiofiles
from datetime import datetime

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
        self.logs_dir = "/var/log/pulseup/deployments"
        # Ensure logs directory exists
        os.makedirs(self.logs_dir, exist_ok=True)

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
            try:
                await self._install_nixpacks()
                if not self._is_nixpacks_installed():
                    raise EnvironmentError("Nixpacks installation attempt finished, but command is still not found.")
            except Exception as e:
                logger.error(f"Failed during Nixpacks installation attempt: {e}")
                raise EnvironmentError("Nixpacks command not found and installation failed. Please install Nixpacks manually or check prerequisites.")

    def _is_nixpacks_installed(self) -> bool:
        return shutil.which("nixpacks") is not None

    async def _async_stream_reader(
        self,
        stream: asyncio.StreamReader,
        stream_name: str, # "stdout" or "stderr"
        log_file: Optional[str],
        is_stderr: bool
    ) -> str:
        """Helper to read a stream, log its content, and return as a single string."""
        internal_lines = []
        while True:
            line_bytes = await stream.readline()
            if not line_bytes:  # EOF
                break
            
            line = line_bytes.decode('utf-8', errors='replace').strip()
            if line:
                internal_lines.append(line)
                timestamp = datetime.now().isoformat()
                
                log_level_for_file = "INFO"
                log_level_for_logger = "INFO"
                logger_method = logger.info
                
                if is_stderr:
                    is_docker_build_progress = any([
                        line.startswith('#'), 
                        'building with' in line,
                        'DONE' in line and 'ERROR' not in line,
                        'transferring' in line, 
                        'load build definition' in line,
                        'load metadata' in line,
                        'exporting layers' in line,
                        'writing image' in line,
                        'naming to' in line
                    ])
                    if not is_docker_build_progress:
                        log_level_for_file = "ERROR"
                        log_level_for_logger = "ERROR"
                        logger_method = logger.error
                
                file_log_line = f"{timestamp} - {log_level_for_file} - {line}\\n"
                
                if log_file:
                    try:
                        async with aiofiles.open(log_file, mode='a') as f:
                            await f.write(file_log_line)
                    except Exception as e:
                        logger.error(f"Failed to write to build log file {log_file}: {e}")

        return '\n'.join(internal_lines)

    async def _run_shell_command(self, command: str, cwd: str = None, deployment_uid: str = None) -> Dict[str, Any]:
        """Run a shell command, log its output, and return stdout, stderr, and return code."""
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )

        log_file = None
        if deployment_uid:
            log_file_path = os.path.join(self.logs_dir, f"{deployment_uid}_build.log")
            try:
                os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
                log_file = log_file_path
                async with aiofiles.open(log_file, mode='a') as f:
                    await f.write(f"{datetime.now().isoformat()} - INFO - Log file initialized for command: {command}\\n")
            except Exception as e:
                logger.error(f"Failed to create or initialize log file directory {log_file_path}: {e}")
                log_file = None

        stdout_reader_task = asyncio.create_task(
            self._async_stream_reader(process.stdout, "stdout", log_file, is_stderr=False)
        )
        stderr_reader_task = asyncio.create_task(
            self._async_stream_reader(process.stderr, "stderr", log_file, is_stderr=True)
        )

        results = await asyncio.gather(stdout_reader_task, stderr_reader_task, return_exceptions=True)
        
        stdout_str = ""
        stderr_str = ""

        if isinstance(results[0], Exception):
            logger.error(f"Exception in stdout reader task for command '{command}': {results[0]}", exc_info=results[0])
            if log_file:
                async with aiofiles.open(log_file, mode='a') as f: await f.write(f"{datetime.now().isoformat()} - ERROR - Exception in stdout_reader: {str(results[0])}\\n")
        else:
            stdout_str = results[0]

        if isinstance(results[1], Exception):
            logger.error(f"Exception in stderr reader task for command '{command}': {results[1]}", exc_info=results[1])
            if log_file:
                async with aiofiles.open(log_file, mode='a') as f: await f.write(f"{datetime.now().isoformat()} - ERROR - Exception in stderr_reader: {str(results[1])}\\n")
        else:
            stderr_str = results[1]
        
        return_code = await process.wait()

        if return_code != 0:
            detailed_error_log = f"Command '{command}' failed with return code {return_code}. Stderr: {stderr_str if stderr_str else 'N/A'}"
            logger.error(detailed_error_log)
            if log_file: 
                timestamp = datetime.now().isoformat()
                async with aiofiles.open(log_file, mode='a') as f: await f.write(f"{timestamp} - ERROR - {detailed_error_log}\\n")

        return {'stdout': stdout_str, 'stderr': stderr_str, 'return_code': return_code}

    async def _install_nixpacks(self):
        """Installs Nixpacks using the official script. Requires curl."""
        if not shutil.which("curl"):
             raise EnvironmentError("curl is required to install Nixpacks automatically. Please install curl.")

        install_script_url = "https://nixpacks.com/install.sh"
        command = f"curl -sSL {install_script_url} | bash"

        try:
            result = await self._run_shell_command(command)
            if result['return_code'] != 0:
                error_message = f"Nixpacks installation script failed. Code: {result['return_code']}. Stderr: {result['stderr']}"
                logger.error(error_message)
                raise RuntimeError(error_message)
        except Exception as e:
            logger.error(f"Error during Nixpacks installation script execution: {e}")
            raise

    async def build_image(self, source_path: str, service_uid: str, deployment_uid: str = None):
        """Builds a container image using Nixpacks."""
        image_name = f"pulseup-app:{service_uid}"
        build_command = f"nixpacks build . --name {image_name}"

        try:
            result = await self._run_shell_command(build_command, cwd=source_path, deployment_uid=deployment_uid)
            if result['return_code'] != 0:
                error_message = f"Nixpacks build failed for service {service_uid}. Code: {result['return_code']}. Stderr: {result['stderr']}"
                logger.error(error_message)
                return {"success": False, "error": error_message}
            return {"success": True, "image_name": image_name}
        except Exception as e:
            logger.error(f"Exception during Nixpacks build for service {service_uid}: {e}")
            return {"success": False, "error": str(e)}

    async def get_suggested_config(self, source_path: str) -> str | None:
        """Gets the suggested Nixpacks configuration (plan) for a source path."""
        plan_command = "nixpacks plan ."
        try:
            result = await self._run_shell_command(plan_command, cwd=source_path)
            
            if result['return_code'] == 0:
                stdout_str = result['stdout']
                if not stdout_str:
                    logger.error(f"Nixpacks plan for {source_path} was successful but returned empty stdout.")
                    return None

                if result['stderr']:
                    logger.warning(f"Nixpacks plan command for {source_path} produced stderr output: {result['stderr']}")
                
                cleaned_stdout_str = stdout_str.strip()
                if cleaned_stdout_str.startswith('\xef\xbb\xbf'): # UTF-8 BOM
                    cleaned_stdout_str = cleaned_stdout_str[3:]

                try:
                    sanitized_str = cleaned_stdout_str.encode('utf-8', 'replace').decode('utf-8', 'replace')
                    parsed_plan = json.loads(sanitized_str)
                    return json.dumps(parsed_plan, sort_keys=True)
                except json.JSONDecodeError as e_parse:
                    logger.error(f"Failed to parse JSON from Nixpacks plan stdout for {source_path}. Error: {e_parse}. Sanitized stdout: >>>{sanitized_str}<<<", exc_info=True)
                    return None
                except Exception as e_sanitize:
                    logger.error(f"Error during sanitization or parsing of Nixpacks plan for {source_path}: {e_sanitize}. Cleaned stdout: >>>{cleaned_stdout_str}<<<", exc_info=True)
                    return None                    
            else:
                error_message = (
                    f"Nixpacks plan command failed for {source_path}. "
                    f"Return code: {result['return_code']}. Stderr: {result['stderr']}. Stdout: {result['stdout'] if result['stdout'] else 'empty'}"
                )
                logger.error(error_message)
                return None
        except Exception as e_outer:
            logger.error(f"General exception occurred while trying to get Nixpacks plan for {source_path}: {e_outer}", exc_info=True)
            return None

    async def deploy(self, deployment_uid: str, source_path: str, service_uid: str, plan_data: Dict[str, Any], container_name: Optional[str] = None, networks: Optional[list] = None) -> Dict[str, Any]:
        """Deploys an application using Nixpacks with the given plan configuration."""
        from src.services.deployment_status import DeploymentStatus
        try:
            await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.IN_PROGRESS, "Starting Nixpacks deployment")

            start_cmd = plan_data.get('phases', {}).get('start', {}).get('cmd')
            if not start_cmd:
                start_cmd = plan_data.get('start', {}).get('command') or plan_data.get('start', {}).get('cmd')

            if not start_cmd:
                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, "No start command found in Nixpacks plan")
                raise ValueError("No start command found in Nixpacks plan")

            image_name = f"pulseup-app:{service_uid}"
            escaped_start_cmd = start_cmd.replace("'", "'\\''")
            build_command = f"nixpacks build . --name {image_name} --start-cmd '{escaped_start_cmd}'"
            
            await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.IN_PROGRESS, "Building container image")

            build_result = await self._run_shell_command(build_command, cwd=source_path, deployment_uid=deployment_uid)            
            if build_result['return_code'] != 0:
                error_message = f"Nixpacks build failed during deployment for {service_uid}. Code: {build_result['return_code']}. Stderr: {build_result['stderr']}"
                logger.error(error_message)
                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_message)
                return {'success': False, 'error': error_message}

            env_vars = {}
            plan_env = plan_data.get('variables') or plan_data.get('env')
            if plan_env:
                for k, v in plan_env.items():
                    env_vars[k] = str(v)
            
            port_from_plan = plan_data.get('start', {}).get('port') or plan_data.get('port')
            if port_from_plan and 'PORT' not in env_vars :
                env_vars['PORT'] = str(port_from_plan)

            await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.IN_PROGRESS, "Deploying container")

            from docker.errors import APIError
            try:
                if not self.deployment_service:
                    await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, "Deployment service not initialized")
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
                
                if deployment_uid:
                    log_file = os.path.join(self.logs_dir, f"{deployment_uid}_build.log") 
                    timestamp = datetime.now().isoformat()
                    async with aiofiles.open(log_file, mode='a') as f: 
                        await f.write(f"{timestamp} - INFO - Deployment process completed successfully.\\n")
                
                return {
                    'success': True,
                    'image_name': image_name,
                    'container_id': deployment_result.get('container_id'),
                    'container_name': deployment_result.get('container_name'),
                    'deployment_color': deployment_result.get('deployment_color')
                }
                
            except APIError as e:
                error_msg = f"Docker API error during deployment: {e}"
                logger.error(error_msg, exc_info=True)
                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}
            except Exception as e:
                error_msg = f"Unexpected error during container deployment phase: {e}"
                logger.error(error_msg, exc_info=True)
                await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
                return {'success': False, 'error': error_msg}

        except ValueError as ve: 
            error_msg = f"Configuration error during Nixpacks deployment: {str(ve)}"
            logger.error(error_msg)
            if "No start command" not in str(ve):
                 await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = f"Overall error during Nixpacks deployment: {str(e)}"
            logger.error(error_msg, exc_info=True)
            await self.status_service.update_deployment_status(deployment_uid, DeploymentStatus.FAILED, error_msg)
            return {'success': False, 'error': error_msg} 