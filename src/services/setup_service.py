import os
import subprocess
import logging
import yaml
from typing import Tuple, List
from src.installations.installation_manager import InstallationManager

logger = logging.getLogger(__name__)

class SetupService:
    CONFIG_PATH = '/etc/pulseup-agent/config'
    SETUP_COMPLETE_KEY = 'SETUP_COMPLETE'

    @staticmethod
    def is_command_available(command: str) -> bool:
        """Check if a command is available in the system."""
        try:
            # Set environment to prefer system libraries over bundled ones
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
            
            subprocess.run(['which', command], capture_output=True, check=True, env=env)
            return True
        except subprocess.CalledProcessError:
            return False

    def is_ubuntu(self) -> bool:
        """Check if the system is running Ubuntu."""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'ubuntu' in content
        except Exception:
            return False

    async def install_docker(self) -> bool:
        """Install Docker on Ubuntu system using the official Docker script."""
        try:
            logger.info("Installing Docker using the official convenience script...")
            
            # Set environment to prefer system libraries over bundled ones to avoid conflicts
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
            
            # Use Docker's convenience script instead of apt commands
            docker_script_command = (
                "curl -fsSL https://get.docker.com -o /tmp/get-docker.sh && "
                "chmod +x /tmp/get-docker.sh && "
                "sh /tmp/get-docker.sh"
            )
            subprocess.run(docker_script_command, shell=True, check=True, env=env)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Docker: {e}")
            return False

    async def install_git(self) -> bool:
        """Install Git on Ubuntu system."""
        try:
            # Set environment to prefer system libraries over bundled ones
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
            
            subprocess.run(['apt-get', 'update'], check=True, env=env)
            subprocess.run(['apt-get', 'install', '-y', 'git'], check=True, env=env)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Git: {e}")
            return False

    def check_docker_installed(self) -> bool:
        """Check if Docker is installed and available."""
        try:
            # Set environment to prefer system libraries over bundled ones
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
            
            subprocess.run(['which', 'docker'], capture_output=True, check=True, env=env)
            return True
        except subprocess.CalledProcessError:
            return False

    def check_git_installed(self) -> bool:
        """Check if Git is installed and available."""
        try:
            # Set environment to prefer system libraries over bundled ones
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
            
            subprocess.run(['which', 'git'], capture_output=True, check=True, env=env)
            return True
        except subprocess.CalledProcessError:
            return False

    def is_setup_complete(self) -> bool:
        """Check if initial setup has been completed."""
        if not os.path.exists(self.CONFIG_PATH):
            return False
        
        try:
            with open(self.CONFIG_PATH, 'r') as f:
                content = f.read()
                return f'{self.SETUP_COMPLETE_KEY}=true' in content
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
            return False

    def mark_setup_complete(self) -> None:
        """Mark the setup as complete in the config file."""
        try:
            # Ensure the directory exists before trying to write the file
            config_dir = os.path.dirname(self.CONFIG_PATH)
            os.makedirs(config_dir, exist_ok=True)
            
            mode = 'a' if os.path.exists(self.CONFIG_PATH) else 'w'
            with open(self.CONFIG_PATH, mode) as f:
                f.write(f'\n{self.SETUP_COMPLETE_KEY}=true\n')
        except Exception as e:
            logger.error(f"Error writing to config file: {e}")
            raise

    async def check_nixpacks_installed(self) -> bool:
        """Check if Nixpacks is installed and available."""
        # Set environment to prefer system libraries over bundled ones
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
        
        # The install script might put it in ~/.nixpacks/bin, which might not be in default PATH
        # We check common locations first
        try:
            subprocess.run(['which', 'nixpacks'], capture_output=True, check=True, env=env)
            return True
        except subprocess.CalledProcessError:
            # Check the default install location
            nixpacks_path = os.path.expanduser('~/.nixpacks/bin/nixpacks')
            return os.path.exists(nixpacks_path)

    async def install_nixpacks(self) -> bool:
        """Install Nixpacks using the official install script."""
        logger.info("Attempting to install Nixpacks...")
        try:
            # Set environment to prefer system libraries over bundled ones
            env = os.environ.copy()
            env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
            
            # The script needs to be run as the user who will use nixpacks,
            # but the agent might run as root. Running as root might install
            # it in /root/.nixpacks, which isn't ideal. 
            # For now, we'll run it directly, assuming the agent's user context
            # is appropriate or that the user will manage path adjustments.
            command = "curl -sSL https://nixpacks.com/install.sh | bash"
            # Use shell=True cautiously. Ensure the source URL is trusted.
            subprocess.run(command, shell=True, check=True, capture_output=True, env=env)
            logger.info("Nixpacks installation script executed.")
            # Verify installation after running the script
            return await self.check_nixpacks_installed()
        except subprocess.CalledProcessError as e:
            logger.error(f"Nixpacks installation script failed: {e.stderr.decode() if e.stderr else e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Nixpacks installation: {e}")
            return False

    async def check_and_install_requirements(self) -> Tuple[bool, list[str]]:
        """Check requirements and attempt to install missing ones on Ubuntu."""
        if not self.is_ubuntu():
            logger.error("This installation script only supports Ubuntu systems")
            return False, ["unsupported-system"]

        # Create installation manager for caddy
        installation_manager = InstallationManager(self.CONFIG_PATH)

        failed_installations = []
        docker_installed = self.check_docker_installed()

        # Check and install Docker
        if not docker_installed:
            logger.info("Docker not found, attempting installation...")
            if await self.install_docker():
                docker_installed = True # Mark as installed for subsequent checks
            else:
                failed_installations.append('docker')

        # Check and install Git
        if not self.check_git_installed():
            logger.info("Git not found, attempting installation...")
            if not await self.install_git():
                failed_installations.append('git')

        # Check and install Nixpacks
        if not await self.check_nixpacks_installed():
            logger.info("Nixpacks not found, attempting installation...")
            if not await self.install_nixpacks():
                failed_installations.append('nixpacks')
        else:
            logger.info("Nixpacks is already installed.")

        # Check and install Caddy using the dedicated installer (only if Docker is available)
        if docker_installed:
            caddy_installer = installation_manager.get_installer('caddy')
            if caddy_installer:
                if not await caddy_installer.check_installed():
                    logger.info("Caddy not found, attempting installation...")
                    if not await caddy_installer.install():
                        failed_installations.append('caddy')
                else:
                    logger.info("Caddy is already running.")
            else:
                logger.warning("Caddy installer not found in installation manager")
                failed_installations.append('caddy')
        else:
            logger.warning("Skipping Caddy installation because Docker is not installed or failed to install.")
            failed_installations.append('caddy')

        return len(failed_installations) == 0, failed_installations

    def get_pending_installations(self) -> List[str]:
        """Return a list of tools that need to be installed."""
        pending_tools = []
        
        # Add tools that aren't installed yet (except git, which gets installed automatically)
        if not self.check_docker_installed():
            pending_tools.append('docker')
        
        # Git is no longer included in pending installations as we install it automatically
        # if needed in agent.py
            
        # For async checks, we need to check the config file
        # since we can't call async functions here
        try:
            if os.path.exists(self.CONFIG_PATH):
                with open(self.CONFIG_PATH, 'r') as f:
                    content = f.read()
                    
                # Check for nixpacks
                if 'NIXPACKS_INSTALLED=false' in content:
                    pending_tools.append('nixpacks')
                elif 'NIXPACKS_INSTALLED=true' not in content:
                    # If we don't have a status, we need to check
                    pending_tools.append('nixpacks')
                
                # Check for caddy
                if 'CADDY_INSTALLED=false' in content:
                    pending_tools.append('caddy')
                elif 'CADDY_INSTALLED=true' not in content:
                    # If we don't have a status, we need to check
                    pending_tools.append('caddy')
        except Exception as e:
            logger.error(f"Error reading config file for pending installations: {e}")
            # Assume these need installation if we can't check
            if 'nixpacks' not in pending_tools:
                pending_tools.append('nixpacks')
            if 'caddy' not in pending_tools:
                pending_tools.append('caddy')
                
        return pending_tools

    async def initialize(self) -> bool:
        """
        Run simplified initial setup - just create config file 
        and connect to websocket without installing tools.
        """
        
        # Create config directory if it doesn't exist
        config_dir = os.path.dirname(self.CONFIG_PATH)
        os.makedirs(config_dir, exist_ok=True)
        
        # Forward environment variables to the config file
        self._forward_env_vars_to_config()
        
        # Check if already completed
        if self.is_setup_complete():
            logger.info("Setup marked as complete in config")
            
            # Even if setup is marked complete, we want to identify pending installations
            # for potential notification to the server
            pending_tools = self.get_pending_installations()
            if pending_tools:
                logger.info(f"Note: There are pending tool installations: {', '.join(pending_tools)}")
            return True
        
        try:
            # In the new setup approach, we don't wait for tool installation -
            # just mark setup as complete and let the installation happen later
            # through the installation handler
            
            # Write pending installation status to config
            pending_tools = self.get_pending_installations()
            with open(self.CONFIG_PATH, 'a') as f:
                for tool in pending_tools:
                    # Mark that these tools need installation but aren't installed yet
                    f.write(f"{tool.upper()}_INSTALLED=false\n")
                
                # Mark setup as complete
                f.write(f"{self.SETUP_COMPLETE_KEY}=true\n")
                
            return True
            
        except Exception as e:
            logger.error(f"Error during initialization: {e}")
            return False
            
    def _forward_env_vars_to_config(self) -> None:
        """
        Forward environment variables to the config file to ensure
        consistent configuration across restarts.
        """
        
        # Important environment variables to persist
        env_vars_to_forward = [
            'WEBSOCKET_URL',
            'AGENT_TOKEN',
            'AGENT_ID',
            'LOG_LEVEL',
            'DEBUG'
        ]
        
        # Get existing config content
        existing_content = ""
        if os.path.exists(self.CONFIG_PATH):
            try:
                with open(self.CONFIG_PATH, 'r') as f:
                    existing_content = f.read()
            except Exception as e:
                logger.error(f"Error reading config file: {e}")
        
        # Write new values for any environment variables that exist
        try:
            with open(self.CONFIG_PATH, 'a') as f:
                for var_name in env_vars_to_forward:
                    var_value = os.environ.get(var_name)
                    if var_value:
                        # Only write if the variable exists in environment
                        # and is not already in the config with the same value
                        var_line = f"{var_name}={var_value}"
                        if var_line not in existing_content:
                            f.write(f"{var_line}\n")
        except Exception as e:
            logger.error(f"Error writing environment variables to config file: {e}")