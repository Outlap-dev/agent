import os
import logging
from typing import Tuple, List
from src.installations.installation_manager import InstallationManager

logger = logging.getLogger(__name__)

class SetupService:
    CONFIG_PATH = '/etc/pulseup-agent/config'
    SETUP_COMPLETE_KEY = 'SETUP_COMPLETE'

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
            config_dir = os.path.dirname(self.CONFIG_PATH)
            os.makedirs(config_dir, exist_ok=True)
            mode = 'a' if os.path.exists(self.CONFIG_PATH) else 'w'
            with open(self.CONFIG_PATH, mode) as f:
                f.write(f'\n{self.SETUP_COMPLETE_KEY}=true\n')
        except Exception as e:
            logger.error(f"Error writing to config file: {e}")
            raise

    async def check_and_install_caddy(self) -> Tuple[bool, List[str]]:
        """Check and install Caddy if not already installed."""
        installation_manager = InstallationManager(self.CONFIG_PATH)
        failed_installations = []
        caddy_installer = installation_manager.get_installer()
        if caddy_installer:
            if not await caddy_installer.check_installed():
                logger.info("Caddy not found, attempting installation...")
                if not await caddy_installer.install():
                    failed_installations.append('caddy')
                else:
                    logger.info("Caddy installed successfully.")
            else:
                logger.info("Caddy is already running.")
        else:
            logger.warning("Caddy installer not found in installation manager")
            failed_installations.append('caddy')
        return len(failed_installations) == 0, failed_installations

    def get_pending_installations(self) -> List[str]:
        """Return a list of tools that need to be installed (only Caddy)."""
        pending_tools = []
        try:
            if os.path.exists(self.CONFIG_PATH):
                with open(self.CONFIG_PATH, 'r') as f:
                    content = f.read()
                if 'CADDY_INSTALLED=false' in content:
                    pending_tools.append('caddy')
                elif 'CADDY_INSTALLED=true' not in content:
                    pending_tools.append('caddy')
        except Exception as e:
            logger.error(f"Error reading config file for pending installations: {e}")
            pending_tools = ['caddy']
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