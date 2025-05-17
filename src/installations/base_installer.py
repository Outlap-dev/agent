import logging
import os
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, Any

logger = logging.getLogger(__name__)

class BaseInstaller(ABC):
    """Base class for all installers."""
    
    def __init__(self, config_path: str = '/etc/pulseup-agent/config'):
        self.config_path = config_path
        
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the name of the tool installed by this installer."""
        pass
    
    @abstractmethod
    async def check_installed(self) -> bool:
        """Check if the tool is already installed."""
        pass
    
    @abstractmethod
    async def install(self) -> bool:
        """Install the tool. Return True if successful, False otherwise."""
        pass
    
    def update_config(self, installed: bool) -> None:
        """Update the configuration file with installation status."""
        try:
            # Ensure the directory exists
            config_dir = os.path.dirname(self.config_path)
            os.makedirs(config_dir, exist_ok=True)
            
            # Append to the config file
            mode = 'a' if os.path.exists(self.config_path) else 'w'
            with open(self.config_path, mode) as f:
                status = "true" if installed else "false"
                f.write(f"{self.tool_name.upper()}_INSTALLED={status}\n")
                
            logger.info(f"Updated configuration for {self.tool_name}: installed={installed}")
            
        except Exception as e:
            logger.error(f"Error updating config file for {self.tool_name}: {str(e)}")
    
    def get_env(self) -> Dict[str, str]:
        """Get a copy of the environment with preferences for system libraries."""
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = '/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu'
        return env
    
    def run_command(self, cmd, shell=False, check=True) -> subprocess.CompletedProcess:
        """Run a command using subprocess."""
        env = self.get_env()
        return subprocess.run(
            cmd,
            shell=shell,
            check=check,
            env=env,
            capture_output=True,
            text=True
        )
    
    def is_ubuntu(self) -> bool:
        """Check if the system is running Ubuntu."""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                return 'ubuntu' in content
        except Exception:
            return False
            
    async def check_and_install(self) -> bool:
        """Check if installed and install if not. Return True if installed (or already was)."""
        if await self.check_installed():
            logger.info(f"{self.tool_name} is already installed")
            self.update_config(True)
            return True
        
        logger.info(f"Installing {self.tool_name}...")
        success = await self.install()
        self.update_config(success)
        
        if success:
            logger.info(f"{self.tool_name} installed successfully")
        else:
            logger.error(f"Failed to install {self.tool_name}")
            
        return success 