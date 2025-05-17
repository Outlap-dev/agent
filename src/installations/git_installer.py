import logging
import subprocess
from .base_installer import BaseInstaller

logger = logging.getLogger(__name__)

class GitInstaller(BaseInstaller):
    """Installer for Git."""
    
    @property
    def tool_name(self) -> str:
        return "git"
    
    async def check_installed(self) -> bool:
        """Check if Git is already installed."""
        try:
            self.run_command(['which', 'git'])
            return True
        except subprocess.CalledProcessError:
            return False
    
    async def install(self) -> bool:
        """Install Git on the system."""
        if not self.is_ubuntu():
            logger.error("Git installation is only supported on Ubuntu")
            return False
            
        try:
            # Update package lists
            self.run_command(['apt-get', 'update'])
            # Install Git
            self.run_command(['apt-get', 'install', '-y', 'git'])
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Git: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Git installation: {str(e)}")
            return False 