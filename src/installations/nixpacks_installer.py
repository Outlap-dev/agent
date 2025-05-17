import logging
import subprocess
import os
from .base_installer import BaseInstaller

logger = logging.getLogger(__name__)

class NixpacksInstaller(BaseInstaller):
    """Installer for Nixpacks."""
    
    @property
    def tool_name(self) -> str:
        return "nixpacks"
    
    async def check_installed(self) -> bool:
        """Check if Nixpacks is already installed."""
        try:
            # Try the direct path first
            self.run_command(['which', 'nixpacks'])
            return True
        except subprocess.CalledProcessError:
            # Check the default install location as a fallback
            nixpacks_path = os.path.expanduser('~/.nixpacks/bin/nixpacks')
            return os.path.exists(nixpacks_path)
    
    async def install(self) -> bool:
        """Install Nixpacks using the official install script."""
        try:
            # Use Nixpacks' official install script
            nixpacks_script_command = (
                "curl -sSL https://nixpacks.com/install.sh | bash"
            )
            
            self.run_command(nixpacks_script_command, shell=True)
            
            # Verify installation
            return await self.check_installed()
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Nixpacks: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Nixpacks installation: {str(e)}")
            return False 