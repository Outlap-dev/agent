import logging
import subprocess
from .base_installer import BaseInstaller

logger = logging.getLogger(__name__)

class DockerInstaller(BaseInstaller):
    """Installer for Docker."""
    
    @property
    def tool_name(self) -> str:
        return "docker"
    
    async def check_installed(self) -> bool:
        """Check if Docker is already installed."""
        try:
            self.run_command(['which', 'docker'])
            return True
        except subprocess.CalledProcessError:
            return False
    
    async def install(self) -> bool:
        """Install Docker using the official convenience script."""
        if not self.is_ubuntu():
            logger.error("Docker installation is only supported on Ubuntu")
            return False
            
        try:
            # Use Docker's official convenience script
            docker_script_command = (
                "curl -fsSL https://get.docker.com -o /tmp/get-docker.sh && "
                "chmod +x /tmp/get-docker.sh && "
                "sh /tmp/get-docker.sh"
            )
            
            self.run_command(docker_script_command, shell=True)
            
            # Verify installation
            if await self.check_installed():
                return True
            else:
                logger.error("Docker installation completed but Docker is not available")
                return False
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Docker: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Docker installation: {str(e)}")
            return False 