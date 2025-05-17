import logging
import subprocess
import os
import docker
from .base_installer import BaseInstaller

logger = logging.getLogger(__name__)

class CaddyInstaller(BaseInstaller):
    """Installer for Caddy."""
    
    CADDY_CONFIG_DIR = '/etc/pulseup-agent/caddy'
    CADDY_CONFIG_FILE = os.path.join(CADDY_CONFIG_DIR, 'Caddyfile')
    CADDY_DATA_DIR = os.path.join(CADDY_CONFIG_DIR, 'data')
    CADDY_CONFIG_DIR_HOST = '/etc/caddy'
    CADDY_CONTAINER_NAME = 'caddy'
    
    @property
    def tool_name(self) -> str:
        return "caddy"
    
    async def check_installed(self) -> bool:
        """Check if the Caddy container is running."""
        try:
            client = docker.from_env()
            containers = client.containers.list(filters={'name': self.CADDY_CONTAINER_NAME})
            return len(containers) > 0 and containers[0].status == 'running'
        except Exception as e:
            logger.error(f"Error checking Caddy container status: {str(e)}")
            return False
    
    async def install(self) -> bool:
        """Install Caddy as a Docker container."""
        try:
            # Ensure Docker client is available
            client = docker.from_env()
        except Exception:
            logger.error("Docker is required for Caddy installation but could not be initialized")
            return False
            
        try:
            # Create required directories
            os.makedirs(self.CADDY_CONFIG_DIR, exist_ok=True)            
            os.makedirs(self.CADDY_DATA_DIR, exist_ok=True)

            # Create domains.json file if it doesn't exist
            domains_file = os.path.join(self.CADDY_CONFIG_DIR, 'domains.json')
            if not os.path.exists(domains_file):
                with open(domains_file, 'w') as f:
                    f.write('{}')
                logger.info(f"Created domains.json file at {domains_file}")

            # Create basic Caddy configuration file
            if not os.path.exists(self.CADDY_CONFIG_FILE):
                # Basic Caddyfile content
                caddyfile_content = """
# Global options
{
    # Email for Let's Encrypt
    email youremail@example.com # TODO: Replace with your email
    
    # Use the HTTP challenge for Let's Encrypt
    acme_ca https://acme-v02.api.letsencrypt.org/directory    
    
    # Logging settings
    log {
        output file /var/log/caddy/access.log
        format json
    }
}
                """
                
                with open('/tmp/Caddyfile.tmp', 'w') as f:
                    f.write(caddyfile_content)
                
                self.run_command(['mv', '/tmp/Caddyfile.tmp', self.CADDY_CONFIG_FILE])
                self.run_command(['chmod', '644', self.CADDY_CONFIG_FILE])
                logger.info(f"Created default Caddyfile at {self.CADDY_CONFIG_FILE}")

            # Create Docker network
            try:
                client.networks.create('caddy-net', driver='bridge', check_duplicate=True)
            except docker.errors.APIError as e:
                if 'already exists' not in str(e):
                    logger.warning(f"Failed to create Docker network: {e}")

            # Check if ports 80 and 443 are available
            try:
                # Check if lsof is available
                lsof_check = self.run_command(['which', 'lsof'], check=False)
                if lsof_check.returncode == 0:
                    # Check port 80
                    port_check_80 = self.run_command(['lsof', '-i', ':80'], check=False)
                    if port_check_80.returncode == 0 and port_check_80.stdout.strip():
                        logger.warning("Port 80 is already in use. Caddy may not start properly.")
                    
                    # Check port 443
                    port_check_443 = self.run_command(['lsof', '-i', ':443'], check=False)
                    if port_check_443.returncode == 0 and port_check_443.stdout.strip():
                        logger.warning("Port 443 is already in use. Caddy may not start properly.")
                else:
                    # Try alternative method with netstat if available
                    netstat_check = self.run_command(['which', 'netstat'], check=False)
                    if netstat_check.returncode == 0:
                        port_check = self.run_command(['netstat', '-tuln'], check=False)
                        if ':80 ' in port_check.stdout:
                            logger.warning("Port 80 is already in use. Caddy may not start properly.")
                        if ':443 ' in port_check.stdout:
                            logger.warning("Port 443 is already in use. Caddy may not start properly.")
                    else:
                        logger.info("Cannot check port availability: neither lsof nor netstat found")
            except Exception as e:
                logger.warning(f"Failed to check port availability: {str(e)}")

            # Pull the Caddy image
            logger.info("Pulling Caddy image...")
            client.images.pull('caddy:latest')

            # Run the Caddy container
            logger.info("Starting Caddy container...")
            try:
                container = client.containers.run(
                    'caddy:latest',
                    name=self.CADDY_CONTAINER_NAME,
                    detach=True,
                    restart_policy={'Name': 'unless-stopped'},
                    ports={'80/tcp': 80, '443/tcp': 443},
                    volumes={
                        self.CADDY_CONFIG_DIR: {'bind': '/etc/caddy/config', 'mode': 'rw'},
                        self.CADDY_DATA_DIR: {'bind': '/data', 'mode': 'rw'}
                    },
                    network='caddy-net',
                    command="caddy run --config /etc/caddy/config/Caddyfile",
                    environment={'CADDY_CONFIG': '/etc/caddy/config/Caddyfile'}
                )
                logger.info("Caddy container started successfully")
                return True
            except docker.errors.ContainerError as e:
                # If container fails to start, log the error
                logger.error(f"Caddy container failed to start: {str(e)}")
                
                # Try to remove the failed container
                try:
                    container = client.containers.get(self.CADDY_CONTAINER_NAME)
                    container.remove(force=True)
                except Exception:
                    pass
                return False
            
        except Exception as e:
            logger.error(f"Unexpected error during Caddy installation: {str(e)}")
            return False 