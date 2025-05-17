import logging
import subprocess
import os
import yaml
from .base_installer import BaseInstaller

logger = logging.getLogger(__name__)

class TraefikInstaller(BaseInstaller):
    """Installer for Traefik."""
    
    TRAEFIK_CONFIG_DIR = '/etc/pulseup-agent/traefik'
    TRAEFIK_CONFIG_FILE = os.path.join(TRAEFIK_CONFIG_DIR, 'traefik.yml')
    TRAEFIK_ACME_FILE = os.path.join(TRAEFIK_CONFIG_DIR, 'acme.json')
    TRAEFIK_CONTAINER_NAME = 'traefik'
    
    @property
    def tool_name(self) -> str:
        return "traefik"
    
    async def check_installed(self) -> bool:
        """Check if the Traefik container is running."""
        try:
            # Check if the container exists and is running
            result = self.run_command([
                'docker', 'ps', '--filter', 
                f'name=^{self.TRAEFIK_CONTAINER_NAME}$', 
                '--format', '{{.Names}}'
            ])
            return self.TRAEFIK_CONTAINER_NAME in result.stdout.strip()
        except subprocess.CalledProcessError:
            return False
        except Exception as e:
            logger.error(f"Error checking Traefik container status: {str(e)}")
            return False
    
    async def install(self) -> bool:
        """Install Traefik as a Docker container."""
        # Traefik requires Docker
        try:
            docker_check = self.run_command(['which', 'docker'])
            if not docker_check or docker_check.returncode != 0:
                logger.error("Docker is required for Traefik installation but is not installed")
                return False
        except Exception:
            logger.error("Failed to check Docker installation, which is required for Traefik")
            return False
            
        try:
            # Ensure config directory exists
            os.makedirs(self.TRAEFIK_CONFIG_DIR, exist_ok=True)
            logger.info(f"Ensuring Traefik config directory exists: {self.TRAEFIK_CONFIG_DIR}")

            # Create basic Traefik configuration file
            if not os.path.exists(self.TRAEFIK_CONFIG_FILE):
                traefik_config = {
                    'entryPoints': {
                        'web': {'address': ':80'},
                        'websecure': {'address': ':443'}
                    },
                    'providers': {
                        'docker': {
                            'exposedByDefault': False
                        }
                    },
                    'api': {
                        'insecure': True  # For simplicity, consider securing this later
                    },
                    'certificatesResolvers': {
                        'letsencrypt': {
                            'acme': {
                                'email': 'youremail@example.com',  # Placeholder
                                'storage': self.TRAEFIK_ACME_FILE,
                                'httpChallenge': {
                                    'entryPoint': 'web'
                                }
                            }
                        }
                    }
                }
                
                with open('/tmp/traefik.yml.tmp', 'w') as f:
                    yaml.dump(traefik_config, f)
                
                self.run_command(['mv', '/tmp/traefik.yml.tmp', self.TRAEFIK_CONFIG_FILE])
                self.run_command(['chmod', '644', self.TRAEFIK_CONFIG_FILE])
                logger.info(f"Created Traefik config file: {self.TRAEFIK_CONFIG_FILE}")
            
            # Create acme.json for Let's Encrypt
            if not os.path.exists(self.TRAEFIK_ACME_FILE):
                self.run_command(['touch', self.TRAEFIK_ACME_FILE])
                self.run_command(['chmod', '600', self.TRAEFIK_ACME_FILE])
                logger.info(f"Created Traefik acme file: {self.TRAEFIK_ACME_FILE}")
                
            # Create Docker network
            try:
                self.run_command(['docker', 'network', 'create', 'traefik-net'], check=False)
            except subprocess.CalledProcessError:
                # Network may already exist, which is fine
                pass

            # Pull the Traefik image
            logger.info("Pulling Traefik image...")
            self.run_command(['docker', 'pull', 'traefik:latest'])

            # Run the Traefik container
            logger.info("Starting Traefik container...")
            self.run_command([
                'docker', 'run', '-d',
                '--name', self.TRAEFIK_CONTAINER_NAME,
                '--restart', 'unless-stopped',
                '-p', '80:80',
                '-p', '443:443',
                '-p', '8080:8080',  # For the dashboard
                '-v', f'{self.TRAEFIK_CONFIG_FILE}:/etc/traefik/traefik.yml',
                '-v', f'{self.TRAEFIK_ACME_FILE}:/acme.json',
                '--network', 'traefik-net',
                'traefik:latest'
            ])

            logger.info("Traefik container started successfully")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install Traefik: {e.stdout} {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Traefik installation: {str(e)}")
            return False 