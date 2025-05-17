import logging
import os
import json
import asyncio
import docker
from typing import Dict, List, Optional, Set, Any

logger = logging.getLogger(__name__)

class CaddyService:
    """
    Service to manage Caddy configuration and Docker container integration.
    Provides methods to:
    - Add/remove domains for containers
    - Manage Caddy configuration
    - Connect containers to the Caddy network
    """
    
    CADDY_CONFIG_DIR = '/etc/pulseup-agent/caddy'
    CADDY_CONFIG_FILE = os.path.join(CADDY_CONFIG_DIR, 'Caddyfile')
    CADDY_DATA_DIR = os.path.join(CADDY_CONFIG_DIR, 'data')
    CADDY_CONFIG_DOMAINS_FILE = os.path.join(CADDY_CONFIG_DIR, 'domains.json')
    CADDY_CONTAINER_NAME = 'caddy'
    CADDY_NETWORK = 'caddy-net'
    DEFAULT_PORT = '80'
    
    def __init__(self):
        """Initialize the Caddy service."""
        self.docker_client = None
        
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
    
    async def initialize(self) -> bool:
        """Initialize the Caddy service."""
        if not self.docker_client:
            logger.error("Docker client unavailable. Docker is required for Caddy service.")
            return False
        
        # Create required directories
        os.makedirs(self.CADDY_CONFIG_DIR, exist_ok=True)
        os.makedirs(self.CADDY_DATA_DIR, exist_ok=True)
        
        # Create domains.json file if it doesn't exist
        if not os.path.exists(self.CADDY_CONFIG_DOMAINS_FILE):
            with open(self.CADDY_CONFIG_DOMAINS_FILE, 'w') as f:
                json.dump({}, f)
        
        # Create Caddy network if it doesn't exist
        try:
            networks = self.docker_client.networks.list(names=[self.CADDY_NETWORK])
            if not networks:
                self.docker_client.networks.create(
                    self.CADDY_NETWORK,
                    driver="bridge",
                    check_duplicate=True
                )
                logger.info(f"Created Docker network: {self.CADDY_NETWORK}")
        except Exception as e:
            logger.error(f"Error creating Caddy network: {e}")
        
        return True
    
    async def is_caddy_running(self) -> bool:
        """Check if Caddy is running."""
        if not self.docker_client:
            return False
            
        try:
            containers = self.docker_client.containers.list(filters={'name': self.CADDY_CONTAINER_NAME})
            return len(containers) > 0 and containers[0].status == 'running'
        except Exception as e:
            logger.error(f"Error checking Caddy container status: {str(e)}")
            return False
    
    async def add_site(self, domain: str, target: str, ssl: bool = True, options: dict = None, port: int = None) -> bool:
        """
        Add a new site to Caddy configuration.
        
        Args:
            domain: Domain name
            target: Target container name or URL
            ssl: Whether to enable SSL
            options: Additional Caddy options
            port: Port to forward to (defaults to DEFAULT_PORT)
            
        Returns:
            True if successful, False otherwise
        """
        if not options:
            options = {}
            
        # Format target URL if needed
        if port is None:
            port = self.DEFAULT_PORT
            
        if not target.startswith('http://') and not target.startswith('https://'):
            # Check if it's a container name
            try:
                if self.docker_client:
                    container = self.docker_client.containers.get(target)
                    # Use container name as hostname in the caddy network with specified port
                    target_url = f"http://{target}:{port}"
                    
                    # Ensure container is in the Caddy network
                    await self.ensure_container_in_network(target, self.CADDY_NETWORK)
                else:
                    # Assume it's a hostname with specified port
                    target_url = f"http://{target}:{port}"
            except docker.errors.NotFound:
                # It's not a container, treat as direct IP with specified port
                target_url = f"http://{target}:{port}"
        else:
            # Already a URL, use as is
            target_url = target
        
        # Create site configuration
        site_config = {
            'domain': domain,
            'target': target_url,
            'ssl': ssl,
            'options': options
        }
        
        # Read current domains
        domains = await self.read_domains()
        
        # Add the new domain
        domains[domain] = site_config
        
        # Write updated domains
        success = await self.write_domains(domains)
        
        # Reload Caddy if successful
        if success:
            await self.reload_caddy()
            
        return success
    
    async def remove_site(self, domain: str) -> bool:
        """
        Remove a site from Caddy configuration.
        
        Args:
            domain: Domain name to remove
            
        Returns:
            True if successful, False otherwise
        """
        # Read current domains
        domains = await self.read_domains()
        
        # Check if domain exists
        if domain not in domains:
            logger.warning(f"Domain {domain} not found in Caddy configuration")
            return False
        
        # Remove the domain
        del domains[domain]
        
        # Write updated domains
        success = await self.write_domains(domains)
        
        # Reload Caddy if successful
        if success:
            await self.reload_caddy()
            
        return success
    
    async def list_sites(self) -> Dict[str, Any]:
        """
        List all configured sites.
        
        Returns:
            Dictionary with domain configurations
        """
        return await self.read_domains()
    
    async def read_domains(self) -> Dict[str, Any]:
        """
        Read domains from the domains.json file.
        
        Returns:
            Dictionary with domain configurations
        """
        try:
            if os.path.exists(self.CADDY_CONFIG_DOMAINS_FILE):
                with open(self.CADDY_CONFIG_DOMAINS_FILE, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error reading domains file: {str(e)}")
            return {}
    
    async def write_domains(self, domains: Dict[str, Any]) -> bool:
        """
        Write domains to the domains.json file.
        
        Args:
            domains: Dictionary with domain configurations
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.CADDY_CONFIG_DOMAINS_FILE), exist_ok=True)
            
            # Write to temporary file first
            temp_file = f"{self.CADDY_CONFIG_DOMAINS_FILE}.tmp"
            with open(temp_file, 'w') as f:
                json.dump(domains, f, indent=2)
            
            # Move to final location
            os.rename(temp_file, self.CADDY_CONFIG_DOMAINS_FILE)
            
            # Generate Caddyfile from domains
            await self.generate_caddyfile(domains)
            
            return True
        except Exception as e:
            logger.error(f"Error writing domains file: {str(e)}")
            return False
    
    async def generate_caddyfile(self, domains: Dict[str, Any]) -> bool:
        """
        Generate Caddyfile from domains.
        
        Args:
            domains: Dictionary with domain configurations
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.CADDY_CONFIG_FILE), exist_ok=True)
            
            # Global options
            caddyfile = """
# Global options
{
    # Email for Let's Encrypt
    email youremail@example.com
    
    # Use HTTP challenge for Let's Encrypt (proper Caddy v2 syntax)
    acme_ca https://acme-v02.api.letsencrypt.org/directory
    
    # Handle HTTP challenges without redirects
    auto_https disable_redirects
    
    # Logging settings
    log {
        output file /var/log/caddy/access.log
        format json
    }
}

# Default site - Handles requests to the server's IP without a domain
:80 {
    # Respond with a message for now
    respond "Caddy reverse proxy is running. Configure a domain to access your applications." 200
}
"""
            
            # Add each site
            for domain, config in domains.items():
                target = config.get('target')
                ssl = config.get('ssl', True)
                options = config.get('options', {})
                
                # Domain line
                caddyfile += f"\n{domain} {{\n"
                
                # SSL options
                if ssl:
                    caddyfile += "    tls {\n"
                    caddyfile += "        protocols tls1.2 tls1.3\n"
                    caddyfile += "    }\n"
                else:
                    caddyfile += "    tls off\n"
                
                # Add custom options
                for key, value in options.items():
                    caddyfile += f"    {key} {value}\n"
                
                # Reverse proxy
                caddyfile += f"    reverse_proxy {target}\n"
                
                # Close site block
                caddyfile += "}\n"
            
            # Write to temporary file first
            temp_file = f"{self.CADDY_CONFIG_FILE}.tmp"
            with open(temp_file, 'w') as f:
                f.write(caddyfile)
            
            # Move to final location
            os.rename(temp_file, self.CADDY_CONFIG_FILE)
            
            return True
        except Exception as e:
            logger.error(f"Error generating Caddyfile: {str(e)}")
            return False
    
    async def reload_caddy(self) -> bool:
        """
        Reload Caddy configuration.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.docker_client:
            return False
            
        try:
            # Get Caddy container
            caddy = self.docker_client.containers.get(self.CADDY_CONTAINER_NAME)
            
            # Execute reload command - Fix the path to match the container's mounted path
            result = caddy.exec_run("caddy reload --config /etc/caddy/config/Caddyfile")
            
            # Log the execution result to help with debugging
            exit_code = result.exit_code
            if exit_code != 0:
                logger.error(f"Caddy reload command failed with exit code {exit_code}: {result.output.decode('utf-8', errors='ignore')}")
                return False
                
            logger.info("Caddy configuration reloaded successfully")
            return True
        except docker.errors.NotFound:
            logger.error(f"Caddy container not found")
            return False
        except Exception as e:
            logger.error(f"Error reloading Caddy configuration: {str(e)}")
            return False
    
    async def ensure_container_in_network(self, container_name: str, network_name: str) -> bool:
        """
        Ensure container is connected to the specified network.
        
        Args:
            container_name: Container name
            network_name: Network name
            
        Returns:
            True if successful, False otherwise
        """
        if not self.docker_client:
            return False
            
        try:
            # Get container
            container = self.docker_client.containers.get(container_name)
            
            # Try to get network
            try:
                network = self.docker_client.networks.get(network_name)
            except docker.errors.NotFound:
                # Create network if it doesn't exist
                network = self.docker_client.networks.create(
                    network_name,
                    driver='bridge',
                    check_duplicate=True
                )
                logger.info(f"Created Docker network: {network_name}")
            
            # Check if container is already connected
            network_info = network.attrs.get('Containers', {})
            if container.id in network_info:
                # Already connected
                return True
            
            # Connect container to network
            network.connect(container)
            logger.info(f"Connected container {container_name} to network {network_name}")
            
            return True
        except docker.errors.NotFound as e:
            logger.error(f"Container not found: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error connecting container to network: {str(e)}")
            return False 