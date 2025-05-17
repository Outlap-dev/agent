import logging
import os
import socket
import requests
import json
from src.handlers.base_handler import CommandHandler

logger = logging.getLogger(__name__)

class DomainHandler(CommandHandler):
    """
    Handler for managing domains for containers.
    Provides simple methods to add and verify domains.
    """
    
    def __init__(self):
        """Initialize the domain handler."""
        self.docker_client = None
        try:
            import docker
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
    
    def get_command_name(self) -> str:
        """Get the command name for this handler."""
        return "manage_domain"
    
    async def handle(self, payload: dict) -> dict:
        """
        Handle domain management commands.
        
        Commands:
        - add_domain: Add a domain to a service
          Parameters:
            - domain: Domain name to add
            - service_uid: Service UID to add domain to
            - port: (Optional) Port to forward to (defaults to 80)
        - remove_domain: Remove a domain from a service
          Parameters:
            - domain: Domain name to remove
        - verify_domain: Verify a domain points to this server
          Parameters:
            - domain: Domain name to verify
        """        
        if not self.docker_client:
            return {
                "success": False,
                "message": "Docker client unavailable"
            }
        
        # Get the action
        action = payload.get('action')
        if not action:
            return {
                "success": False,
                "message": "No action specified. Valid actions: add_domain, remove_domain"
            }
        
        # Handle different actions
        if action == 'add_domain':
            return await self._handle_add_domain(payload)
        elif action == 'remove_domain':
            return await self._handle_remove_domain(payload)
        else:
            return {
                "success": False,
                "message": f"Invalid action: {action}. Valid actions: add_domain, remove_domain"
            }
    
    async def _handle_add_domain(self, payload: dict) -> dict:
        """
        Add a domain to a service.
        
        Required payload fields:
        - domain: Domain name to add
        - service_uid: Service UID to add domain to
        
        Optional payload fields:
        - port: Port to forward to (defaults to 80)
        """
        domain = payload.get('domain')
        service_uid = payload.get('service_uid')
        port = payload.get('port', 80)
        
        if not domain:
            return {"success": False, "message": "Domain name is required"}
        
        if not service_uid:
            return {"success": False, "message": "service_uid is required"}
        
        container_name = f"pulseup-app-{service_uid}-blue"
        
        # Get the service manager
        service_manager = self.get_service_manager()
        if not service_manager:
            return {"success": False, "message": "Service manager not available"}
        
        caddy_service = service_manager.caddy_service
        if not caddy_service:
            return {"success": False, "message": "Caddy service not available"}        
        
        try:
            import docker

            # Make sure container exists
            try:
                container = self.docker_client.containers.get(container_name)
            except docker.errors.NotFound:
                return {"success": False, "message": f"Container {container_name} not found. Make sure the service is deployed."}
            
            # Ensure container is connected to caddy-net
            success = await caddy_service.ensure_container_in_network(container_name, caddy_service.CADDY_NETWORK)
            if not success:
                return {"success": False, "message": f"Failed to connect container {container_name} to the Caddy network"}
            
            # Also make sure the Caddy container itself is connected to the network
            caddy_success = await caddy_service.ensure_container_in_network(caddy_service.CADDY_CONTAINER_NAME, caddy_service.CADDY_NETWORK)
            if not caddy_success:
                return {"success": False, "message": "Failed to connect Caddy container to the Caddy network"}
            
            # Check if containers can communicate with each other
            try:
                caddy_container = self.docker_client.containers.get(caddy_service.CADDY_CONTAINER_NAME)
                ping_result = caddy_container.exec_run(f"ping -c 1 {container_name}")
                if ping_result.exit_code != 0:
                    logger.warning(f"Caddy container cannot ping {container_name}: {ping_result.output.decode('utf-8', errors='ignore')}")
                    # Try to inspect the Docker network to see if DNS resolution is working
                    network = self.docker_client.networks.get(caddy_service.CADDY_NETWORK)
                    network_info = network.attrs
                    logger.info(f"Network info for caddy-net: {json.dumps(network_info, indent=2)}")
            except Exception as e:
                logger.warning(f"Error checking container connectivity: {str(e)}")
            
            # Add domain to Caddy
            success = await caddy_service.add_site(
                domain=domain,
                target=container_name,
                ssl=True,
                port=port
            )
            
            if success:
                return {
                    "success": True,
                    "message": f"Domain {domain} successfully added to service {service_uid}",
                    "domain": domain,
                    "container": container_name
                }
            else:
                return {"success": False, "message": "Failed to add domain to Caddy configuration"}
            
        except Exception as e:
            logger.error(f"Error adding domain {domain} to service {service_uid}: {str(e)}")
            return {"success": False, "message": f"Error adding domain: {str(e)}"}

    async def _handle_remove_domain(self, payload: dict) -> dict:
        """
        Remove a domain from a service.
        
        Required payload fields:
        - domain: Domain name to remove
        """
        domain = payload.get('domain')
        
        if not domain:
            return {"success": False, "message": "Domain name is required"}
        
        # Get the service manager
        service_manager = self.get_service_manager()
        if not service_manager:
            return {"success": False, "message": "Service manager not available"}
        
        caddy_service = service_manager.caddy_service
        if not caddy_service:
            return {"success": False, "message": "Caddy service not available"}
        
        try:
            # Remove domain from Caddy
            success = await caddy_service.remove_site(domain)
            
            if success:
                return {
                    "success": True,
                    "message": f"Domain {domain} successfully removed",
                    "domain": domain
                }
            else:
                return {"success": False, "message": f"Failed to remove domain {domain} from Caddy configuration"}
            
        except Exception as e:
            logger.error(f"Error removing domain {domain}: {str(e)}")
            return {"success": False, "message": f"Error removing domain: {str(e)}"}