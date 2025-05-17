import logging
import platform
import psutil
import socket
import requests
import uuid
from typing import Dict, Any
from .base_handler import CommandHandler

logger = logging.getLogger(__name__)

class GetHardwareInfoHandler(CommandHandler):
    """Handles collecting hardware information from the system."""

    def get_command_name(self) -> str:
        return "get_hardware_info"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Collects hardware information from the system.
        
        Returns:
            Dictionary containing hardware information including:
            - hostname
            - public IP
            - OS version
            - CPU count
            - Memory in GB
        """
        try:
            # Get hostname
            hostname = socket.gethostname()

            # Get public IP using a reliable service
            try:
                ip_response = requests.get('https://api.ipify.org?format=json', timeout=5)
                public_ip = ip_response.json()['ip']
            except Exception as e:
                logger.warning(f"Failed to get public IP: {e}")
                public_ip = "Unknown"

            # Get OS information
            os_info = f"{platform.system()} {platform.release()}"
            if platform.system() == "Linux":
                try:
                    import distro
                    os_info = f"{distro.name()} {distro.version()}"
                except ImportError:
                    pass

            # Get CPU count
            cpu_count = psutil.cpu_count()
            cpu_physical_cores = psutil.cpu_count(logical=False) # Get physical cores
            cpu_logical_count = psutil.cpu_count(logical=True) # Get logical processors (includes hyperthreading)

            # Get memory in GB
            memory_gb = round(psutil.virtual_memory().total / (1024**3), 2)
            # Get total storage for the root partition in GB
            try:
                storage_total_gb = round(psutil.disk_usage('/').total / (1024**3), 2)
            except Exception as e:
                logger.warning(f"Failed to get root partition storage: {e}")
                storage_total_gb = "Unknown"

            return {
                "success": True,
                "hardware_info": {
                    "hostname": hostname,
                    "public_ip": public_ip,
                    "os_info": os_info,
                    "cpu_count": cpu_count, # Deprecated, use specific counts below
                    "cpu_physical_cores": cpu_physical_cores,
                    "cpu_logical_count": cpu_logical_count,
                    "total_memory_gb": memory_gb,
                    "storage_total_gb": storage_total_gb,
                }
            }

        except Exception as e:
            logger.error(f"Error collecting hardware information: {e}")
            return {
                "success": False,
                "error": f"Failed to collect hardware information: {str(e)}"
            } 