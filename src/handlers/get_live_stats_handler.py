from .base_handler import CommandHandler
from typing import Dict, Any
import psutil  # Example: Using psutil to get stats

class GetLiveStatsHandler(CommandHandler):
    """Handles the 'get_live_stats' command"""

    def get_command_name(self) -> str:
        return "get_live_stats"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetches live system statistics.

        Args:
            data: Dictionary containing command parameters (currently unused)

        Returns:
            Dictionary containing live system stats (CPU, memory, disk)
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1) 
            memory_info = psutil.virtual_memory()
            disk_usage = psutil.disk_usage('/') # Root disk usage

            return {
                "success": True,
                "stats": {
                    "cpu_percent": cpu_percent,
                    "memory_used_gb": round(memory_info.used / (1024**3), 2),
                    "disk_used_gb": round(disk_usage.used / (1024**3), 2),
                }
            }
        except Exception as e:
            # Consider more specific error handling
            return {
                "success": False,
                "error": f"Failed to get live stats: {str(e)}"
            } 