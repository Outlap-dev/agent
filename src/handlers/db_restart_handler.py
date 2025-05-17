import asyncio
import logging
from typing import Dict, Any
from .base_handler import CommandHandler

logger = logging.getLogger(__name__)

class DBRestartHandler(CommandHandler):
    def get_command_name(self) -> str:
        return "restart_database"
    
    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle database restart command
        
        Expected data format:
        {
            "database_type": "mysql",  # The type of database to restart (mysql/postgresql)
            "timeout": 30              # Optional timeout in seconds for restart operation
        }
        """
        try:
            print("--------------------------------")
            logger.info("Starting database restart process")
            print("Starting database restart process")
            print("--------------------------------")

            # Validate input
            db_type = data.get("database_type", "mysql").lower()
            timeout = data.get("timeout", 30)
            
            if db_type not in ["mysql", "postgresql"]:
                raise ValueError("Unsupported database type. Must be either 'mysql' or 'postgresql'")            

            stop_cmd = "sudo systemctl stop " + db_type
            start_cmd = "sudo systemctl start " + db_type
            status_cmd = "sudo systemctl status " + db_type
            
            # Stop the database
            logger.info("Stopping database service...")
            process = await asyncio.create_subprocess_shell(
                stop_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if process.returncode != 0:
                raise Exception("Failed to stop database service")
            
            # Small delay to ensure clean shutdown
            await asyncio.sleep(2)
            
            # Start the database
            logger.info("Starting database service...")
            process = await asyncio.create_subprocess_shell(
                start_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.communicate()
            
            if process.returncode != 0:
                raise Exception("Failed to start database service")
            
            # Check status
            logger.info("Checking database service status...")
            process = await asyncio.create_subprocess_shell(
                status_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception("Database service failed to start properly")
            
            result = {
                "success": True,
                "message": f"{db_type.upper()} database restarted successfully",
                "status": stdout.decode()
            }
            logger.info(f"Database restart successful: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error restarting database: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            } 