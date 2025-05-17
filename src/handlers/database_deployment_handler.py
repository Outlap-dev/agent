from typing import Dict, Any

from .base_handler import CommandHandler as BaseHandler
from src.services.database_service import DatabaseService
from src.services.service_registry import ServiceRegistry
from src.services.service_status import ServiceStatus

class DatabaseDeploymentHandler(BaseHandler):
    def __init__(self):
        super().__init__()
        self.database_service = self.get_service_manager().database_service
        self.services = ServiceRegistry()

    def get_command_name(self) -> str:
        """Get the command name for this handler."""
        return "deploy_database"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle database deployment request
        
        Expected data format:
        {
            "service_uid": "svc_1234567890",
            "type": "mysql",  # Database type (currently only mysql supported)
            "password": "secure-password",  # Password for root and default user
            "port": 3306,  # Optional: Port to expose (will find available port if not specified)
            "username": "admin",  # Optional: Default user to create (defaults to "admin")
            "database": "default"  # Optional: Default database to create (defaults to "default")
        }
        """
        # Validate required fields
        required_fields = ["type", "service_uid", "password"]
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")

        # Extract optional parameters with defaults
        port = data.get("port")
        username = data.get("username", "admin")
        database = data.get("database", "default")

        # Generate container name from service_uid
        container_name = data["service_uid"]

        try:
            # Deploy the database
            result = self.database_service.deploy_database(
                db_type=data["type"],
                password=data["password"],
                name=container_name,
                port=port,
                username=username,
                database=database
            )
        except Exception as e:
            # Update the status of the database service to failed
            await self.services.status_service.update_service_status(
                service_uid=data["service_uid"],
                status=ServiceStatus.FAILED,
                error_message=str(e)
            )

            return {
                "status": "error",
                "message": f"Error deploying database: {str(e)}"
            }
        
        # Update the status of the database service to successful
        await self.services.status_service.update_service_status(
            service_uid=data["service_uid"],
            status=ServiceStatus.RUNNING,
        )

        return {
            "status": "success",
            "message": f"Database {container_name} deployed successfully",
            "details": result
        }

    async def validate(self, data: Dict[str, Any]) -> None:
        """
        Validate the incoming request data
        """
        if "type" in data and data["type"].lower() != "mysql":
            raise ValueError("Currently only MySQL database type is supported")

        if "port" in data:
            if not isinstance(data["port"], int):
                raise ValueError("Port must be an integer")
            if data["port"] < 1 or data["port"] > 65535:
                raise ValueError("Port must be between 1 and 65535") 