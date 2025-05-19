import asyncio
import logging

from src.services.service_container import ServiceContainer
from src.utils.logging_utils import get_logger, log_exception

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
# Set higher level for noisy libraries
logging.getLogger("socketio").setLevel(logging.WARNING)
logging.getLogger("engineio").setLevel(logging.WARNING)

logger = get_logger(__name__)

class PulseUpAgent:
    def __init__(self):
        self.container = ServiceContainer()
        
    async def setup(self) -> bool:
        """Initialize the agent and all required services"""
        try:
            # Initialize service container
            if not await self.container.initialize():
                logger.error("Failed to initialize service container")
                return False            
            
            # Initialize setup service
            if not await self.container.setup_service.initialize():
                logger.error("Failed to initialize setup service")
                return False
            
            return True
            
        except Exception as e:
            log_exception(logger, "Error during agent setup", e)
            return False    
    
    async def initialize_services(self) -> bool:
        """Initialize all required services"""
        try:
            service_manager = self.container.service_manager
            if not service_manager:
                logger.error("Service manager not initialized")
                return False            
            
            # Set up metrics service
            service_manager.system_metrics_service.set_socket_manager(
                service_manager.socket_manager
            )

            # Set up version check service
            service_manager.version_check_service.set_socket_manager(
                service_manager.socket_manager
            )
            
            return True
            
        except Exception as e:
            log_exception(logger, "Error initializing services", e)
            return False
    
    async def run(self):
        """Main agent runtime loop"""
        try:
            # Setup agent
            if not await self.setup():
                return
            
            # Initialize services
            if not await self.initialize_services():
                return
            
            service_manager = self.container.service_manager
            if not service_manager:
                return
            
            # Start services
            connect_task = asyncio.create_task(service_manager.connect())
            # -- Metrics coming soon
            # metrics_task = asyncio.create_task(service_manager.system_metrics_service.start())
            # Start version check service
            version_check_task = asyncio.create_task(service_manager.version_check_service.start())
            
            # Wait for the connection task to complete
            await connect_task
            
        except Exception as e:
            log_exception(logger, "Critical error in agent runtime", e)
            raise

async def main():
    agent = PulseUpAgent()
    await agent.run()

if __name__ == "__main__":
    asyncio.run(main())