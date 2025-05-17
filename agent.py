import asyncio
import logging
from typing import Optional

from src.services.service_container import ServiceContainer
from src.installations.installation_orchestrator import InstallationOrchestrator
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
        self.installation_orchestrator: Optional[InstallationOrchestrator] = None
        
    async def setup(self) -> bool:
        """Initialize the agent and all required services"""
        try:
            # Initialize service container
            if not await self.container.initialize():
                logger.error("Failed to initialize service container")
                return False
            
            # Initialize installation orchestrator
            self.installation_orchestrator = InstallationOrchestrator(
                self.container.installation_manager
            )
            
            # Initialize setup service
            if not await self.container.setup_service.initialize():
                logger.error("Failed to initialize setup service")
                return False
            
            return True
            
        except Exception as e:
            log_exception(logger, "Error during agent setup", e)
            return False
    
    async def install_dependencies(self) -> bool:
        """Install all required system dependencies"""
        try:
            if not self.installation_orchestrator:
                logger.error("Installation orchestrator not initialized")
                return False
                
            installed_tools = await self.installation_orchestrator.install_required_tools()
            logger.info(f"Successfully installed tools: {', '.join(installed_tools)}")
            
            return True
            
        except Exception as e:
            log_exception(logger, "Error installing dependencies", e)
            return False
    
    async def initialize_services(self) -> bool:
        """Initialize all required services"""
        try:
            service_manager = self.container.service_manager
            if not service_manager:
                logger.error("Service manager not initialized")
                return False
            
            # Initialize services that require it
            init_tasks = [
                service_manager.github_clone_service.initialize()
            ]
            await asyncio.gather(*init_tasks)
            
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
            
            # Install dependencies
            if not await self.install_dependencies():
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