import asyncio
import logging
import os
from typing import Optional, TYPE_CHECKING
from src.config.agent_version import AGENT_VERSION

if TYPE_CHECKING:
    from src.websocket.socket_manager import SocketManager

logger = logging.getLogger(__name__)

# Check interval (seconds)
CHECK_INTERVAL_SEC = 300  # 5 minutes

class VersionCheckService:
    """Service for periodically checking for new versions."""

    def __init__(self):
        self.socket_manager: Optional['SocketManager'] = None
        self._check_task_handle: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._running = False

    def set_socket_manager(self, socket_manager: 'SocketManager'):
        """Sets the SocketManager instance used for checking versions."""
        self.socket_manager = socket_manager

    async def start(self):
        """Starts the background version check task."""
        if self._running:
            logger.debug("Version check service already running")
            return

        if not self.socket_manager:
            logger.error("SocketManager not set. Cannot start VersionCheckService.")
            return

        self._stop_event.clear()
        self._running = True
        self._check_task_handle = asyncio.create_task(
            self._check_task(),
            name="version_check_task"
        )
        logger.info("Version check service started")

    async def stop(self):
        """Stops the background task gracefully."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()
        if self._check_task_handle and not self._check_task_handle.done():
            self._check_task_handle.cancel()
            try:
                await self._check_task_handle
            except asyncio.CancelledError:
                pass
            self._check_task_handle = None
        logger.info("Version check service stopped")

    async def _perform_update(self, install_url: str, install_token: str) -> bool:
        """Perform the agent update using the install script."""
        try:
            # Construct the update command
            update_cmd = f'curl -sSL {install_url} | bash -s -- --token {install_token}'
            
            # Execute the update command
            process = await asyncio.create_subprocess_shell(
                update_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Update failed with return code {process.returncode}")
                logger.error(f"Update error output: {stderr.decode()}")
                return False
            
            logger.info("Update completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during update: {e}", exc_info=True)
            return False

    async def _check_task(self):
        """Background task to periodically check for new versions."""
        while not self._stop_event.is_set():
            try:
                if not self.socket_manager:
                    logger.warning("Cannot check version: SocketManager not connected")
                    await asyncio.wait_for(self._stop_event.wait(), timeout=CHECK_INTERVAL_SEC)
                    continue

                # Call the check_version endpoint with current version
                result = await self.socket_manager.sio.call(
                    'check_version',
                    {'version': AGENT_VERSION},
                    namespace=self.socket_manager.namespace,
                    timeout=30
                )

                # Process the response
                if not result or not isinstance(result, dict):
                    continue

                # If the version check fails, continue
                if not result.get('success'):
                    logger.warning(f"Version check failed: {result.get('error')}")
                    continue

                # If no update is available, continue
                if not result.get('update_available'):
                    continue

                # If an update is available, perform the update
                latest_version = result.get('latest_version')
                logger.info(f"New version available: {latest_version}")
                
                # Get install URL from environment
                install_url = os.getenv('INSTALL_URL')
                install_token = os.getenv('AGENT_TOKEN')
                
                if not install_url or not install_token:
                    logger.error("INSTALL_URL or AGENT_TOKEN not configured")
                    continue

                logger.info("Starting agent update...")
                if await self._perform_update(install_url, install_token):
                    # Stop the service after successful update
                    await self.stop()
                    return

                # Wait for the next interval or stop event
                await asyncio.wait_for(self._stop_event.wait(), timeout=CHECK_INTERVAL_SEC)

            except asyncio.TimeoutError:
                continue  # Expected timeout, continue loop
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in version check loop: {e}", exc_info=True)
                # Wait before retrying on error
                await asyncio.sleep(CHECK_INTERVAL_SEC) 