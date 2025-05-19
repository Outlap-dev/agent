import asyncio
import logging
import os
import aiohttp
from typing import Optional, TYPE_CHECKING
from src.config.agent_version import AGENT_VERSION, is_newer_version

if TYPE_CHECKING:
    from src.websocket.socket_manager import SocketManager

logger = logging.getLogger(__name__)

# Check interval (seconds)
CHECK_INTERVAL_SEC = 300  # 5 minutes

# GitHub repository details
GITHUB_REPO = "PulseUp-IO/pulseup-agent"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/tags"

# Update flag file path
UPDATE_FLAG_FILE = "/var/run/pulseup-agent/update-needed"

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

    async def _get_latest_version(self) -> Optional[str]:
        """Get the latest version from GitHub tags."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(GITHUB_API_URL) as response:
                    if response.status != 200:
                        logger.error(f"Failed to fetch GitHub tags: {response.status}")
                        return None
                    
                    tags = await response.json()
                    if not tags:
                        logger.warning("No tags found in GitHub repository")
                        return None
                    
                    # Get the latest tag (first in the list)
                    latest_tag = tags[0]['name']
                    # Remove 'v' prefix if present
                    return latest_tag.lstrip('v')
                    
        except Exception as e:
            logger.error(f"Error fetching latest version: {e}", exc_info=True)
            return None

    async def _request_update(self) -> bool:
        """Request an update by creating the update flag file."""
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(UPDATE_FLAG_FILE), exist_ok=True)
            
            # Create the update flag file
            with open(UPDATE_FLAG_FILE, 'w') as f:
                f.write('')  # Empty file is sufficient as a flag
            
            logger.info("Update requested via flag file")
            return True
            
        except Exception as e:
            logger.error(f"Error requesting update: {e}", exc_info=True)
            return False

    async def _check_task(self):
        """Background task to periodically check for new versions."""
        while not self._stop_event.is_set():
            try:
                # Get latest version from GitHub
                latest_version = await self._get_latest_version()
                if not latest_version:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=CHECK_INTERVAL_SEC)
                    continue

                # Compare versions
                if is_newer_version(AGENT_VERSION, latest_version):
                    logger.info(f"New version available: {latest_version}")
                    
                    # Request update via flag file
                    logger.info("Requesting agent update...")
                    if await self._request_update():
                        # Stop the service after requesting update
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