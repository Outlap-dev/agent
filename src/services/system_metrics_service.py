import asyncio
import time
import psutil
import logging
import collections
import math

logger = logging.getLogger(__name__)

# Collection interval (seconds)
COLLECTION_INTERVAL_SEC = 5
# Sending interval (seconds)
SEND_INTERVAL_SEC = 60

class SystemMetricsService:
    """Collects and sends system metrics periodically."""

    def __init__(self):
        self.socket_manager = None
        # Use a deque for efficient appends
        self.metrics_buffer = collections.deque()
        self._collect_task_handle = None
        self._send_task_handle = None
        self._stop_event = asyncio.Event()
        # Initialize last net counters and time for delta calculation
        try:
            self._last_net_io = psutil.net_io_counters()
        except Exception as e:
            logger.warning(f"Could not get initial net_io_counters: {e}. Network metrics might be inaccurate initially.")
            # Use dummy zero counters if unavailable
            self._last_net_io = psutil._common.snetio(bytes_sent=0, bytes_recv=0, packets_sent=0, packets_recv=0, errin=0, errout=0, dropin=0, dropout=0)
        self._last_collection_time = time.monotonic() # Use monotonic clock for intervals


    def set_socket_manager(self, socket_manager):
        """Sets the SocketManager instance used for sending data."""
        self.socket_manager = socket_manager

    async def start(self):
        """Starts the background collection and sending tasks."""
        if not self.socket_manager:
            logger.error("SocketManager not set. Cannot start SystemMetricsService.")
            return

        self._stop_event.clear()
        # Start tasks
        self._collect_task_handle = asyncio.create_task(self._collect_task())
        self._send_task_handle = asyncio.create_task(self._send_task())

    async def stop(self):
        """Stops the background tasks gracefully."""
        self._stop_event.set()
        tasks_to_cancel = [self._collect_task_handle, self._send_task_handle]
        # Cancel tasks
        for task in tasks_to_cancel:
            if task and not task.done():
                task.cancel()
        # Wait for tasks to finish cancellation
        await asyncio.gather(*[t for t in tasks_to_cancel if t], return_exceptions=True)


    def _get_metrics(self) -> dict | None:
        """Collects CPU, memory, disk, and network metrics."""
        try:
            current_time = time.time() # Wall clock time for timestamp 't'
            current_monotonic_time = time.monotonic()
            time_delta = current_monotonic_time - self._last_collection_time
            # Prevent division by zero or negative time delta if clock changes
            time_delta = max(time_delta, 0.1) 

            # CPU (non-blocking)
            cpu_percent = psutil.cpu_percent(interval=None)

            # Memory
            mem = psutil.virtual_memory()
            mem_percent = mem.percent

            # Disk (root partition)
            try:
                disk = psutil.disk_usage('/')
                disk_percent = disk.percent
            except FileNotFoundError:
                 logger.warning("Root partition '/' not found for disk usage metrics.")
                 disk_percent = 0.0 # Report 0 if root partition isn't found

            # Network I/O
            try:
                current_net_io = psutil.net_io_counters()
                bytes_sent_delta = current_net_io.bytes_sent - self._last_net_io.bytes_sent
                bytes_recv_delta = current_net_io.bytes_recv - self._last_net_io.bytes_recv

                 # Handle counter wrap-around (rare, but possible)
                if bytes_sent_delta < 0: bytes_sent_delta = current_net_io.bytes_sent
                if bytes_recv_delta < 0: bytes_recv_delta = current_net_io.bytes_recv

                # Normalize to bytes per second (ensure non-negative)
                net_out_bps = max(0, bytes_sent_delta / time_delta)
                net_in_bps = max(0, bytes_recv_delta / time_delta)

                # Update last values for next delta calculation
                self._last_net_io = current_net_io
                
            except Exception as e:
                logger.warning(f"Could not calculate network metrics: {e}. Reporting 0.")
                net_in_bps = 0
                net_out_bps = 0
                # Attempt to refresh counters on error to potentially recover
                try:
                     self._last_net_io = psutil.net_io_counters()
                except Exception:
                     pass # Keep old dummy counters if refresh fails too

            self._last_collection_time = current_monotonic_time

            return {
                "t": int(current_time), # Unix timestamp integer
                "cpu": round(cpu_percent, 1),
                "mem": round(mem_percent, 1),
                "disk": round(disk_percent, 1),
                # Use math.ceil to avoid reporting 0 for small but non-zero values
                "in": math.ceil(net_in_bps),
                "out": math.ceil(net_out_bps)
            }
        except Exception as e:
            logger.exception(f"Unexpected error collecting system metrics: {e}")
            # Attempt to re-initialize last_net_io on unexpected errors
            try:
                self._last_net_io = psutil.net_io_counters()
            except Exception:
                 pass # Keep old dummy counters if refresh fails too
            self._last_collection_time = time.monotonic()
            return None

    async def _collect_task(self):
        """Background task to periodically collect metrics."""
        while not self._stop_event.is_set():
            start_collection_time = time.monotonic()
            try:
                metrics = self._get_metrics()
                if metrics:
                    self.metrics_buffer.append(metrics)

                # Calculate time spent collecting and adjust sleep time
                collection_duration = time.monotonic() - start_collection_time
                sleep_duration = max(0, COLLECTION_INTERVAL_SEC - collection_duration)

                # Wait for the next interval or stop event
                await asyncio.wait_for(self._stop_event.wait(), timeout=sleep_duration)
            except asyncio.TimeoutError:
                continue # Expected timeout, continue loop
            except asyncio.CancelledError:
                 break
            except Exception as e:
                logger.error(f"Error in metric collection loop: {e}")
                # Avoid tight loop on error, wait full interval
                await asyncio.sleep(COLLECTION_INTERVAL_SEC)

    async def _send_task(self):
        """Background task to periodically send buffered metrics."""
        while not self._stop_event.is_set():
            try:
                # Wait for the send interval or stop event
                await asyncio.wait_for(self._stop_event.wait(), timeout=SEND_INTERVAL_SEC)
            except asyncio.TimeoutError:
                # Time to send
                if not self.metrics_buffer:
                    logger.debug("No metrics in buffer to send.")
                    continue

                if not self.socket_manager:
                     logger.warning("Send task running but SocketManager not available.")
                     continue
                
                if not self.socket_manager.is_connected():
                     logger.warning("Cannot send metrics: SocketManager not connected.")
                     continue

                # Create a copy and clear original buffer immediately
                metrics_to_send = list(self.metrics_buffer)
                self.metrics_buffer.clear()

                payload = {
                    "metrics": metrics_to_send
                }
                try:
                    # Use the socket manager's emit method
                    await self.socket_manager.emit('update_server_stats', payload)
                except Exception as e:
                    logger.error(f"Failed to send metrics via SocketManager: {e}")
            except asyncio.CancelledError:
                break
            except Exception as e:
                 logger.error(f"Error in metric sending loop: {e}")
                 # Add a small sleep to prevent tight loop on unexpected errors
                 await asyncio.sleep(5) 