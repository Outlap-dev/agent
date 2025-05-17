import asyncio
import logging
from typing import Dict, Any, Optional, TYPE_CHECKING
import docker
import threading
import concurrent.futures
from docker.errors import APIError
import datetime

from src.handlers.base_handler import CommandHandler
from src.services.service_manager import ServiceManager
# Use TYPE_CHECKING to avoid circular import at runtime
if TYPE_CHECKING:
    from src.websocket.socket_manager import SocketManager

logger = logging.getLogger(__name__)

# Event names for sending log data and errors
LOG_EVENT = 'container_log_chunk'
LOG_ERROR_EVENT = 'container_log_error'

class StreamContainerLogsHandler(CommandHandler):
    """Handles streaming Docker container logs over WebSocket to the server."""

    def __init__(self):
        """
        Initialize the handler
        """
        # Get service_manager from base class
        service_manager = self.get_service_manager()
        self.service_manager = service_manager
        self.docker_service = service_manager.docker_service
        self.socket_manager = service_manager.socket_manager

        # Store active streaming tasks: {service_uid: asyncio.Task}
        self._streaming_tasks: Dict[str, asyncio.Task] = {}

    def get_command_name(self) -> str:
        return "stream_container_logs"

    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initiates log streaming for a service container to the server.

        Args:
            data: Dictionary containing command parameters:
                - service_uid: ID of the service whose container logs are needed.
                - from_timestamp: Optional ISO timestamp to fetch logs from. Format example: 2025-04-22T00:06:59.902572175Z
        Returns:
            Dictionary indicating success or failure of initiating the stream.
        """
        if not self.service_manager:
            return {'success': False, 'error': 'Service manager not available'}
            
        service_uid = data.get('service_uid')
        last_timestamp = data.get('last_timestamp')  # Get the from_timestamp parameter

        if not service_uid:
            return {'success': False, 'error': 'Missing required parameter: service_uid'}

        # If there's an existing stream, cancel it before starting a new one
        if service_uid in self._streaming_tasks and not self._streaming_tasks[service_uid].done():
            logger.info(f"Cancelling existing log stream for service {service_uid} before starting new one")
            await self.cancel_streaming_for_service(service_uid)
            # Small delay to ensure cleanup is complete
            await asyncio.sleep(0.1)

        logger.info(f"Initiating log stream for service {service_uid} to server")

        # Create and start the background task for streaming
        streaming_task = asyncio.create_task(
            self._stream_logs(service_uid, last_timestamp),  # Pass from_timestamp
            name=f"log_stream_{service_uid}"
        )
        self._streaming_tasks[service_uid] = streaming_task

        # Add a callback to remove the task from the dict when it's done
        # Use service_uid in the callback closure
        streaming_task.add_done_callback(
            lambda t, suid=service_uid: self._task_done_callback(suid, t)
        )

        return {'success': True, 'message': f'Log streaming started for service {service_uid}'}

    def _task_done_callback(self, service_uid: str, task: asyncio.Task):
        """Callback executed when a streaming task finishes or is cancelled."""
        task_name = task.get_name()
        logger.debug(f"Callback executing for task '{task_name}' (service: {service_uid}). Removing task from dict.")
        self._streaming_tasks.pop(service_uid, None)

        # Get state immediately
        is_cancelled = False
        final_exception = None
        try:
            # This check must come first, as accessing task.exception() can implicitly
            # clear the CancelledError state in some edge cases if it wasn't externally cancelled.
            is_cancelled = task.cancelled()
            if not is_cancelled:
                # Only get exception if not marked as cancelled
                final_exception = task.exception()
        except asyncio.CancelledError:
            # If cancelled() or exception() itself raises CancelledError, treat it as cancelled
            is_cancelled = True
            logger.warning(f"Getting state for task '{task_name}' raised CancelledError.")
        except Exception as e:
            logger.error(f"Unexpected error getting state from task '{task_name}': {e}", exc_info=True)
            final_exception = e # Store the error from trying to get the state

        # Log the results clearly
        logger.debug(f"Task '{task_name}' final state check: cancelled={is_cancelled}, exception={final_exception!r}")

        if final_exception:
            # Check again if the exception is CancelledError
            if isinstance(final_exception, asyncio.CancelledError):
                 logger.warning(f"FINAL_STATE: Log streaming task '{task_name}' for {service_uid} finished due to an internal CancelledError (exception={final_exception!r}), but task.cancelled() was False.")
            else:
                 logger.error(f"FINAL_STATE: Log streaming task '{task_name}' for {service_uid} ended with exception: {final_exception!r}", exc_info=final_exception)
        else:
            # Finished normally
            logger.info(f"FINAL_STATE: Log streaming task '{task_name}' for {service_uid} finished normally.")

    async def _stream_logs(self, service_uid: str, from_timestamp: Optional[str] = None):
        container: Optional[docker.models.containers.Container] = None
        log_stream = None
        reader_thread: Optional[threading.Thread] = None
        stop_event = threading.Event()
        log_queue = asyncio.Queue(maxsize=100)
        loop = asyncio.get_running_loop()

        try:
            logger.info(f"Task started: Streaming logs for service {service_uid} to server")
            container = await self.docker_service.get_container_by_service_uid(service_uid)
            if not container:
                 raise ValueError(f"Container for service {service_uid} not found.")

            # Send existing logs (optional but good practice)
            try:
                # Get recent logs
                existing_logs = await asyncio.to_thread(
                    container.logs, stream=False, tail=100, stdout=True, stderr=True, timestamps=True
                )
                
                if existing_logs:
                    logs_to_send = existing_logs
                    
                    # Filter logs by timestamp if requested
                    if from_timestamp:
                        try:
                            logger.info(f"Filtering logs since timestamp: {from_timestamp}")
                            filtered_logs = self._filter_logs_by_timestamp(existing_logs, from_timestamp)
                            if filtered_logs:
                                logs_to_send = filtered_logs
                                logger.info(f"Sending {len(filtered_logs)} bytes of filtered logs since {from_timestamp}")
                            else:
                                logs_to_send = b"No logs found after the specified timestamp.\n"
                                logger.info(f"No logs found after timestamp {from_timestamp}")
                        except Exception as filter_err:
                            logger.error(f"Error filtering logs by timestamp: {filter_err}")
                            # Fall back to sending all logs if filtering fails
                    
                    # Send the logs
                    await self.service_manager.socket_manager.emit(
                        LOG_EVENT,
                        {'service_uid': service_uid, 'log': logs_to_send.decode('utf-8', errors='replace'), 'existing': True}
                    )
            except APIError as e:
                logger.error(f"APIError getting existing logs for {service_uid}: {e}")

            # Get the log stream - pass from_timestamp parameter if available
            # For streaming, we don't need to filter as Docker will only send new logs
            log_stream = await asyncio.to_thread(
                container.logs, stream=True, follow=True, stdout=True, stderr=True, timestamps=True
            )
            logger.info(f"Attached to log stream for {service_uid}")

            # Start the reader in a thread
            reader_thread = threading.Thread(
                target=self._threaded_log_reader,
                args=(loop, log_stream, log_queue, service_uid, stop_event, from_timestamp),
                name=f"log_reader_{service_uid}",
                daemon=True
            )
            reader_thread.start()

            # Consume from queue
            while True:
                log_line = await log_queue.get()
                if log_line is None:
                    logger.info(f"Received termination sentinel for {service_uid}.")
                    break

                # Emit log_line via WebSocket
                log_content = log_line.decode('utf-8', errors='replace').strip()
                logger.debug(f"LOG [{service_uid}]: {log_content}") # Add log content
                try:
                    await self.service_manager.socket_manager.emit(
                        LOG_EVENT,
                        {'service_uid': service_uid, 'log': log_content, 'existing': False}
                    )
                except Exception as emit_exc:
                    logger.error(f"Failed to emit log line for {service_uid}: {emit_exc}")
                    break

        except ValueError as e: # Specific error for container not found
             logger.error(f"Error preparing log stream for {service_uid}: {e}")
             await self._send_error(service_uid, str(e))
        except APIError as e: # Docker API errors
             logger.error(f"Docker API error during log streaming setup for {service_uid}: {e}")
             await self._send_error(service_uid, f"Docker API error: {e}")
        except asyncio.CancelledError:
            logger.info(f"Consumer loop for {service_uid} cancelled.")
            # Task cancellation is handled by the done_callback
        except Exception as e:
            # Catch other unexpected errors in the main stream task
            logger.exception(f"Unexpected error in main log streaming task for {service_uid}: {e}")
            await self._send_error(service_uid, f"Unexpected server error: {e}")
        finally:
            stop_event.set()
            if reader_thread:
                reader_thread.join(timeout=5)
                if reader_thread.is_alive():
                    logger.warning(f"Reader thread for {service_uid} did not stop gracefully.")
            
            if log_stream and hasattr(log_stream, 'close'):
                try:
                    log_stream.close()
                except Exception as close_exc:
                     logger.warning(f"Error closing log stream for {service_uid} (may be harmless): {close_exc}")
            # Note: No need to explicitly remove task from _streaming_tasks here,
            # the done_callback handles that.

    def _parse_docker_timestamp(self, timestamp: str) -> datetime.datetime:
        """
        Parse Docker timestamp format which has nanosecond precision to Python datetime.
        Docker format: 2025-04-22T00:06:59.902572175Z (nanoseconds)
        We'll truncate to microseconds (6 digits) as that's what Python datetime supports.
        """
        try:
            # Remove the 'Z' and truncate nanoseconds to microseconds
            ts_parts = timestamp.rstrip('Z').split('.')
            if len(ts_parts) == 2:
                # If we have fractional seconds, truncate to 6 digits (microseconds)
                timestamp = f"{ts_parts[0]}.{ts_parts[1][:6]}Z"
            
            # Now parse with truncated precision
            dt = datetime.datetime.strptime(timestamp.rstrip('Z'), '%Y-%m-%dT%H:%M:%S.%f')
            return dt.replace(tzinfo=datetime.timezone.utc)
        except Exception as e:
            logger.error(f"Error parsing Docker timestamp {timestamp}: {e}")
            raise

    def _filter_logs_by_timestamp(self, logs_bytes: bytes, last_timestamp: str) -> bytes:
        """
        Filter log lines to only include those after the given timestamp.
        Since Docker logs are ordered by timestamp, once we find the first matching log,
        we can include all subsequent logs without checking timestamps.
        
        Args:
            logs_bytes: The raw log bytes with timestamp prefixes
            last_timestamp: ISO format timestamp string (e.g., '2025-04-22T00:06:59.902572175Z')
            
        Returns:
            Filtered log bytes containing only lines after the specified timestamp
        """
        try:
            # Convert the target timestamp string to a datetime object
            target_dt = self._parse_docker_timestamp(last_timestamp)
            
            # Split logs into lines and process each line
            log_lines = logs_bytes.splitlines(True)  # Keep line endings
            filtered_lines = []
            found_first_match = False
            
            for line in log_lines:
                if found_first_match:
                    # Once we find a matching timestamp, all subsequent logs will be newer
                    filtered_lines.append(line)
                    continue
                    
                try:
                    # Docker log format with timestamps has timestamp at the start of each line
                    # Format is typically: 2023-04-22T00:06:59.902572175Z log content...
                    line_str = line.decode('utf-8', errors='replace')
                    timestamp_end = line_str.find(' ')
                    
                    if timestamp_end > 0:
                        line_timestamp = line_str[:timestamp_end]
                        # Convert to datetime for comparison
                        line_dt = self._parse_docker_timestamp(line_timestamp)
                        
                        # Include line if it's at or after the target timestamp
                        if line_dt >= target_dt:
                            filtered_lines.append(line)
                            found_first_match = True  # Set flag to include all subsequent lines
                except Exception as line_err:
                    # If we can't parse a line's timestamp, include it to be safe
                    logger.warning(f"Error parsing timestamp in log line, including it: {line_err}")
                    filtered_lines.append(line)
            
            # Combine filtered lines back into a single bytes object
            return b''.join(filtered_lines) if filtered_lines else b''
            
        except Exception as e:
            logger.error(f"Error filtering logs by timestamp: {e}")
            # Return original logs on error
            return logs_bytes
            
    def _threaded_log_reader(self, loop, stream, queue, service_uid, stop_event: threading.Event, last_timestamp: Optional[str] = None):
        logger.debug(f"Threaded log reader started for {service_uid}")
        processed_lines = 0
        found_first_match = False
        target_dt = None
        
        # Parse the target timestamp once if provided
        if last_timestamp:
            try:
                target_dt = self._parse_docker_timestamp(last_timestamp)
            except Exception as e:
                logger.error(f"Error parsing last_timestamp {last_timestamp}: {e}")
                # If we can't parse the timestamp, we'll include all logs
                last_timestamp = None
        
        try:
            for line in stream:
                if stop_event.is_set():
                    logger.info(f"Stop event set for {service_uid}, terminating threaded reader.")
                    break
                
                if line:
                    # Filter by timestamp if needed and we haven't found a match yet
                    if last_timestamp and not found_first_match and target_dt:
                        try:
                            line_str = line.decode('utf-8', errors='replace')
                            timestamp_end = line_str.find(' ')
                            
                            if timestamp_end > 0:
                                line_timestamp = line_str[:timestamp_end]
                                line_dt = self._parse_docker_timestamp(line_timestamp)
                                
                                # Skip lines before the requested timestamp
                                if line_dt < target_dt:
                                    continue
                                else:
                                    found_first_match = True  # Found first matching timestamp, include all subsequent logs
                        except Exception as line_err:
                            # If we can't parse the timestamp, include the line to be safe
                            logger.warning(f"Error filtering streaming log by timestamp, including it: {line_err}")
                            found_first_match = True  # Stop trying to parse timestamps on error
                    
                    future = asyncio.run_coroutine_threadsafe(queue.put(line), loop)
                    try:
                        future.result(timeout=5)
                        processed_lines += 1
                    except concurrent.futures.TimeoutError: # Use correct exception type
                        logger.warning(f"Queue put timed out for {service_uid}. Exiting reader thread.")
                        break
                    except Exception as fut_exc:
                        logger.error(f"Error waiting for queue.put future result for {service_uid}: {fut_exc}")
                        break # Exit if putting to queue fails
                else:
                    logger.debug(f"Empty line for {service_uid}, stopping reader.")
                    break
        except Exception as e:
            # Catch errors during stream iteration (e.g., stream closed unexpectedly)
            if isinstance(e, (ValueError, OSError)) and 'I/O operation on closed file' in str(e):
                 logger.debug(f"Log stream closed for {service_uid} while reading (processed {processed_lines} lines).")
            else:
                 logger.error(f"Error iterating Docker log stream for {service_uid}: {e}", exc_info=True)
        finally:
            # Ensure a sentinel None is placed to signal the end.
            try:
                future = asyncio.run_coroutine_threadsafe(queue.put(None), loop)
                future.result(timeout=1)
            except Exception as final_put_exc:
                 logger.error(f"Failed to put final sentinel on queue for {service_uid}: {final_put_exc}")
            logger.debug(f"Threaded log reader for {service_uid} finished after {processed_lines} lines.")

    async def _send_error(self, service_uid: str, error_message: str):
        """Sends an error message back to the server."""
        try:
             await self.service_manager.socket_manager.emit( # Removed to=sid
                 LOG_ERROR_EVENT,
                 {'service_uid': service_uid, 'error': error_message}
             )
        except Exception as e:
            logger.error(f"Failed to send error message '{error_message}' for {service_uid}: {e}")

    async def cancel_streaming_for_service(self, service_uid: str):
        """Cancels the streaming task for a given service ID."""
        if service_uid in self._streaming_tasks:
            task = self._streaming_tasks[service_uid]
            if not task.done():
                logger.info(f"Requesting cancellation of log streaming task for service {service_uid}")
                task.cancel()
                # The done_callback will handle removing the task from the dict
            else:
                 # Task already done, ensure it's removed
                 self._streaming_tasks.pop(service_uid, None)
                 logger.debug(f"Log streaming task for service {service_uid} was already done.")
        else:
             logger.debug(f"No active log streaming task found for service {service_uid} to cancel.") 