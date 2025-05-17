import logging
import json
from typing import Dict, Any, Optional
import socketio

logger = logging.getLogger(__name__)

class EnvironmentService:
    """Service for handling environment variable operations"""
    
    def __init__(self, socket_manager=None):
        """
        Initialize the environment service.
        
        Args:
            socket_manager: Socket manager instance for server communication
        """
        self._socket_manager = socket_manager
        
    @property
    def socket_manager(self):
        return self._socket_manager
        
    @socket_manager.setter
    def socket_manager(self, socket_manager):
        self._socket_manager = socket_manager
        
    async def get_service_env_vars(self, service_uid: str) -> Dict[str, Any]:
        """
        Gets environment variables for a service from the server.
        
        Args:
            service_uid: ID of the service to get environment variables for
            
        Returns:
            Dictionary containing the environment variables or error information
        """
        if not self.socket_manager or not hasattr(self.socket_manager, 'sio'):
            logger.warning(f"No socket manager available to get environment variables for {service_uid}")
            return {'success': False, 'error': "Socket manager not available"}
            
        try:
            result = await self.socket_manager.sio.call(
                'get_service_env_vars',
                {'service_uid': service_uid},
                namespace=self.socket_manager.namespace,
                timeout=30
            )
            
            # Simplified error check: Allow empty dict, only check for explicit error
            if isinstance(result, dict) and 'error' in result:
                error_msg = result.get('error')
                logger.error(f"Error getting env vars for service {service_uid}: {error_msg}")
                # Return error structure consistent with failure
                return {'success': False, 'error': error_msg}
                
            # Process the environment variables
            env_vars = {}
            
            # Handle string format (JSON)
            if isinstance(result, str):
                try:
                    result = json.loads(result)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse environment variables string for service {service_uid}: {result}")
                    return {'success': False, 'error': 'Invalid environment variables format'}
            
            # Handle dictionary format
            if isinstance(result, dict):
                # Convert detailed format to simple key-value pairs
                for key, value in result.items():
                    if isinstance(value, dict) and 'value' in value:
                        env_vars[key] = value['value']
                    else:
                        env_vars[key] = value
            else:
                logger.warning(f"Unexpected type for environment variables: {type(result)}. Value: {result}")
                env_vars = {}
            
            # Return success with processed environment variables
            return {'success': True, 'env_vars': env_vars}
            
        except socketio.exceptions.TimeoutError:
            error_msg = f"Timeout getting env vars for service {service_uid}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = f"Failed to get env vars: {str(e)}"
            logger.error(f"Error getting env vars for service {service_uid}: {e}")
            return {'success': False, 'error': error_msg} 