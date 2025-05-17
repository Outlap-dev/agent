import logging
from typing import Optional, Dict, Any
import socketio
from src.services.build_service import DeploymentStatus
from src.services.service_status import ServiceStatus

logger = logging.getLogger(__name__)

class StatusService:
    def __init__(self, sio: socketio.AsyncClient, namespace: str):
        self.sio = sio
        self.namespace = namespace
    
    async def update_service_status(self, service_uid: str, status: str, error_message: Optional[str] = None):
        """Update service status."""
        if status not in ServiceStatus.get_choices():
            raise ValueError(f"Invalid service status: {status}")
            
        payload = {
            'service_uid': service_uid,
            'status': status
        }
        if error_message:
            payload['error'] = error_message
            
        try:
            await self.sio.emit(
                'update_service_status', 
                payload,
                namespace=self.namespace
            )
        except Exception as e:
            logger.error(f"Failed to emit status update for service {service_uid}: {e}")
    
    async def update_deployment_status(self, deployment_uid: str, status: str, error_message: Optional[str] = None):
        """Update deployment status."""
        if status not in DeploymentStatus.choices():
            raise ValueError(f"Invalid deployment status: {status}")

        payload = {
            'deployment_uid': deployment_uid,
            'status': status
        }
        if error_message:
            payload['error'] = error_message

        try:
            await self.sio.emit(
                'update_deployment_status', 
                payload,
                namespace=self.namespace
            )
        except Exception as e:
            logger.error(f"Failed to emit status update for deployment {deployment_uid}: {e}")
    
    async def send_pending_installations(self, pending_tools: Dict[str, Any]):
        """Send pending installation information."""
        try:
            await self.sio.emit(
                'pending_installations',
                {'pending_tools': pending_tools},
                namespace=self.namespace
            )
        except Exception as e:
            logger.error(f"Failed to send pending installations: {e}")
    
    async def get_service_env_vars(self, service_uid: str) -> Dict[str, Any]:
        """Get service environment variables."""
        try:
            result = await self.sio.call(
                'get_service_env_vars',
                {'service_uid': service_uid},
                namespace=self.namespace,
                timeout=30
            )
            
            if not result or (isinstance(result, dict) and 'error' in result):
                error_msg = result.get('error') if isinstance(result, dict) else "Invalid response"
                logger.error(f"Error getting env vars for {service_uid}: {error_msg}")
                return {'success': False, 'error': error_msg}
            
            return {'success': True, 'env_vars': result}
            
        except socketio.exceptions.TimeoutError:
            error_msg = f"Timeout getting env vars for service {service_uid}"
            logger.error(error_msg)
            return {'success': False, 'error': error_msg}
        except Exception as e:
            error_msg = f"Failed to get env vars: {str(e)}"
            logger.error(f"Error getting env vars for {service_uid}: {e}")
            return {'success': False, 'error': error_msg} 