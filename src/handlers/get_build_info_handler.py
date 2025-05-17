import logging
from typing import Dict, Any
from src.handlers.base_handler import CommandHandler
from src.services.service_manager import ServiceManager

logger = logging.getLogger(__name__)

class GetBuildInfoHandler(CommandHandler):
    """Handles requests to get build information for a service"""
    
    def __init__(self):
        """
        Initialize the handler
        """
        # Get service_manager from base class
        service_manager = self.get_service_manager()
        if not service_manager:
            logger.error("No service manager available for GetBuildInfoHandler")
            self.service_manager = None
            self.build_service = None
        else:
            self.service_manager = service_manager
            self.build_service = service_manager.build_service
    
    def get_command_name(self) -> str:
        return "get_build_info"
    
    async def handle(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle the request to get build information
        
        Args:
            data: Dictionary containing the request parameters
                - service_uid: ID of the service to get build info for
        
        Returns:
            Dictionary containing the build information
        """
        if not self.service_manager:
            return {'success': False, 'error': 'Service manager not available'}
            
        try:
            service_uid = data.get('service_uid')
            if not service_uid:
                return {
                    'success': False,
                    'error': 'Missing service_uid parameter'
                }
            
            build_info = self.build_service.get_build_command_info(service_uid)
            if not build_info:
                return {
                    'success': False,
                    'error': f'No build information found for service {service_uid}'
                }
            
            # Return a successful response with the build info
            result = {
                'success': True,
                'build_info': build_info
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting build info: {str(e)}")
            return {
                'success': False,
                'error': f'Error getting build info: {str(e)}'
            } 