from typing import List

class ServiceStatus:
    """Defines possible service statuses"""
    RUNNING = 'running'
    STOPPED = 'stopped'
    DEPLOYING = 'deploying'
    FAILED = 'failed'
    PENDING = 'pending'
    READY = 'ready'
    STOPPING = 'stopping'

    @classmethod
    def get_choices(cls) -> List[str]:
        """Get all possible status values"""
        return [
            cls.RUNNING,
            cls.STOPPED,
            cls.DEPLOYING,
            cls.FAILED,
            cls.PENDING,
            cls.READY,
            cls.STOPPING
        ]
    
    @classmethod
    def get_completed_statuses(cls) -> List[str]:
        """Get statuses that represent a completed state"""
        return [
            cls.STOPPED,
            cls.FAILED,
            cls.READY,
            cls.RUNNING
        ]
    
    @classmethod
    def from_docker_status(cls, docker_status: str) -> str:
        """Convert a Docker container status to a service status"""
        status_map = {
            'running': cls.RUNNING,
            'exited': cls.STOPPED,
            'dead': cls.FAILED,
            'created': cls.PENDING,
            'restarting': cls.DEPLOYING,
            'removing': cls.STOPPING,
            'paused': cls.STOPPED
        }
        return status_map.get(docker_status.lower(), cls.FAILED) 