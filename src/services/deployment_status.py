import enum

class DeploymentStatus:
    """Defines possible deployment statuses"""
    PENDING = 'pending'
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'

    @classmethod
    def get_choices(cls):
        return [
            cls.PENDING,
            cls.IN_PROGRESS,
            cls.COMPLETED,
            cls.FAILED,
            cls.CANCELLED
        ]
    
    @classmethod
    def get_completed_statuses(cls):
        return [
            cls.COMPLETED,
            cls.FAILED,
            cls.CANCELLED
        ]