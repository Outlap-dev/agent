from typing import TypeVar, Type

T = TypeVar('T')

class Singleton:
    """Base class for implementing the singleton pattern"""
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        # Skip initialization if already initialized
        if getattr(self, '_initialized', False):
            return
        self._initialized = True 