from typing import Dict, Optional
from src.handlers.base_handler import CommandHandler
from src.utils.singleton import Singleton

class CommandRegistry(Singleton):
    def __init__(self):
        super().__init__()
        self._handlers: Dict[str, CommandHandler] = {}
    
    def register_handler(self, handler: CommandHandler) -> None:
        """Register a new command handler"""
        command_name = handler.get_command_name()
        self._handlers[command_name] = handler
    
    def get_handler(self, command_name: str) -> Optional[CommandHandler]:
        """Get a handler for a specific command"""
        handler = self._handlers.get(command_name)
        if not handler:
            raise ValueError(f"No handler registered for command: {command_name}")
        return handler
    
    def get_all_handlers(self) -> Dict[str, CommandHandler]:
        """Get all registered handlers"""
        return self._handlers.copy()
    
    def get_handler_names(self) -> list:
        """Get a list of all registered handler names"""
        return list(self._handlers.keys())
    
    def __str__(self) -> str:
        """String representation of the registry showing registered handlers"""
        if not self._handlers:
            return "CommandRegistry(empty)"
        return f"CommandRegistry({len(self._handlers)} handlers: {', '.join(self._handlers.keys())})" 