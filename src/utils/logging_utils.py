import logging
from typing import Optional, Any

def get_logger(module_name: str) -> logging.Logger:
    """
    Get a standardized logger for the specified module.
    
    Args:
        module_name: The name of the module requesting the logger
        
    Returns:
        Configured logger instance
    """
    return logging.getLogger(module_name)

def log_exception(logger: logging.Logger, message: str, exception: Optional[Exception] = None) -> None:
    """
    Log an exception with a consistent format.
    
    Args:
        logger: The logger to use
        message: The error message
        exception: The exception object, if available
    """
    if exception:
        logger.error(f"{message}: {exception}")
        logger.exception(exception)
    else:
        logger.error(message)

def log_function_entry(logger: logging.Logger, function_name: str, **kwargs) -> None:
    """
    Log function entry with parameters for debugging purposes.
    
    Args:
        logger: The logger to use
        function_name: The name of the function being entered
        **kwargs: Function parameters to log
    """
    if logger.isEnabledFor(logging.DEBUG):
        params = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        logger.debug(f"Entering {function_name}({params})")

def log_function_exit(logger: logging.Logger, function_name: str, result: Any = None) -> None:
    """
    Log function exit with optional result for debugging purposes.
    
    Args:
        logger: The logger to use
        function_name: The name of the function being exited
        result: Optional function result to log
    """
    if logger.isEnabledFor(logging.DEBUG):
        if result is not None:
            logger.debug(f"Exiting {function_name} with result: {result}")
        else:
            logger.debug(f"Exiting {function_name}") 