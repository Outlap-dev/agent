"""Configuration for agent versioning."""

# Current version of the agent
AGENT_VERSION = "0.1.4"

def parse_version(version_str: str) -> tuple:
    """Parse a version string into a tuple of integers."""
    try:
        return tuple(map(int, version_str.split('.')))
    except (ValueError, AttributeError):
        return (0, 0, 0)  # Return lowest version for invalid strings

def is_newer_version(current: str, latest: str) -> bool:
    """Check if latest version is newer than current version."""
    current_parts = parse_version(current)
    latest_parts = parse_version(latest)
    return latest_parts > current_parts 