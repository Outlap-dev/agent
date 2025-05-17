import os
from typing import Optional, Dict, Any
from docker.errors import APIError

class DatabasePortInUseError(Exception):
    """Raised when attempting to use a port that is already in use"""
    pass

class DatabaseService:
    def __init__(self):
        import docker

        self.client = docker.from_env()
        self.volume_base_path = "/var/lib/pulseup/databases"

    def _get_database_config(self, db_type: str) -> Dict[str, Any]:
        """Get configuration for different database types"""
        configs = {
            "mysql": {
                "image": "mysql:8",
                "internal_port": 3306,
                "volume_path": "/var/lib/mysql",
                "env_prefix": "MYSQL",
                "root_password_var": "MYSQL_ROOT_PASSWORD",
                "default_user_var": "MYSQL_USER",
                "default_password_var": "MYSQL_PASSWORD",
                "default_database_var": "MYSQL_DATABASE"
            },
            "postgresql": {
                "image": "postgres:16",
                "internal_port": 5432,
                "volume_path": "/var/lib/postgresql/data",
                "env_prefix": "POSTGRES",
                "root_password_var": "POSTGRES_PASSWORD",
                "default_user_var": "POSTGRES_USER",
                "default_password_var": "POSTGRES_PASSWORD",
                "default_database_var": "POSTGRES_DB"
            },
            "mariadb": {
                "image": "mariadb:11.2",
                "internal_port": 3306,
                "volume_path": "/var/lib/mysql",
                "env_prefix": "MARIADB",
                "root_password_var": "MARIADB_ROOT_PASSWORD",
                "default_user_var": "MARIADB_USER",
                "default_password_var": "MARIADB_PASSWORD",
                "default_database_var": "MARIADB_DATABASE"
            }
            # Add more database types here in the future
        }
        return configs.get(db_type.lower())

    def _find_available_port(self, start_port: int) -> int:
        """Find the next available port starting from start_port"""
        containers = self.client.containers.list(all=True)
        used_ports = set()
        
        for container in containers:
            ports = container.attrs['HostConfig']['PortBindings'] or {}
            for port_bindings in ports.values():
                if port_bindings:
                    for binding in port_bindings:
                        if binding.get('HostPort'):
                            used_ports.add(int(binding['HostPort']))
        
        current_port = start_port
        while current_port in used_ports:
            current_port += 1
        
        return current_port

    def _is_port_in_use_by_container(self, port: int) -> Optional[str]:
        """
        Check if a port is already in use by a Docker container
        
        Args:
            port: The port number to check
            
        Returns:
            Container name if port is in use, None otherwise
        """
        containers = self.client.containers.list(all=True)
        for container in containers:
            ports = container.attrs['HostConfig']['PortBindings'] or {}
            for port_bindings in ports.values():
                if port_bindings:
                    for binding in port_bindings:
                        if binding.get('HostPort') and int(binding['HostPort']) == port:
                            return container.name
        return None

    def deploy_database(
        self,
        db_type: str,
        password: str,
        name: str,
        port: Optional[int] = None,
        username: str = "admin",
        database: str = "default"
    ) -> Dict[str, Any]:
        """
        Deploy a database container
        
        Args:
            db_type: Type of database (e.g., 'mysql')
            password: Root password for the database
            name: Name for the container
            port: Port to expose (optional)
            username: Default user to create
            database: Default database to create
        
        Returns:
            Dict containing deployment information
            
        Raises:
            ValueError: If database type is unsupported
            DatabasePortInUseError: If the specified port is already in use
            RuntimeError: If container creation or startup fails
        """
        config = self._get_database_config(db_type)
        if not config:
            raise ValueError(f"Unsupported database type: {db_type}")

        # Ensure volume directory exists
        volume_path = os.path.join(self.volume_base_path, name)
        os.makedirs(volume_path, exist_ok=True)

        # Find available port if none specified
        if not port:
            port = self._find_available_port(config['internal_port'])
        else:
            # Check if port is already in use
            container_name = self._is_port_in_use_by_container(port)
            if container_name:
                raise DatabasePortInUseError(
                    f"Port {port} is already in use by container '{container_name}'. "
                    "Please choose a different port."
                )

        # Prepare environment variables
        environment = {
            config['root_password_var']: password,
            config['default_user_var']: username,
            config['default_password_var']: password,
            config['default_database_var']: database
        }

        try:
            # Create and start container
            container = self.client.containers.run(
                image=config['image'],
                name=f"pulseup-db-{name}",
                environment=environment,
                volumes={
                    volume_path: {'bind': config['volume_path'], 'mode': 'rw'}
                },
                ports={
                    config['internal_port']: port
                },
                detach=True,
                restart_policy={"Name": "unless-stopped"}
            )
        except APIError as e:
            # Handle specific Docker API errors
            if "port is already allocated" in str(e):
                raise DatabasePortInUseError(
                    f"Port {port} is already in use by another process. "
                    "Please choose a different port."
                ) from e
            elif "Conflict" in str(e):
                raise RuntimeError(
                    f"A container named 'pulseup-db-{name}' already exists. "
                    "Please choose a different name or remove the existing container first."
                ) from e
            else:
                raise RuntimeError(f"Failed to create database container: {str(e)}") from e

        return {
            "container_id": container.id,
            "name": container.name,
            "port": port,
            "type": db_type,
            "username": username,
            "database": database,
            "volume_path": volume_path
        }

    def remove_database(self, name: str, remove_volume: bool = False) -> None:
        """
        Remove a database container and optionally its volume
        
        Args:
            name: Name of the database container
            remove_volume: Whether to remove the persistent volume
        """
        from docker.errors import NotFound

        try:
            container = self.client.containers.get(f"pulseup-db-{name}")
            container.remove(force=True)
            
            if remove_volume:
                volume_path = os.path.join(self.volume_base_path, name)
                if os.path.exists(volume_path):
                    import shutil
                    shutil.rmtree(volume_path)
        except NotFound:
            raise ValueError(f"Database container {name} not found")

    def get_database_status(self, name: str) -> Dict[str, Any]:
        """
        Get status information about a database container
        
        Args:
            name: Name of the database container
            
        Returns:
            Dict containing status information
        """
        from docker.errors import NotFound

        try:
            container = self.client.containers.get(f"pulseup-db-{name}")
            return {
                "id": container.id,
                "status": container.status,
                "name": container.name,
                "created": container.attrs['Created'],
                "state": container.attrs['State'],
                "ports": container.attrs['HostConfig']['PortBindings']
            }
        except NotFound:
            raise ValueError(f"Database container {name} not found") 