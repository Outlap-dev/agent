import os
import logging
import aiofiles
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

class SSHKeyService:
    def __init__(self):
        self.ssh_dir = Path.home() / '.ssh'
        self.authorized_keys_file = self.ssh_dir / 'authorized_keys'

    async def add_key(self, public_key: str, key_uid: str) -> Dict[str, Any]:
        """
        Adds a public SSH key to the authorized_keys file.

        Args:
            public_key: The public SSH key string.
            key_uid: An identifier for the key (for logging purposes).

        Returns:
            A dictionary indicating success or failure.
        """
        if not public_key or not isinstance(public_key, str):
            return {"success": False, "error": "Invalid public key provided."}

        public_key = public_key.strip()
        if not public_key:
             return {"success": False, "error": "Public key cannot be empty."}

        try:
            # Ensure .ssh directory exists with correct permissions (700)
            self.ssh_dir.mkdir(mode=0o700, exist_ok=True)
            logger.info(f"Ensured SSH directory exists: {self.ssh_dir}")

            # Check if key already exists
            key_exists = False
            if self.authorized_keys_file.exists():
                 async with aiofiles.open(self.authorized_keys_file, mode='r') as f:
                    async for line in f:
                        # Basic check, might need refinement for comments/options
                        if public_key in line.strip(): 
                            key_exists = True
                            break
            
            if key_exists:
                logger.info(f"Key with UID {key_uid} already exists in {self.authorized_keys_file}. Skipping.")
                return {"success": True, "message": "Key already exists."}

            # Append the key, ensuring it's on a new line
            async with aiofiles.open(self.authorized_keys_file, mode='a') as f:
                # Check if file ends with newline, add one if not
                await f.seek(0, os.SEEK_END)
                file_size = await f.tell()
                needs_newline = False
                if file_size > 0:
                    await f.seek(-1, os.SEEK_END)
                    last_char = await f.read(1)
                    if last_char != '\n':
                        needs_newline = True
                
                if needs_newline:
                    await f.write('\n') # Add newline if missing before the key

                await f.write(f"{public_key}\n") # Add the key and a newline

            # Ensure authorized_keys file has correct permissions (600)
            os.chmod(self.authorized_keys_file, 0o600)

            logger.info(f"Successfully added SSH key with UID {key_uid} to {self.authorized_keys_file}")
            return {"success": True, "message": "SSH key added successfully."}

        except OSError as e:
            logger.error(f"OS error adding SSH key (UID: {key_uid}): {e}")
            return {"success": False, "error": f"File system error: {e}"}
        except Exception as e:
            logger.exception(f"Unexpected error adding SSH key (UID: {key_uid}): {e}")
            return {"success": False, "error": f"An unexpected error occurred: {e}"} 