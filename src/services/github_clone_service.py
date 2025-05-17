import os
import shutil
import asyncio
from urllib.parse import urlparse
import platform
from src.utils.logging_utils import get_logger, log_exception, log_function_entry, log_function_exit

logger = get_logger(__name__)

class GithubCloneService:
    def __init__(self, base_clone_dir: str = "/opt/pulseup/apps"):
        # Just set the base directory, don't check/install git here
        self.base_clone_dir = base_clone_dir
        os.makedirs(self.base_clone_dir, exist_ok=True)
        self._build_service = None

    def set_build_service(self, build_service):
        """Set the build service for this clone service."""
        self._build_service = build_service
        logger.debug("Build service set for GitHub clone service")

    async def initialize(self):
        """Checks for git and attempts installation if missing."""
        log_function_entry(logger, "initialize")
        if not self._is_git_installed():
            logger.warning("Git command not found. Attempting installation...")
            try:
                # Await the installation coroutine directly
                await self._install_git()
            except Exception as e:
                log_exception(logger, "Failed during git installation attempt", e)
                raise EnvironmentError("Git command not found and installation attempt failed. Please install git manually.")

            if not self._is_git_installed():
                 raise EnvironmentError("Git installation attempt finished, but git command is still not found. Please install git manually.")
        log_function_exit(logger, "initialize")

    def _is_git_installed(self) -> bool:
        """Checks if the git command is available in PATH."""
        return shutil.which("git") is not None

    async def _run_shell_command(self, command: str):
        """Helper to run shell commands and log output/errors."""
        log_function_entry(logger, "_run_shell_command", command=command)
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if stderr:
            logger.warning(f"Command stderr: {stderr.decode().strip()}") # Use warning for stderr as some commands output info here
            
        if process.returncode != 0:
            error_msg = f"Command '{command}' failed with return code {process.returncode}"
            logger.error(error_msg)
            if stderr:
                 error_msg += f"\nstderr: {stderr.decode().strip()}"
            raise RuntimeError(error_msg)
        
        log_function_exit(logger, "_run_shell_command", result=True)
        return True

    async def _install_git(self):
        """Attempts to install git using common package managers."""
        log_function_entry(logger, "_install_git")
        # Basic OS/Package manager detection
        system = platform.system()
        
        if system != "Linux":
            raise NotImplementedError(f"Automatic git installation not supported on {system}. Please install git manually.")

        install_command = None
        update_command = None

        # Check for apt (Debian/Ubuntu)
        if shutil.which("apt-get"):
            update_command = "sudo apt-get update -y"
            install_command = "sudo apt-get install -y git"
        # Check for yum (CentOS/RHEL/Fedora)
        elif shutil.which("yum"):
            # No separate update needed usually, yum handles it
            install_command = "sudo yum install -y git"
        # Check for apk (Alpine)
        elif shutil.which("apk"):
             update_command = "sudo apk update"
             install_command = "sudo apk add --no-cache git"
        else:
            raise EnvironmentError("Could not detect a supported package manager (apt, yum, apk). Please install git manually.")

        try:
            if update_command:
                await self._run_shell_command(update_command)
            await self._run_shell_command(install_command)
        except Exception as e:
            log_exception(logger, "Error during git installation command execution", e)
            raise # Re-raise the exception
        log_function_exit(logger, "_install_git")

    def _construct_clone_url(self, repo_url: str, access_token: str) -> str:
        """Constructs the clone URL with embedded access token."""
        parsed_url = urlparse(repo_url)
        # Ensure scheme is https for token auth
        if parsed_url.scheme != 'https' :
             raise ValueError(f"Repository URL must use https for token authentication: {repo_url}")
        # Inject token: https://<token>@github.com/user/repo.git
        clone_url = f"https://oauth2:{access_token}@{parsed_url.netloc}{parsed_url.path}"
        logger.debug(f"Constructed clone URL (token omitted from log): https://<token>@{parsed_url.netloc}{parsed_url.path}")
        return clone_url

    async def clone_repo(self, repo_url: str, access_token: str, service_uid: str) -> dict:
        """Clones a GitHub repository into a directory named after the service_uid."""
        
        import git
        
        # Ensure the repo_url is a full HTTPS URL
        if not repo_url.startswith("http"):
            full_repo_url = f"https://github.com/{repo_url.strip()}"
        else:
            full_repo_url = repo_url            
        
        try:
            # Construct the clone path using the service UID
            clone_path = os.path.join(self.base_clone_dir, service_uid)
            
            # Do not continue if the directory already exists
            if os.path.exists(clone_path):
                return {"success": True, "clone_path": clone_path}
            
            # Ensure the target directory exists before cloning
            # Although clone_from might create it, be explicit
            os.makedirs(clone_path, exist_ok=True)
            
            # Construct the clone URL with the token using the full URL
            clone_url_with_token = self._construct_clone_url(full_repo_url, access_token)            
            
            # Run the blocking GitPython clone operation in a separate thread
            await asyncio.to_thread(
                git.Repo.clone_from,
                url=clone_url_with_token,
                to_path=clone_path
            )

            # Prepare the build if build_service is available
            if self._build_service:
                try:
                    await self._build_service.prepare_build(clone_path, service_uid)
                except Exception as e:
                    logger.error(f"Error preparing build after clone: {e}")
                    # Don't fail the clone if build prep fails
            else:
                logger.warning(f"Build service not available for auto-preparing build after clone for {service_uid}")
            
            return {"success": True, "clone_path": clone_path}

        except git.GitCommandError as e:
            error_msg = f"Git command failed during clone: {e.stderr.strip()}"
            logger.error(f"Failed to clone {full_repo_url} for service {service_uid}: {error_msg}")
            return {"success": False, "error": error_msg}
        except ValueError as e:
            logger.error(f"Configuration error cloning {full_repo_url} for service {service_uid}: {str(e)}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error cloning repository {full_repo_url} for service {service_uid}: {str(e)}")
            logger.exception(e) 
            return {"success": False, "error": f"An unexpected error occurred: {str(e)}"} 
        

    async def pull_repo(self, service_uid: str):
        """Pulls the latest changes from the remote repository."""
        import git

        clone_path = os.path.join(self.base_clone_dir, service_uid)
        if not os.path.exists(clone_path):
            raise ValueError(f"Repository {service_uid} not found in {clone_path}")        
        
        socket_manager = self._build_service.socket_manager
        
        try:
            # Get fresh repo info with new access token
            repo_info = await socket_manager.sio.call(
                'get_github_repo',
                {'service_uid': service_uid},
                namespace=socket_manager.namespace,
                timeout=30
            )
            
            if not repo_info or not isinstance(repo_info, dict) or 'error' in repo_info:
                error_msg = repo_info.get('error') if isinstance(repo_info, dict) else "Invalid response"
                logger.error(f"Error getting GitHub repo info for {service_uid}: {error_msg}")
                return {'success': False, 'error': f"Failed to get repo info: {error_msg}"}
            
            repo_url = repo_info.get('repo_url')
            access_token = repo_info.get('access_token')
            if not repo_url or not access_token:
                error_msg = f"Missing repo_url or access_token in response for {service_uid}"
                logger.error(f"{error_msg}: {repo_info}")
                return {'success': False, 'error': error_msg}
                
            # Ensure the repo_url is a full HTTPS URL before constructing the clone URL
            if not repo_url.startswith("http"):
                full_repo_url = f"https://github.com/{repo_url.strip()}"
            else:
                full_repo_url = repo_url   
                
            # Get the repo instance
            repo = git.Repo(clone_path)
            
            # Update remote URL with the new access token using the corrected URL
            remote_url_with_token = self._construct_clone_url(full_repo_url, access_token)
            origin = repo.remotes.origin
            
            # Set the new URL with updated token
            with repo.config_writer() as config:
                config.set_value('remote "origin"', 'url', remote_url_with_token)
            
            # First fetch to get latest refs
            origin.fetch()
            
            try:
                # Try to get the main branch name
                main_branch = next((ref.name.replace('origin/', '') for ref in repo.references if ref.name in ['origin/main', 'origin/master']), 'main')
                
                # Reset any local changes and checkout main branch
                repo.git.reset('--hard')
                repo.git.checkout(main_branch)
                
                # Pull the latest changes
                origin.pull()
                return {"success": True}
            except git.GitCommandError as branch_e:
                # If branch operations fail, try a more aggressive reset
                logger.warning(f"Branch operations failed, attempting aggressive reset: {str(branch_e)}")
                repo.git.reset('--hard', 'origin/main')
                origin.pull()
                return {"success": True}
            
        except git.GitCommandError as e:
            error_msg = f"Git command failed during pull: {e.stderr.strip()}"
            logger.error(f"Failed to pull for service {service_uid}: {error_msg}")
            return {"success": False, "error": error_msg}
        except Exception as e:
            logger.error(f"Unexpected error pulling repository for service {service_uid}: {str(e)}")
            logger.exception(e)
            return {"success": False, "error": f"An unexpected error occurred: {str(e)}"}