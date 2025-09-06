import getpass
import json
import logging
import os
import subprocess
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Union

from ..utils.recipient_utils import parse_for_recipient
from .languages.applescript import AppleScript
from .languages.html import HTML
from .languages.java import Java
from .languages.javascript import JavaScript
from .languages.powershell import PowerShell
from .languages.python import Python
from .languages.r import R
from .languages.react import React
from .languages.ruby import Ruby
from .languages.shell import Shell

# Should this be renamed to OS or System?

import_computer_api_code = """
import os
os.environ["INTERPRETER_COMPUTER_API"] = "False" # To prevent infinite recurring import of the computer API

import time
import datetime
from interpreter import interpreter

computer = interpreter.computer
""".strip()


class Terminal:
    def __init__(self, computer):
        self.computer = computer
        self.languages = [
            Ruby,
            Python,
            Shell,
            JavaScript,
            HTML,
            AppleScript,
            R,
            PowerShell,
            React,
            Java,
        ]
        self._active_languages = {}

        # Enhanced output capture system
        self._capture_structured_output = False
        self._execution_metadata = {}
        self._file_tracker = FileTracker()
        self._logger = self._setup_logging()

    def sudo_install(self, package):
        try:
            # First, try to install without sudo
            subprocess.run(["apt", "install", "-y", package], check=True)
        except subprocess.CalledProcessError:
            # If it fails, try with sudo
            print(f"Installation of {package} requires sudo privileges.")
            sudo_password = getpass.getpass("Enter sudo password: ")

            try:
                # Use sudo with password
                subprocess.run(
                    ["sudo", "-S", "apt", "install", "-y", package],
                    input=sudo_password.encode(),
                    check=True,
                )
                print(f"Successfully installed {package}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to install {package}. Error: {e}")
                return False

        return True

    def get_language(self, language):
        for lang in self.languages:
            if language.lower() == lang.name.lower() or (
                hasattr(lang, "aliases")
                and language.lower() in (alias.lower() for alias in lang.aliases)
            ):
                return lang
        return None

    def run(
        self,
        language,
        code,
        stream=False,
        display=False,
        capture_files=False,
        working_directory=None,
        timeout=None,
        structured_output=False,
    ) -> Union[List[Dict], Generator[Dict, None, None], Dict]:
        # Setup structured output capture if requested
        if structured_output:
            return self._run_with_structured_output(
                language, code, capture_files, working_directory, timeout
            )

        # Check if this is an apt install command
        if language == "shell" and code.strip().startswith("apt install"):
            package = code.split()[-1]
            if self.sudo_install(package):
                return [
                    {
                        "type": "console",
                        "format": "output",
                        "content": f"Package {package} installed successfully.",
                    }
                ]
            else:
                return [
                    {
                        "type": "console",
                        "format": "output",
                        "content": f"Failed to install package {package}.",
                    }
                ]

        if language == "python":
            if (
                self.computer.import_computer_api
                and not self.computer._has_imported_computer_api
                and "computer" in code
                and os.getenv("INTERPRETER_COMPUTER_API", "True") != "False"
            ):
                self.computer._has_imported_computer_api = True
                # Give it access to the computer via Python
                time.sleep(0.5)
                self.computer.run(
                    language="python",
                    code=import_computer_api_code,
                    display=self.computer.verbose,
                )

            if self.computer.import_skills and not self.computer._has_imported_skills:
                self.computer._has_imported_skills = True
                self.computer.skills.import_skills()

            # This won't work because truncated code is stored in interpreter.messages :/
            # If the full code was stored, we could do this:
            if False and "get_last_output()" in code:
                if "# We wouldn't want to have maximum recursion depth!" in code:
                    # We just tried to run this, in a moment.
                    pass
                else:
                    code_outputs = [
                        m
                        for m in self.computer.interpreter.messages
                        if m["role"] == "computer"
                        and "content" in m
                        and m["content"] != ""
                    ]
                    if len(code_outputs) > 0:
                        last_output = code_outputs[-1]["content"]
                    else:
                        last_output = ""
                    last_output = json.dumps(last_output)

                    self.computer.run(
                        "python",
                        f"# We wouldn't want to have maximum recursion depth!\nimport json\ndef get_last_output():\n    return '''{last_output}'''",
                    )

        if stream is False:
            # If stream == False, *pull* from _streaming_run.
            output_messages = []
            for chunk in self._streaming_run(language, code, display=display):
                if chunk.get("format") != "active_line":
                    # Should we append this to the last message, or make a new one?
                    if (
                        output_messages != []
                        and output_messages[-1].get("type") == chunk["type"]
                        and output_messages[-1].get("format") == chunk["format"]
                    ):
                        output_messages[-1]["content"] += chunk["content"]
                    else:
                        output_messages.append(chunk)
            return output_messages

        elif stream is True:
            # If stream == True, replace this with _streaming_run.
            return self._streaming_run(language, code, display=display)

    def _streaming_run(self, language, code, display=False):
        if language not in self._active_languages:
            # Get the language. Pass in self.computer *if it takes a single argument*
            # but pass in nothing if not. This makes custom languages easier to add / understand.
            lang_class = self.get_language(language)
            if lang_class.__init__.__code__.co_argcount > 1:
                self._active_languages[language] = lang_class(self.computer)
            else:
                self._active_languages[language] = lang_class()
        try:
            for chunk in self._active_languages[language].run(code):
                # self.format_to_recipient can format some messages as having a certain recipient.
                # Here we add that to the LMC messages:
                if chunk["type"] == "console" and chunk.get("format") == "output":
                    recipient, content = parse_for_recipient(chunk["content"])
                    if recipient:
                        chunk["recipient"] = recipient
                        chunk["content"] = content

                    # Sometimes, we want to hide the traceback to preserve tokens.
                    # (is this a good idea?)
                    if "@@@HIDE_TRACEBACK@@@" in content:
                        chunk["content"] = (
                            "Stopping execution.\n\n"
                            + content.split("@@@HIDE_TRACEBACK@@@")[-1].strip()
                        )

                yield chunk

                # Print it also if display = True
                if (
                    display
                    and chunk.get("format") != "active_line"
                    and chunk.get("content")
                ):
                    print(chunk["content"], end="")

        except GeneratorExit:
            self.stop()

    def stop(self):
        for language in self._active_languages.values():
            language.stop()

    def terminate(self):
        for language_name in list(self._active_languages.keys()):
            language = self._active_languages[language_name]
            if (
                language
            ):  # Not sure why this is None sometimes. We should look into this
                language.terminate()
            del self._active_languages[language_name]

    def _run_with_structured_output(
        self,
        language: str,
        code: str,
        capture_files: bool = False,
        working_directory: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Enhanced execution with structured output capture for Phase 2.2.1

        Returns structured output in format:
        {
            "status": "completed|failed|timeout",
            "stdout": "...",
            "stderr": "...",
            "files": [...],
            "execution_time": 1234,
            "exit_code": 0,
            "working_directory": "/path/to/workdir",
            "metadata": {...}
        }
        """
        execution_id = str(uuid.uuid4())
        start_time = time.time()

        self._logger.info(
            f"[{execution_id}] Starting structured execution",
            {
                "language": language,
                "code_length": len(code),
                "capture_files": capture_files,
                "working_directory": working_directory,
                "timeout": timeout,
            },
        )

        result = {
            "execution_id": execution_id,
            "status": "running",
            "stdout": "",
            "stderr": "",
            "files": [],
            "execution_time": 0,
            "exit_code": None,
            "working_directory": working_directory or os.getcwd(),
            "metadata": {
                "language": language,
                "timestamp": datetime.now().isoformat(),
                "capture_files": capture_files,
                "timeout": timeout,
            },
        }

        try:
            # Setup working directory if specified
            original_cwd = None
            if working_directory:
                original_cwd = os.getcwd()
                os.makedirs(working_directory, exist_ok=True)
                os.chdir(working_directory)
                result["working_directory"] = working_directory

            # Setup file tracking if requested
            if capture_files:
                self._file_tracker.start_tracking(result["working_directory"])

            # Execute with timeout if specified
            if timeout:
                execution_result = self._run_with_timeout(language, code, timeout)
            else:
                execution_result = self._execute_and_capture(language, code)

            # Process execution results
            result.update(execution_result)

            # Capture generated files if requested
            if capture_files:
                result["files"] = self._file_tracker.get_new_files()
                self._file_tracker.stop_tracking()

            # Calculate execution time
            result["execution_time"] = int((time.time() - start_time) * 1000)  # ms

            # Determine final status
            if result["status"] == "running":
                result["status"] = (
                    "completed" if result.get("exit_code", 0) == 0 else "failed"
                )

            self._logger.info(
                f"[{execution_id}] Execution completed",
                {
                    "status": result["status"],
                    "execution_time_ms": result["execution_time"],
                    "files_created": len(result["files"]),
                },
            )

            return result

        except TimeoutError as e:
            result.update(
                {
                    "status": "timeout",
                    "stderr": str(e),
                    "execution_time": int((time.time() - start_time) * 1000),
                }
            )
            self._logger.error(f"[{execution_id}] Execution timeout", {"error": str(e)})
            return result

        except Exception as e:
            result.update(
                {
                    "status": "failed",
                    "stderr": str(e),
                    "execution_time": int((time.time() - start_time) * 1000),
                }
            )
            self._logger.error(
                f"[{execution_id}] Execution failed",
                {"error": str(e), "traceback": __import__("traceback").format_exc()},
            )
            return result

        finally:
            # Restore original working directory
            if original_cwd:
                os.chdir(original_cwd)

            # Cleanup file tracking
            if capture_files:
                self._file_tracker.cleanup()

    def _execute_and_capture(self, language: str, code: str) -> Dict[str, Any]:
        """
        Execute code and capture stdout/stderr in structured format
        """
        stdout_lines = []
        stderr_lines = []
        exit_code = 0

        try:
            # Execute using existing streaming mechanism
            for chunk in self._streaming_run(language, code, display=False):
                if chunk.get("type") == "console":
                    if chunk.get("format") == "output":
                        content = chunk.get("content", "")
                        if "KeyboardInterrupt" in content or "Traceback" in content:
                            stderr_lines.append(content)
                            exit_code = 1
                        else:
                            stdout_lines.append(content)
                    elif chunk.get("format") == "active_line":
                        # Skip active line markers in structured output
                        continue
                elif chunk.get("type") == "image":
                    # Handle image outputs (matplotlib plots, etc.)
                    stdout_lines.append(
                        f"[Image generated: {chunk.get('format', 'unknown')}]"
                    )
                elif chunk.get("type") == "code":
                    # Handle code outputs (HTML, JavaScript)
                    stdout_lines.append(
                        f"[Code output: {chunk.get('format', 'unknown')}]"
                    )

        except Exception as e:
            stderr_lines.append(str(e))
            exit_code = 1

        return {
            "stdout": "".join(stdout_lines),
            "stderr": "".join(stderr_lines),
            "exit_code": exit_code,
        }

    def _run_with_timeout(
        self, language: str, code: str, timeout: int
    ) -> Dict[str, Any]:
        """
        Execute code with timeout using threading
        """
        result = {"stdout": "", "stderr": "", "exit_code": None, "status": "running"}
        exception_holder = [None]

        def execute_target():
            try:
                execution_result = self._execute_and_capture(language, code)
                result.update(execution_result)
            except Exception as e:
                exception_holder[0] = e
                result.update({"stderr": str(e), "exit_code": 1})

        thread = threading.Thread(target=execute_target)
        thread.daemon = True
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            # Timeout occurred - try to stop execution
            self.stop()
            result.update(
                {
                    "status": "timeout",
                    "stderr": f"Execution timed out after {timeout} seconds",
                    "exit_code": 124,  # Standard timeout exit code
                }
            )
            raise TimeoutError(f"Execution timed out after {timeout} seconds")

        if exception_holder[0]:
            raise exception_holder[0]

        return result

    def _setup_logging(self):
        """
        Setup structured logging for terminal operations
        """
        import logging

        # Create logger with unique name
        logger_name = f"terminal_{id(self)}"
        logger = logging.getLogger(logger_name)

        # Prevent duplicate handlers
        if not logger.handlers:
            logger.setLevel(logging.INFO)

            # Create console handler with structured formatting
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[%(asctime)s] %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger


class FileTracker:
    """
    Tracks file system changes during code execution
    Monitors file creation, modification, and deletion
    """

    def __init__(self):
        self.tracking_directory = None
        self.initial_files = set()
        self.tracking_active = False
        self._logger = logging.getLogger(f"file_tracker_{id(self)}")

    def start_tracking(self, directory: str):
        """
        Start tracking files in the specified directory

        Args:
            directory: Directory path to monitor
        """
        self.tracking_directory = Path(directory).resolve()
        self.tracking_active = True

        # Capture initial state
        self.initial_files = self._scan_directory(self.tracking_directory)

        self._logger.info(
            f"Started file tracking in {self.tracking_directory}",
            {"initial_file_count": len(self.initial_files)},
        )

    def get_new_files(self) -> List[str]:
        """
        Get list of new files created since tracking started

        Returns:
            List of absolute file paths that were created
        """
        if not self.tracking_active or not self.tracking_directory:
            return []

        current_files = self._scan_directory(self.tracking_directory)
        new_files = current_files - self.initial_files

        # Convert to absolute string paths and filter valid files
        result = []
        for file_path in new_files:
            try:
                if file_path.exists() and file_path.is_file():
                    # Ensure secure path handling
                    if self._is_safe_path(file_path):
                        result.append(str(file_path))
            except (OSError, PermissionError) as e:
                self._logger.warning(f"Cannot access file {file_path}: {e}")

        self._logger.info(
            f"Detected {len(result)} new files",
            {"new_files": result[:10]},  # Log first 10 files to prevent log spam
        )

        return sorted(result)

    def stop_tracking(self):
        """
        Stop file tracking
        """
        self.tracking_active = False
        self._logger.info("Stopped file tracking")

    def cleanup(self):
        """
        Clean up tracking resources
        """
        self.tracking_active = False
        self.tracking_directory = None
        self.initial_files.clear()

    def _scan_directory(self, directory: Path) -> set:
        """
        Recursively scan directory and return set of all file paths

        Args:
            directory: Directory to scan

        Returns:
            Set of Path objects for all files found
        """
        files = set()

        try:
            # Scan recursively with reasonable depth limit
            for item in directory.rglob("*"):
                try:
                    # Only include actual files, skip directories and symlinks
                    if item.is_file() and not item.is_symlink():
                        # Apply reasonable size limit (100MB) to prevent memory issues
                        if item.stat().st_size < 100 * 1024 * 1024:
                            files.add(item)
                except (OSError, PermissionError):
                    # Skip files we can't access
                    continue

        except (OSError, PermissionError) as e:
            self._logger.warning(f"Cannot scan directory {directory}: {e}")

        return files

    def _is_safe_path(self, file_path: Path) -> bool:
        """
        Validate that the file path is safe to include in results

        Args:
            file_path: Path to validate

        Returns:
            True if path is safe, False otherwise
        """
        try:
            # Resolve path to detect any traversal attempts
            resolved = file_path.resolve()

            # Ensure path is within or under the tracking directory
            if self.tracking_directory:
                tracking_resolved = self.tracking_directory.resolve()
                try:
                    resolved.relative_to(tracking_resolved)
                except ValueError:
                    # Path is outside tracking directory
                    self._logger.warning(
                        f"File {resolved} is outside tracking directory"
                    )
                    return False

            # Additional safety checks
            file_name = resolved.name.lower()

            # Skip system/hidden files
            if file_name.startswith(".") and file_name not in [".gitignore", ".env"]:
                return False

            # Skip potentially sensitive files
            sensitive_patterns = ["password", "secret", "key", "token", "credential"]
            if any(pattern in file_name for pattern in sensitive_patterns):
                self._logger.warning(
                    f"Skipping potentially sensitive file: {file_name}"
                )
                return False

            return True

        except Exception as e:
            self._logger.warning(f"Path validation failed for {file_path}: {e}")
            return False
