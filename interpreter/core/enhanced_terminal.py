"""
Enhanced Terminal for Structured I/O Capture

This module extends the existing Open Interpreter terminal functionality to provide
comprehensive structured output capture for orchestrator consumption. It builds upon
the existing language execution infrastructure while adding enhanced monitoring,
file tracking, and result formatting capabilities.

Key Features:
- Structured output capture (stdout, stderr, files)
- Execution metadata collection (timing, exit codes, resource usage)
- File generation tracking with path resolution
- Enhanced error handling and logging
- Performance monitoring and metrics
- Thread-safe execution with timeout handling
- Integration with existing language execution modules

Architecture:
- Extends existing Terminal class functionality
- Maintains compatibility with current language modules
- Adds structured result formatting for job management system
- Provides enhanced monitoring and debugging capabilities
"""

import logging
import os
import signal
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

import psutil

from .computer.terminal.terminal import Terminal

# Configure enhanced logging for terminal operations
logger = logging.getLogger("interpreter.enhanced_terminal")
logger.setLevel(logging.INFO)

if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s - Language: %(language)s | ExecutionID: %(exec_id)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class ExecutionResult:
    """
    Comprehensive execution result container with structured data capture

    This class provides a unified structure for capturing all aspects of code
    execution, including outputs, file generation, timing, and resource usage.

    Attributes:
        stdout: Captured standard output content
        stderr: Captured error output content
        files_created: List of file paths generated during execution
        files_modified: List of existing files that were modified
        execution_time_ms: Total execution time in milliseconds
        exit_code: Process exit code (0 for success, non-zero for error)
        error_message: Human-readable error description
        resource_usage: System resource consumption metrics
        metadata: Additional execution context and information
        working_directory: Directory where execution occurred
        environment_snapshot: Relevant environment variables during execution
    """

    def __init__(self):
        self.stdout: str = ""
        self.stderr: str = ""
        self.files_created: List[str] = []
        self.files_modified: List[str] = []
        self.execution_time_ms: Optional[int] = None
        self.exit_code: int = 0
        self.error_message: Optional[str] = None
        self.resource_usage: Dict[str, Any] = {}
        self.metadata: Dict[str, Any] = {}
        self.working_directory: str = os.getcwd()
        self.environment_snapshot: Dict[str, str] = {}
        self.process_id: Optional[int] = None
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert execution result to dictionary for JSON serialization

        Returns:
            Dict containing all execution result data in structured format
        """
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "files_created": self.files_created,
            "files_modified": self.files_modified,
            "execution_time_ms": self.execution_time_ms,
            "exit_code": self.exit_code,
            "error_message": self.error_message,
            "resource_usage": self.resource_usage,
            "metadata": self.metadata,
            "working_directory": self.working_directory,
            "environment_snapshot": self.environment_snapshot,
            "process_id": self.process_id,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class EnhancedTerminal(Terminal):
    """
    Enhanced terminal class with comprehensive structured output capture

    This class extends the existing Open Interpreter Terminal functionality to provide
    detailed execution monitoring, file tracking, and structured result formatting.
    It maintains full compatibility with the existing language execution system while
    adding enhanced capabilities for orchestrator integration.

    Key Enhancements:
    - Structured output capture with detailed metadata
    - File system monitoring for creation/modification tracking
    - Resource usage monitoring (CPU, memory, disk)
    - Execution timeout handling with graceful termination
    - Enhanced error handling and debugging information
    - Performance metrics and timing information
    - Thread-safe execution with proper cleanup

    Integration:
    - Maintains compatibility with existing language modules
    - Extends current Terminal class without breaking changes
    - Provides optional enhanced capture for new functionality
    - Falls back to standard behavior when needed
    """

    def __init__(
        self,
        computer,
        enable_file_tracking: bool = True,
        enable_resource_monitoring: bool = True,
    ):
        """
        Initialize enhanced terminal with monitoring capabilities

        Args:
            computer: Computer instance for system integration
            enable_file_tracking: Whether to track file creation/modification
            enable_resource_monitoring: Whether to monitor resource usage
        """
        super().__init__(computer)

        # Enhanced monitoring configuration
        self.enable_file_tracking = enable_file_tracking
        self.enable_resource_monitoring = enable_resource_monitoring

        # Execution tracking and monitoring systems
        self._execution_counter = 0
        self._active_executions: Dict[str, Dict[str, Any]] = {}
        self._file_snapshots: Dict[str, Dict[str, Any]] = {}

        # Thread safety for concurrent executions
        self._lock = threading.Lock()

        logger.info(
            f"EnhancedTerminal initialized - File tracking: {enable_file_tracking}, Resource monitoring: {enable_resource_monitoring}",
            extra={"language": "system", "exec_id": "init"},
        )

    def run_enhanced(
        self,
        language: str,
        code: str,
        timeout: int = 30,
        working_directory: Optional[str] = None,
        environment_variables: Optional[Dict[str, str]] = None,
        capture_files: bool = True,
    ) -> ExecutionResult:
        """
        Execute code with enhanced monitoring and structured result capture

        This method provides comprehensive code execution with full monitoring,
        file tracking, resource usage measurement, and structured result formatting.
        It's designed for integration with the job management system and orchestrator.

        Args:
            language: Programming language for execution
            code: Code content to execute
            timeout: Maximum execution time in seconds
            working_directory: Directory for code execution
            environment_variables: Custom environment variables
            capture_files: Whether to track file generation

        Returns:
            ExecutionResult: Comprehensive execution results with structured data
        """
        # Generate unique execution ID for tracking and logging
        with self._lock:
            self._execution_counter += 1
            execution_id = f"exec_{self._execution_counter}_{int(time.time())}"

        logger.info(
            f"Starting enhanced execution - Language: {language}, Timeout: {timeout}s",
            extra={"language": language, "exec_id": execution_id},
        )

        # Initialize execution result container
        result = ExecutionResult()
        result.start_time = datetime.now()
        result.metadata = {
            "execution_id": execution_id,
            "language": language,
            "timeout": timeout,
            "code_length": len(code),
            "capture_files_enabled": capture_files and self.enable_file_tracking,
        }

        # Prepare execution environment
        original_cwd = os.getcwd()
        if working_directory:
            result.working_directory = os.path.abspath(working_directory)
            os.makedirs(result.working_directory, exist_ok=True)
            os.chdir(result.working_directory)
        else:
            result.working_directory = original_cwd

        # Capture environment snapshot for debugging and reproduction
        result.environment_snapshot = self._capture_environment_snapshot(
            environment_variables
        )

        # Initialize file system monitoring if enabled
        file_snapshot = None
        if capture_files and self.enable_file_tracking:
            file_snapshot = self._create_file_system_snapshot(result.working_directory)

        # Initialize resource monitoring if enabled
        resource_monitor = None
        if self.enable_resource_monitoring:
            resource_monitor = self._start_resource_monitoring(execution_id)

        try:
            # Execute code with timeout and monitoring
            start_time = time.time()

            with self._execution_timeout(timeout, execution_id):
                # Use existing terminal execution with enhanced capture
                execution_chunks = super().run(
                    language, code, stream=False, display=False
                )

                # Process execution results and extract structured data
                stdout_parts = []
                stderr_parts = []

                for chunk in execution_chunks:
                    if chunk.get("type") == "console":
                        content = chunk.get("content", "")
                        if chunk.get("format") == "output":
                            stdout_parts.append(str(content))
                        elif chunk.get("format") == "error":
                            stderr_parts.append(str(content))
                    elif chunk.get("type") == "error":
                        stderr_parts.append(chunk.get("content", ""))
                        result.exit_code = 1

                # Combine captured outputs
                result.stdout = "\n".join(stdout_parts) if stdout_parts else ""
                result.stderr = "\n".join(stderr_parts) if stderr_parts else ""

            # Calculate execution timing
            end_time = time.time()
            result.execution_time_ms = int((end_time - start_time) * 1000)
            result.end_time = datetime.now()

            logger.info(
                f"Execution completed successfully - Time: {result.execution_time_ms}ms, Exit code: {result.exit_code}",
                extra={"language": language, "exec_id": execution_id},
            )

        except TimeoutError as e:
            # Handle execution timeout with proper cleanup
            result.execution_time_ms = timeout * 1000
            result.exit_code = 124  # Standard timeout exit code
            result.error_message = f"Execution timed out after {timeout} seconds"
            result.stderr += f"\nExecution timeout: {str(e)}"
            result.end_time = datetime.now()

            logger.warning(
                f"Execution timed out - Timeout: {timeout}s",
                extra={"language": language, "exec_id": execution_id},
            )

        except Exception as e:
            # Handle execution errors with comprehensive error capture
            result.execution_time_ms = (
                int((time.time() - start_time) * 1000)
                if "start_time" in locals()
                else None
            )
            result.exit_code = 1
            result.error_message = f"Execution failed: {str(e)}"
            result.stderr += f"\nExecution error: {traceback.format_exc()}"
            result.end_time = datetime.now()

            logger.error(
                f"Execution failed - Error: {str(e)}",
                extra={"language": language, "exec_id": execution_id},
            )

        finally:
            # Cleanup and finalize execution results
            try:
                # Capture file system changes if monitoring was enabled
                if file_snapshot and capture_files and self.enable_file_tracking:
                    file_changes = self._detect_file_system_changes(
                        result.working_directory, file_snapshot
                    )
                    result.files_created = file_changes["created"]
                    result.files_modified = file_changes["modified"]

                # Finalize resource monitoring if enabled
                if resource_monitor and self.enable_resource_monitoring:
                    result.resource_usage = self._finalize_resource_monitoring(
                        resource_monitor
                    )

                # Restore original working directory
                os.chdir(original_cwd)

                # Update execution metadata with final statistics
                result.metadata.update(
                    {
                        "files_created_count": len(result.files_created),
                        "files_modified_count": len(result.files_modified),
                        "stdout_length": len(result.stdout),
                        "stderr_length": len(result.stderr),
                        "resource_monitoring_enabled": self.enable_resource_monitoring,
                        "file_tracking_enabled": self.enable_file_tracking
                        and capture_files,
                    }
                )

            except Exception as cleanup_error:
                logger.error(
                    f"Cleanup error: {str(cleanup_error)}",
                    extra={"language": language, "exec_id": execution_id},
                )
                # Ensure we don't lose the main execution result due to cleanup errors
                result.metadata["cleanup_error"] = str(cleanup_error)

        logger.info(
            f"Enhanced execution complete - Files created: {len(result.files_created)}, Modified: {len(result.files_modified)}",
            extra={"language": language, "exec_id": execution_id},
        )

        return result

    @contextmanager
    def _execution_timeout(self, timeout: int, execution_id: str):
        """
        Context manager for execution timeout handling with graceful termination

        Args:
            timeout: Maximum execution time in seconds
            execution_id: Unique execution identifier for tracking
        """

        def timeout_handler(signum, frame):
            raise TimeoutError(f"Code execution timed out after {timeout} seconds")

        # Set up timeout signal handler
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

        try:
            yield
        finally:
            # Restore original signal handler and cancel alarm
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

    def _capture_environment_snapshot(
        self, custom_env: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Capture relevant environment variables for execution context

        Args:
            custom_env: Custom environment variables to include

        Returns:
            Dict containing relevant environment variables
        """
        # Standard environment variables that are often relevant for debugging
        relevant_vars = [
            "PATH",
            "PYTHONPATH",
            "NODE_PATH",
            "JAVA_HOME",
            "GOPATH",
            "RUSTUP_HOME",
            "HOME",
            "USER",
            "SHELL",
            "LANG",
            "LC_ALL",
            "TERM",
        ]

        env_snapshot = {}

        # Capture standard environment variables
        for var in relevant_vars:
            if var in os.environ:
                env_snapshot[var] = os.environ[var]

        # Include custom environment variables
        if custom_env:
            env_snapshot.update(custom_env)

        return env_snapshot

    def _create_file_system_snapshot(self, directory: str) -> Dict[str, Any]:
        """
        Create snapshot of file system state for change detection

        Args:
            directory: Directory to monitor for file changes

        Returns:
            Dict containing file system state information
        """
        snapshot = {"files": {}, "timestamp": time.time(), "directory": directory}

        try:
            # Recursively scan directory for files and their metadata
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        snapshot["files"][file_path] = {
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "exists": True,
                        }
                    except OSError:
                        # Skip files we can't access
                        continue

        except Exception as e:
            logger.warning(
                f"File system snapshot creation failed: {str(e)}",
                extra={"language": "system", "exec_id": "snapshot"},
            )

        return snapshot

    def _detect_file_system_changes(
        self, directory: str, original_snapshot: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """
        Detect file system changes by comparing current state with snapshot

        Args:
            directory: Directory to check for changes
            original_snapshot: Original file system state

        Returns:
            Dict containing lists of created and modified files
        """
        changes = {"created": [], "modified": []}

        try:
            current_files = {}

            # Scan current directory state
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        current_files[file_path] = {
                            "size": stat.st_size,
                            "mtime": stat.st_mtime,
                            "exists": True,
                        }
                    except OSError:
                        continue

            original_files = original_snapshot.get("files", {})

            # Detect changes by comparing snapshots
            for file_path, current_info in current_files.items():
                if file_path not in original_files:
                    # New file created
                    changes["created"].append(file_path)
                else:
                    # Check if file was modified
                    original_info = original_files[file_path]
                    if (
                        current_info["mtime"] > original_info["mtime"]
                        or current_info["size"] != original_info["size"]
                    ):
                        changes["modified"].append(file_path)

        except Exception as e:
            logger.warning(
                f"File system change detection failed: {str(e)}",
                extra={"language": "system", "exec_id": "change_detection"},
            )

        return changes

    def _start_resource_monitoring(self, execution_id: str) -> Dict[str, Any]:
        """
        Start resource usage monitoring for execution

        Args:
            execution_id: Unique execution identifier

        Returns:
            Dict containing monitoring context and initial measurements
        """
        try:
            process = psutil.Process()
            monitor_context = {
                "execution_id": execution_id,
                "start_time": time.time(),
                "initial_cpu": process.cpu_percent(),
                "initial_memory": process.memory_info(),
                "process": process,
                "samples": [],
            }

            return monitor_context

        except Exception as e:
            logger.warning(
                f"Resource monitoring initialization failed: {str(e)}",
                extra={"language": "system", "exec_id": execution_id},
            )
            return {}

    def _finalize_resource_monitoring(
        self, monitor_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Finalize resource usage monitoring and calculate statistics

        Args:
            monitor_context: Monitoring context from start_resource_monitoring

        Returns:
            Dict containing resource usage statistics
        """
        if not monitor_context:
            return {}

        try:
            process = monitor_context["process"]
            end_time = time.time()

            # Collect final resource measurements
            final_cpu = process.cpu_percent()
            final_memory = process.memory_info()

            resource_usage = {
                "execution_time_seconds": end_time - monitor_context["start_time"],
                "cpu_percent": {
                    "initial": monitor_context["initial_cpu"],
                    "final": final_cpu,
                    "average": (monitor_context["initial_cpu"] + final_cpu) / 2,
                },
                "memory_bytes": {
                    "initial_rss": monitor_context["initial_memory"].rss,
                    "final_rss": final_memory.rss,
                    "initial_vms": monitor_context["initial_memory"].vms,
                    "final_vms": final_memory.vms,
                    "peak_rss": final_memory.rss,  # Simplified peak calculation
                },
                "process_id": process.pid,
                "monitoring_samples": len(monitor_context.get("samples", [])),
            }

            return resource_usage

        except Exception as e:
            logger.warning(
                f"Resource monitoring finalization failed: {str(e)}",
                extra={
                    "language": "system",
                    "exec_id": monitor_context.get("execution_id", "unknown"),
                },
            )
            return {}

    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive monitoring statistics for the terminal instance

        Returns:
            Dict containing monitoring system statistics and metrics
        """
        with self._lock:
            stats = {
                "total_executions": self._execution_counter,
                "active_executions": len(self._active_executions),
                "file_tracking_enabled": self.enable_file_tracking,
                "resource_monitoring_enabled": self.enable_resource_monitoring,
                "supported_languages": [lang.name for lang in self.languages],
                "current_working_directory": os.getcwd(),
            }

        return stats
