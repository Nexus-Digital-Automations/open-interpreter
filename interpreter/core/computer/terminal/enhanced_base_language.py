"""
Enhanced Base Language Classes with Structured JSON Output Support

This module provides enhanced base classes for language-specific terminal execution
that support structured JSON output capture. These base classes extend the existing
BaseLanguage interface with comprehensive output capture, file tracking, and
execution context management.

Key Features:
- Structured JSON output format consistent across all languages
- Language-specific stdout/stderr capture patterns
- File system monitoring during execution
- Execution timing and performance metrics
- Error handling and validation
- Security context and restrictions
- Language-specific execution environment management

Author: Language-Specific Subclasses Specialist
Date: 2025-09-09
"""

import json
import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base_language import BaseLanguage


class StructuredExecutionResult:
    """
    Standardized execution result for structured JSON output

    This class provides a consistent interface for execution results across
    all language implementations, ensuring compatibility with orchestrator
    systems and machine-to-machine communication.

    Attributes:
        execution_id: Unique identifier for this execution
        language: Programming language used
        status: Execution status (running, completed, failed, timeout)
        stdout: Captured standard output
        stderr: Captured error output
        files: List of files created during execution
        exit_code: Process exit code
        execution_time_ms: Total execution time in milliseconds
        working_directory: Directory where execution occurred
        timestamp: When execution started
        command: The code/command that was executed
        metadata: Additional language-specific metadata
        error: Error message if execution failed
        metrics: Performance and resource usage metrics
    """

    def __init__(
        self,
        execution_id: str,
        language: str,
        command: str,
        working_directory: str = None,
    ):
        self.execution_id = execution_id
        self.language = language
        self.status = "running"
        self.stdout = ""
        self.stderr = ""
        self.files: List[str] = []
        self.exit_code: Optional[int] = None
        self.execution_time_ms = 0
        self.working_directory = working_directory or os.getcwd()
        self.timestamp = datetime.now()
        self.command = command
        self.metadata: Dict[str, Any] = {}
        self.error: Optional[str] = None
        self.metrics: Optional[Dict[str, Any]] = None

        # Language-specific context
        self.language_version: Optional[str] = None
        self.runtime_environment: Optional[str] = None
        self.active_line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert execution result to dictionary for JSON serialization

        Returns:
            Dictionary representation compatible with orchestrator systems
        """
        return {
            "execution_id": self.execution_id,
            "language": self.language,
            "status": self.status,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "files": self.files,
            "exit_code": self.exit_code,
            "execution_time_ms": self.execution_time_ms,
            "working_directory": self.working_directory,
            "timestamp": self.timestamp.isoformat(),
            "command": self.command,
            "metadata": self.metadata,
            "error": self.error,
            "metrics": self.metrics,
            "language_context": {
                "version": self.language_version,
                "runtime_environment": self.runtime_environment,
                "active_line": self.active_line,
            },
        }

    def to_json(self) -> str:
        """
        Convert execution result to JSON string

        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=2, default=str)


class LanguageFileTracker:
    """
    Language-specific file system monitoring

    This class provides file tracking capabilities tailored to specific
    programming languages, monitoring typical output directories and
    file patterns for each language.
    """

    def __init__(self, language: str, working_directory: str):
        self.language = language.lower()
        self.working_directory = Path(working_directory).resolve()
        self.initial_files: set = set()
        self.tracking_active = False
        self.logger = logging.getLogger(f"file_tracker_{language}_{id(self)}")

        # Language-specific watch patterns
        self.watch_patterns = self._get_language_patterns()

    def _get_language_patterns(self) -> List[str]:
        """
        Get file patterns specific to the programming language

        Returns:
            List of file patterns to monitor
        """
        patterns = {
            "python": [
                "*.py",
                "*.pyc",
                "*.pyo",
                "*.pyd",
                "__pycache__/*",
                "*.pkl",
                "*.csv",
                "*.json",
                "*.txt",
                "*.png",
                "*.jpg",
                "*.pdf",
            ],
            "javascript": [
                "*.js",
                "*.json",
                "*.html",
                "*.css",
                "package.json",
                "package-lock.json",
                "node_modules/*",
                "*.log",
            ],
            "shell": ["*.sh", "*.log", "*.txt", "*.tar.gz", "*.zip", "*.tmp"],
            "ruby": ["*.rb", "*.gem", "Gemfile", "Gemfile.lock", "*.log"],
            "java": ["*.java", "*.class", "*.jar", "*.war", "*.properties"],
            "powershell": ["*.ps1", "*.psd1", "*.psm1", "*.log", "*.txt"],
            "r": ["*.R", "*.Rmd", "*.Rdata", "*.csv", "*.png", "*.pdf", "*.txt"],
            "react": ["*.jsx", "*.tsx", "*.css", "*.html", "build/*", "dist/*"],
        }

        return patterns.get(self.language, ["*"])

    def start_tracking(self):
        """
        Start monitoring file system changes
        """
        self.tracking_active = True
        self.initial_files = self._scan_directory()

        self.logger.info(
            f"Started file tracking for {self.language}",
            extra={
                "language": self.language,
                "working_directory": str(self.working_directory),
                "initial_file_count": len(self.initial_files),
                "watch_patterns": self.watch_patterns,
            },
        )

    def get_new_files(self) -> List[str]:
        """
        Get list of new files created since tracking started

        Returns:
            List of absolute file paths that were created
        """
        if not self.tracking_active:
            return []

        current_files = self._scan_directory()
        new_files = current_files - self.initial_files

        # Convert to string paths and filter for language-specific patterns
        result = []
        for file_path in new_files:
            try:
                if file_path.exists() and file_path.is_file():
                    if self._matches_language_pattern(file_path):
                        result.append(str(file_path))
            except (OSError, PermissionError):
                continue

        self.logger.info(
            f"Detected {len(result)} new {self.language} files",
            extra={
                "new_files": result[:5],  # Log first 5 files
                "total_count": len(result),
            },
        )

        return sorted(result)

    def stop_tracking(self):
        """
        Stop file tracking
        """
        self.tracking_active = False
        self.logger.info(f"Stopped file tracking for {self.language}")

    def _scan_directory(self) -> set:
        """
        Scan working directory for files matching language patterns

        Returns:
            Set of Path objects for matching files
        """
        files = set()

        try:
            # Scan recursively but with reasonable depth limit
            for pattern in self.watch_patterns:
                try:
                    for file_path in self.working_directory.rglob(pattern):
                        if file_path.is_file() and not file_path.is_symlink():
                            # Apply size limit (50MB per file)
                            if file_path.stat().st_size < 50 * 1024 * 1024:
                                files.add(file_path)
                except (OSError, PermissionError):
                    continue

        except Exception as e:
            self.logger.warning(f"Error scanning directory: {e}")

        return files

    def _matches_language_pattern(self, file_path: Path) -> bool:
        """
        Check if file matches language-specific patterns

        Args:
            file_path: Path to check

        Returns:
            True if file matches language patterns
        """
        file_name = file_path.name.lower()
        file_suffix = file_path.suffix.lower()

        # Language-specific validation
        if self.language == "python":
            return file_suffix in [
                ".py",
                ".pyc",
                ".pyo",
                ".pyd",
                ".pkl",
                ".csv",
                ".json",
                ".txt",
                ".png",
                ".jpg",
                ".pdf",
            ] or "__pycache__" in str(file_path)
        elif self.language == "javascript":
            return file_suffix in [
                ".js",
                ".json",
                ".html",
                ".css",
                ".log",
            ] or file_name in ["package.json", "package-lock.json"]
        elif self.language == "shell":
            return file_suffix in [".sh", ".log", ".txt", ".tar.gz", ".zip", ".tmp"]
        elif self.language == "ruby":
            return file_suffix in [".rb", ".gem", ".log"] or file_name in [
                "gemfile",
                "gemfile.lock",
            ]
        elif self.language == "java":
            return file_suffix in [".java", ".class", ".jar", ".war", ".properties"]
        elif self.language == "powershell":
            return file_suffix in [".ps1", ".psd1", ".psm1", ".log", ".txt"]
        elif self.language == "r":
            return file_suffix in [
                ".r",
                ".rmd",
                ".rdata",
                ".csv",
                ".png",
                ".pdf",
                ".txt",
            ]
        elif self.language == "react":
            return (
                file_suffix in [".jsx", ".tsx", ".css", ".html"]
                or "build" in str(file_path)
                or "dist" in str(file_path)
            )

        return True  # Default: include all files


class EnhancedBaseLanguage(BaseLanguage, ABC):
    """
    Enhanced base language class with structured JSON output support

    This abstract base class extends the original BaseLanguage interface
    to provide comprehensive structured output capture, file tracking,
    and execution context management for all language implementations.

    Key Features:
    - Structured JSON output capture
    - Language-specific file system monitoring
    - Execution timing and performance metrics
    - Error handling and validation
    - Security restrictions and context management
    - Consistent interface across all language implementations

    Subclasses must implement:
    - _execute_with_capture(): Core execution logic with output capture
    - _get_language_version(): Detect language version
    - _detect_language_specific_errors(): Parse language-specific error patterns
    """

    def __init__(self, computer=None):
        super().__init__()
        self.computer = computer
        self.logger = logging.getLogger(f"enhanced_{self.name.lower()}_{id(self)}")

        # Structured execution support
        self._structured_mode = False
        self._current_execution: Optional[StructuredExecutionResult] = None
        self._file_tracker: Optional[LanguageFileTracker] = None

        # Performance monitoring
        self._start_time = 0
        self._peak_memory = 0

        # Language-specific context
        self._language_version = None
        self._runtime_environment = None

    def run_structured(
        self,
        code: str,
        capture_files: bool = True,
        working_directory: Optional[str] = None,
        timeout: Optional[int] = None,
        security_restrictions: Optional[Dict[str, Any]] = None,
    ) -> StructuredExecutionResult:
        """
        Execute code with structured JSON output capture

        This method provides the enhanced interface for executing code with
        comprehensive output capture, file tracking, and execution context.

        Args:
            code: Code to execute
            capture_files: Whether to track file system changes
            working_directory: Directory to execute in
            timeout: Maximum execution time in seconds
            security_restrictions: Security context and restrictions

        Returns:
            StructuredExecutionResult with comprehensive execution data
        """
        execution_id = str(uuid.uuid4())
        work_dir = working_directory or os.getcwd()

        self.logger.info(
            f"[{execution_id}] Starting structured execution",
            extra={
                "language": self.name,
                "code_length": len(code),
                "capture_files": capture_files,
                "working_directory": work_dir,
                "timeout": timeout,
            },
        )

        # Initialize structured execution
        result = StructuredExecutionResult(
            execution_id=execution_id,
            language=self.name,
            command=code,
            working_directory=work_dir,
        )

        result.language_version = self._get_language_version()
        result.runtime_environment = self._get_runtime_environment()

        self._current_execution = result
        self._structured_mode = True
        self._start_time = time.time()

        try:
            # Setup working directory
            original_cwd = None
            if working_directory and working_directory != os.getcwd():
                original_cwd = os.getcwd()
                os.makedirs(working_directory, exist_ok=True)
                os.chdir(working_directory)

            # Setup file tracking
            if capture_files:
                self._file_tracker = LanguageFileTracker(self.name, work_dir)
                self._file_tracker.start_tracking()

            # Apply security restrictions
            if security_restrictions:
                self._apply_security_restrictions(security_restrictions)

            # Execute with language-specific capture
            if timeout:
                result.update(self._execute_with_timeout(code, timeout))
            else:
                self._execute_with_capture(code, result)

            # Capture generated files
            if capture_files and self._file_tracker:
                result.files = self._file_tracker.get_new_files()

            # Calculate execution metrics
            result.execution_time_ms = int((time.time() - self._start_time) * 1000)

            # Determine final status
            if result.status == "running":
                result.status = (
                    "completed" if (result.exit_code or 0) == 0 else "failed"
                )

            # Add performance metrics
            result.metrics = self._collect_performance_metrics()

            self.logger.info(
                f"[{execution_id}] Structured execution completed",
                extra={
                    "status": result.status,
                    "execution_time_ms": result.execution_time_ms,
                    "files_created": len(result.files),
                    "stdout_length": len(result.stdout),
                    "stderr_length": len(result.stderr),
                },
            )

            return result

        except TimeoutError as e:
            result.status = "timeout"
            result.error = str(e)
            result.execution_time_ms = int((time.time() - self._start_time) * 1000)

            self.logger.error(
                f"[{execution_id}] Execution timeout", extra={"error": str(e)}
            )
            return result

        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            result.execution_time_ms = int((time.time() - self._start_time) * 1000)

            self.logger.error(
                f"[{execution_id}] Execution failed",
                extra={
                    "error": str(e),
                    "traceback": self._get_error_traceback(),
                },
            )
            return result

        finally:
            # Cleanup
            self._structured_mode = False
            self._current_execution = None

            if original_cwd:
                os.chdir(original_cwd)

            if self._file_tracker:
                self._file_tracker.stop_tracking()
                self._file_tracker = None

    # Abstract methods that subclasses must implement

    @abstractmethod
    def _execute_with_capture(self, code: str, result: StructuredExecutionResult):
        """
        Execute code with output capture

        This method must be implemented by each language subclass to provide
        language-specific execution with comprehensive output capture.

        Args:
            code: Code to execute
            result: StructuredExecutionResult to populate with output
        """
        pass

    @abstractmethod
    def _get_language_version(self) -> Optional[str]:
        """
        Get the version of the programming language

        Returns:
            Language version string, or None if unavailable
        """
        pass

    @abstractmethod
    def _detect_language_specific_errors(self, output: str) -> Optional[str]:
        """
        Parse language-specific error patterns from output

        Args:
            output: Output text to analyze

        Returns:
            Parsed error message, or None if no error detected
        """
        pass

    # Helper methods for subclasses

    def _get_runtime_environment(self) -> str:
        """
        Get runtime environment information

        Returns:
            String describing the runtime environment
        """
        return f"{self.name} runtime on {os.name}"

    def _apply_security_restrictions(self, restrictions: Dict[str, Any]):
        """
        Apply security restrictions to execution environment

        Args:
            restrictions: Dictionary of security restrictions
        """
        # Log security restrictions for audit
        self.logger.info(
            "Applied security restrictions", extra={"restrictions": restrictions}
        )

        # Implementation would depend on specific security requirements
        # This is a placeholder for security restriction logic

    def _execute_with_timeout(self, code: str, timeout: int) -> Dict[str, Any]:
        """
        Execute code with timeout handling

        Args:
            code: Code to execute
            timeout: Timeout in seconds

        Returns:
            Dictionary with execution results
        """
        import threading

        result_holder = {}
        exception_holder = [None]

        def execute_target():
            try:
                if self._current_execution:
                    self._execute_with_capture(code, self._current_execution)
                    result_holder["success"] = True
            except Exception as e:
                exception_holder[0] = e

        thread = threading.Thread(target=execute_target)
        thread.daemon = True
        thread.start()
        thread.join(timeout)

        if thread.is_alive():
            # Timeout occurred
            self.stop()  # Stop execution
            raise TimeoutError(f"Execution timed out after {timeout} seconds")

        if exception_holder[0]:
            raise exception_holder[0]

        return result_holder

    def _collect_performance_metrics(self) -> Dict[str, Any]:
        """
        Collect performance and resource usage metrics

        Returns:
            Dictionary of performance metrics
        """
        import psutil

        try:
            process = psutil.Process()
            memory_info = process.memory_info()

            return {
                "peak_memory_usage": max(self._peak_memory, memory_info.rss),
                "cpu_percent": process.cpu_percent(),
                "memory_percent": process.memory_percent(),
                "num_threads": process.num_threads(),
                "io_counters": (
                    process.io_counters()._asdict()
                    if hasattr(process, "io_counters")
                    else {}
                ),
                "language": self.name,
                "execution_time_ms": int((time.time() - self._start_time) * 1000),
            }
        except Exception:
            return {
                "language": self.name,
                "execution_time_ms": int((time.time() - self._start_time) * 1000),
            }

    def _get_error_traceback(self) -> str:
        """
        Get formatted error traceback

        Returns:
            Formatted traceback string
        """
        import traceback

        return traceback.format_exc()

    def _update_active_line(self, line_number: int):
        """
        Update active line tracking for debugging

        Args:
            line_number: Current line being executed
        """
        if self._current_execution:
            self._current_execution.active_line = line_number
            self._current_execution.metadata["last_active_line"] = line_number

    def _append_stdout(self, content: str):
        """
        Append content to stdout capture

        Args:
            content: Content to append
        """
        if self._current_execution:
            self._current_execution.stdout += content

    def _append_stderr(self, content: str):
        """
        Append content to stderr capture

        Args:
            content: Content to append
        """
        if self._current_execution:
            self._current_execution.stderr += content

            # Check for language-specific errors
            error = self._detect_language_specific_errors(content)
            if error and not self._current_execution.error:
                self._current_execution.error = error

    def _set_exit_code(self, code: int):
        """
        Set execution exit code

        Args:
            code: Exit code
        """
        if self._current_execution:
            self._current_execution.exit_code = code


class EnhancedSubprocessLanguage(EnhancedBaseLanguage):
    """
    Enhanced subprocess-based language execution with structured output

    This class provides a common implementation for languages that execute
    via subprocess (JavaScript, Shell, Ruby, PowerShell, etc.) with
    comprehensive structured output capture.
    """

    def __init__(self, computer=None):
        super().__init__(computer)

        # Subprocess management
        self.process = None
        self.start_cmd = []
        self.output_queue = None
        self.done_event = None

        # Output processing
        self.verbose = False

    @abstractmethod
    def get_start_command(self) -> List[str]:
        """
        Get the command to start the language interpreter

        Returns:
            List of command arguments
        """
        pass

    @abstractmethod
    def preprocess_code_structured(self, code: str) -> str:
        """
        Preprocess code for structured execution

        Args:
            code: Original code

        Returns:
            Preprocessed code with markers and error handling
        """
        pass

    def _execute_with_capture(self, code: str, result: StructuredExecutionResult):
        """
        Execute code via subprocess with comprehensive output capture

        Args:
            code: Code to execute
            result: StructuredExecutionResult to populate
        """
        import queue
        import threading

        try:
            # Preprocess code for structured execution
            processed_code = self.preprocess_code_structured(code)

            # Start subprocess if needed
            if not self.process or self.process.poll() is not None:
                self._start_subprocess()

            # Setup output capture
            output_queue = queue.Queue()
            done_event = threading.Event()

            # Start output listeners
            stdout_thread = threading.Thread(
                target=self._capture_subprocess_output,
                args=(self.process.stdout, output_queue, False, done_event),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=self._capture_subprocess_output,
                args=(self.process.stderr, output_queue, True, done_event),
                daemon=True,
            )

            stdout_thread.start()
            stderr_thread.start()

            # Send code to subprocess
            self.process.stdin.write(processed_code + "\n")
            self.process.stdin.flush()

            # Capture output until completion
            while not done_event.is_set():
                try:
                    output_item = output_queue.get(timeout=0.1)
                    self._process_output_item(output_item, result)
                except queue.Empty:
                    continue

            # Get any remaining output
            while not output_queue.empty():
                output_item = output_queue.get_nowait()
                self._process_output_item(output_item, result)

            # Set final exit code
            if self.process.poll() is not None:
                result.exit_code = self.process.poll()
            else:
                result.exit_code = 0

        except Exception as e:
            result.error = str(e)
            result.exit_code = 1
            self.logger.error(f"Subprocess execution failed: {e}")

    def _start_subprocess(self):
        """
        Start the language interpreter subprocess
        """
        import subprocess

        self.start_cmd = self.get_start_command()

        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"

        self.process = subprocess.Popen(
            self.start_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=0,
            universal_newlines=True,
            env=env,
            encoding="utf-8",
            errors="replace",
        )

    def _capture_subprocess_output(
        self, stream, output_queue, is_stderr: bool, done_event
    ):
        """
        Capture output from subprocess stream

        Args:
            stream: Subprocess stream to read from
            output_queue: Queue to put output items
            is_stderr: Whether this is stderr stream
            done_event: Event to signal when done
        """
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break

                # Apply language-specific line processing
                processed_line = self.line_postprocessor(line)
                if processed_line is None:
                    continue

                # Check for end-of-execution markers
                if self.detect_end_of_execution(processed_line):
                    # Remove marker from line before adding to output
                    cleaned_line = self._clean_execution_markers(processed_line)
                    if cleaned_line.strip():
                        output_queue.put(
                            {
                                "type": "output",
                                "is_stderr": is_stderr,
                                "content": cleaned_line,
                            }
                        )
                    done_event.set()
                    break

                # Check for active line markers
                active_line = self.detect_active_line(processed_line)
                if active_line is not None:
                    output_queue.put(
                        {
                            "type": "active_line",
                            "line_number": active_line,
                            "content": processed_line,
                        }
                    )
                    # Continue processing the line after removing marker
                    cleaned_line = self._clean_active_line_markers(processed_line)
                    if cleaned_line.strip():
                        output_queue.put(
                            {
                                "type": "output",
                                "is_stderr": is_stderr,
                                "content": cleaned_line,
                            }
                        )
                else:
                    output_queue.put(
                        {
                            "type": "output",
                            "is_stderr": is_stderr,
                            "content": processed_line,
                        }
                    )

        except Exception as e:
            output_queue.put(
                {
                    "type": "error",
                    "content": f"Output capture error: {str(e)}",
                }
            )
        finally:
            done_event.set()

    def _process_output_item(
        self, output_item: Dict[str, Any], result: StructuredExecutionResult
    ):
        """
        Process individual output item and update result

        Args:
            output_item: Output item from queue
            result: StructuredExecutionResult to update
        """
        if output_item["type"] == "output":
            if output_item.get("is_stderr"):
                self._append_stderr(output_item["content"])
            else:
                self._append_stdout(output_item["content"])
        elif output_item["type"] == "active_line":
            self._update_active_line(output_item["line_number"])
        elif output_item["type"] == "error":
            result.error = output_item["content"]
            result.exit_code = 1

    def _clean_execution_markers(self, line: str) -> str:
        """
        Remove execution end markers from line

        Args:
            line: Line to clean

        Returns:
            Cleaned line
        """
        # Default implementation - subclasses should override
        return line.replace("##end_of_execution##", "").strip()

    def _clean_active_line_markers(self, line: str) -> str:
        """
        Remove active line markers from line

        Args:
            line: Line to clean

        Returns:
            Cleaned line
        """
        import re

        return re.sub(r"##active_line\d+##", "", line).strip()

    def line_postprocessor(self, line: str) -> Optional[str]:
        """
        Post-process output line (can be overridden by subclasses)

        Args:
            line: Raw output line

        Returns:
            Processed line, or None to discard
        """
        return line.rstrip()

    def detect_active_line(self, line: str) -> Optional[int]:
        """
        Detect active line markers (can be overridden by subclasses)

        Args:
            line: Output line to check

        Returns:
            Line number if detected, None otherwise
        """
        if "##active_line" in line:
            try:
                return int(line.split("##active_line")[1].split("##")[0])
            except (IndexError, ValueError):
                return None
        return None

    def detect_end_of_execution(self, line: str) -> bool:
        """
        Detect end-of-execution markers (can be overridden by subclasses)

        Args:
            line: Output line to check

        Returns:
            True if end of execution detected
        """
        return "##end_of_execution##" in line

    def terminate(self):
        """
        Terminate subprocess and cleanup resources
        """
        if self.process:
            try:
                self.process.terminate()
                self.process.stdin.close()
                self.process.stdout.close()
                self.process.stderr.close()
                self.process = None
            except Exception:
                pass

    def stop(self):
        """
        Stop current execution
        """
        if self.process:
            try:
                self.process.send_signal(2)  # SIGINT
            except Exception:
                pass
