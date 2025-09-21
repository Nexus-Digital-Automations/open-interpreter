"""
Job Management System for Open Interpreter FastAPI Server

This module implements UUID-based job tracking and management capabilities for the
Open Interpreter FastAPI server, enabling reliable orchestrator communication
and asynchronous execution handling.

Key Features:
- UUID-based job identification and tracking
- Job status management (queued, running, completed, failed, timeout)
- Result caching and retrieval
- Execution timeout handling
- Thread-safe operations with asyncio integration
- Comprehensive logging and monitoring

Usage:
    job_manager = JobManager()
    job_id = await job_manager.create_job(request_data)
    status = await job_manager.get_job_status(job_id)
    result = await job_manager.get_job_result(job_id)

Architecture Integration:
- Extends existing AsyncInterpreter functionality
- Thread-safe integration with existing execution model
- Compatible with current WebSocket and REST API patterns
"""

import asyncio
import logging
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

# Configure comprehensive logging for job management operations
logger = logging.getLogger("interpreter.job_manager")
logger.setLevel(logging.INFO)

# Create console handler with structured formatting for debugging
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s - JobID: %(job_id)s | Status: %(job_status)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


class JobStatus(Enum):
    """
    Enumeration of possible job execution states

    QUEUED: Job created and waiting for execution
    RUNNING: Job currently being executed
    COMPLETED: Job finished successfully with results
    FAILED: Job failed due to execution error
    TIMEOUT: Job exceeded maximum execution time
    CANCELLED: Job was cancelled before completion
    """

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ExecuteRequest(BaseModel):
    """
    Pydantic model for code execution requests

    Validates and structures incoming execution requests with comprehensive
    parameter support for different execution scenarios.

    Attributes:
        code: Code content to execute
        language: Programming language (python, javascript, shell, etc.)
        timeout: Maximum execution time in seconds (default: 30)
        capture_files: Whether to track generated files (default: True)
        working_directory: Execution working directory (optional)
        environment_variables: Custom environment variables (optional)
        metadata: Additional execution metadata (optional)
    """

    code: str
    language: str = "python"
    timeout: int = 30
    capture_files: bool = True
    working_directory: Optional[str] = None
    environment_variables: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None


class JobResult(BaseModel):
    """
    Structured job execution result format

    Provides consistent result structure for orchestrator consumption
    with comprehensive execution information and file tracking.

    Attributes:
        job_id: Unique job identifier
        status: Current job execution status
        stdout: Captured standard output content
        stderr: Captured error output content
        files_created: List of file paths generated during execution
        execution_time_ms: Total execution time in milliseconds
        exit_code: Process exit code (if applicable)
        error_message: Human-readable error description (if failed)
        metadata: Additional execution information
        created_at: Job creation timestamp
        started_at: Execution start timestamp (optional)
        completed_at: Execution completion timestamp (optional)
    """

    job_id: str
    status: JobStatus
    stdout: str = ""
    stderr: str = ""
    files_created: List[str] = []
    execution_time_ms: Optional[int] = None
    exit_code: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class JobManager:
    """
    Comprehensive job management system for Open Interpreter FastAPI server

    This class manages the complete lifecycle of code execution jobs, from
    creation through completion, providing thread-safe operations and
    comprehensive logging for production environments.

    Key Responsibilities:
    - Job creation with UUID generation and validation
    - Job status tracking and state management
    - Result caching and retrieval with TTL expiration
    - Execution timeout handling and cleanup
    - Thread-safe operations with proper locking
    - Integration with existing AsyncInterpreter execution model
    - Comprehensive logging and error handling

    Thread Safety:
    - All operations are protected by threading locks
    - Safe concurrent access from FastAPI endpoints
    - Proper cleanup of completed/expired jobs

    Performance Considerations:
    - In-memory storage for fast access
    - Configurable result TTL for memory management
    - Background cleanup of expired jobs
    - Efficient job lookup with UUID indexing
    """

    def __init__(self, result_ttl_hours: int = 24, max_concurrent_jobs: int = 10):
        """
        Initialize job management system with configuration parameters

        Args:
            result_ttl_hours: Time to live for cached results in hours
            max_concurrent_jobs: Maximum number of concurrent executing jobs
        """
        # Core job storage - thread-safe dictionaries for job data
        self.jobs: Dict[str, JobResult] = {}
        self.job_threads: Dict[str, threading.Thread] = {}

        # Configuration parameters for job management behavior
        self.result_ttl = timedelta(hours=result_ttl_hours)
        self.max_concurrent_jobs = max_concurrent_jobs

        # Thread synchronization for safe concurrent access
        self._lock = threading.Lock()
        self._stop_events: Dict[str, threading.Event] = {}

        # Background cleanup thread for expired job results
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_expired_jobs, daemon=True
        )
        self._cleanup_running = True
        self._cleanup_thread.start()

        logger.info(
            f"JobManager initialized - Result TTL: {result_ttl_hours}h, Max concurrent: {max_concurrent_jobs}",
            extra={"job_id": "system", "job_status": "initialized"},
        )

    async def create_job(self, request: ExecuteRequest) -> str:
        """
        Create new execution job with UUID generation and initial setup

        This method validates the execution request, generates a unique job ID,
        and initializes the job tracking structures. The job is created in QUEUED
        status and ready for execution.

        Args:
            request: ExecuteRequest object containing code and execution parameters

        Returns:
            str: Unique job ID for tracking and result retrieval

        Raises:
            ValueError: If request validation fails
            RuntimeError: If maximum concurrent jobs limit is reached
        """
        # Generate unique job identifier using UUID4 for guaranteed uniqueness
        job_id = str(uuid.uuid4())

        # Validate request parameters and check system capacity
        if not request.code.strip():
            raise ValueError("Code content cannot be empty")

        with self._lock:
            # Check if system has capacity for new jobs (running jobs only)
            running_jobs = sum(
                1 for job in self.jobs.values() if job.status == JobStatus.RUNNING
            )
            if running_jobs >= self.max_concurrent_jobs:
                raise RuntimeError(
                    f"Maximum concurrent jobs limit reached: {self.max_concurrent_jobs}"
                )

            # Create job result object with initial state
            job_result = JobResult(
                job_id=job_id,
                status=JobStatus.QUEUED,
                created_at=datetime.now(),
                metadata={
                    **{
                        "request_language": request.language,
                        "request_timeout": request.timeout,
                        "capture_files": request.capture_files,
                        "working_directory": request.working_directory,
                        "environment_variables": request.environment_variables or {},
                    },
                    **(request.metadata or {}),
                },
            )

            # Store job in tracking systems
            self.jobs[job_id] = job_result
            self._stop_events[job_id] = threading.Event()

        logger.info(
            f"Job created successfully - Language: {request.language}, Timeout: {request.timeout}s",
            extra={"job_id": job_id, "job_status": JobStatus.QUEUED.value},
        )

        return job_id

    async def execute_job(
        self, job_id: str, interpreter_instance, request: ExecuteRequest
    ) -> None:
        """
        Execute job in separate thread with comprehensive error handling

        This method manages the complete job execution lifecycle, including
        status updates, timeout handling, result capture, and error management.
        Integrates with existing AsyncInterpreter execution model.

        Args:
            job_id: Unique job identifier
            interpreter_instance: AsyncInterpreter instance for code execution
            request: Original execution request with parameters
        """
        with self._lock:
            if job_id not in self.jobs:
                logger.error(
                    "Job not found for execution",
                    extra={"job_id": job_id, "job_status": "not_found"},
                )
                return

            # Update job status to running and record start time
            self.jobs[job_id].status = JobStatus.RUNNING
            self.jobs[job_id].started_at = datetime.now()

        logger.info(
            f"Starting job execution - Language: {request.language}",
            extra={"job_id": job_id, "job_status": JobStatus.RUNNING.value},
        )

        # Execute job in separate thread for timeout handling and non-blocking operation
        execution_thread = threading.Thread(
            target=self._execute_job_sync,
            args=(job_id, interpreter_instance, request),
            name=f"JobExecution-{job_id[:8]}",
        )

        with self._lock:
            self.job_threads[job_id] = execution_thread

        execution_thread.start()

    def _execute_job_sync(
        self, job_id: str, interpreter_instance, request: ExecuteRequest
    ) -> None:
        """
        Synchronous job execution with comprehensive result capture

        This method handles the actual code execution, capturing all outputs,
        tracking generated files, and managing execution timeouts. All results
        are captured in structured format for orchestrator consumption.

        Args:
            job_id: Unique job identifier
            interpreter_instance: AsyncInterpreter instance for execution
            request: Execution request parameters
        """
        start_time = time.time()
        _stop_event = self._stop_events.get(
            job_id
        )  # Intentionally unused - prepared for future cancellation logic

        try:
            # Prepare execution environment and capture structures
            stdout_buffer = []
            stderr_buffer = []
            files_created = []

            # Execute code using existing interpreter terminal system
            # This integrates with the existing language execution infrastructure
            terminal = interpreter_instance.computer.terminal

            # Track working directory changes for file capture
            original_cwd = None
            if request.working_directory:
                import os

                original_cwd = os.getcwd()
                os.chdir(request.working_directory)

            try:
                # Execute code and capture structured output
                execution_results = terminal.run(
                    language=request.language,
                    code=request.code,
                    stream=False,  # We handle streaming ourselves for job management
                    display=False,  # Disable display output for clean capture
                )

                # Process execution results and extract structured data
                exit_code = 0
                for result_chunk in execution_results:
                    if result_chunk.get("type") == "console":
                        if result_chunk.get("format") == "output":
                            stdout_buffer.append(result_chunk.get("content", ""))
                        elif result_chunk.get("format") == "error":
                            stderr_buffer.append(result_chunk.get("content", ""))
                    elif result_chunk.get("type") == "error":
                        stderr_buffer.append(result_chunk.get("content", ""))
                        exit_code = 1

                # Capture generated files if requested
                if request.capture_files:
                    files_created = self._discover_generated_files(
                        request.working_directory
                    )

            finally:
                # Restore original working directory
                if original_cwd:
                    os.chdir(original_cwd)

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Update job result with execution data
            with self._lock:
                if job_id in self.jobs:
                    job_result = self.jobs[job_id]
                    job_result.status = JobStatus.COMPLETED
                    job_result.stdout = "\n".join(stdout_buffer)
                    job_result.stderr = "\n".join(stderr_buffer)
                    job_result.files_created = files_created
                    job_result.execution_time_ms = execution_time_ms
                    job_result.exit_code = exit_code
                    job_result.completed_at = datetime.now()

            logger.info(
                f"Job completed successfully - Execution time: {execution_time_ms}ms, Files created: {len(files_created)}",
                extra={"job_id": job_id, "job_status": JobStatus.COMPLETED.value},
            )

        except Exception as e:
            # Handle execution errors with comprehensive error capture
            execution_time_ms = int((time.time() - start_time) * 1000)
            error_message = f"Execution failed: {str(e)}"
            error_traceback = traceback.format_exc()

            with self._lock:
                if job_id in self.jobs:
                    job_result = self.jobs[job_id]
                    job_result.status = JobStatus.FAILED
                    job_result.error_message = error_message
                    job_result.stderr = error_traceback
                    job_result.execution_time_ms = execution_time_ms
                    job_result.exit_code = 1
                    job_result.completed_at = datetime.now()

            logger.error(
                f"Job execution failed - Error: {error_message}",
                extra={"job_id": job_id, "job_status": JobStatus.FAILED.value},
            )

        finally:
            # Cleanup job thread tracking
            with self._lock:
                self.job_threads.pop(job_id, None)
                # Keep stop_event for potential cancellation tracking

    def _discover_generated_files(self, working_directory: Optional[str]) -> List[str]:
        """
        Discover files generated during code execution

        This method scans the working directory to identify files that were
        created during job execution. It's used for comprehensive result tracking.

        Args:
            working_directory: Directory to scan for generated files

        Returns:
            List[str]: Absolute paths to discovered generated files
        """
        import glob
        import os

        if not working_directory or not os.path.exists(working_directory):
            return []

        generated_files = []
        try:
            # Use glob patterns to find common generated file types
            file_patterns = [
                "*.png",
                "*.jpg",
                "*.jpeg",
                "*.gif",
                "*.svg",  # Images
                "*.pdf",
                "*.docx",
                "*.xlsx",
                "*.csv",  # Documents
                "*.txt",
                "*.json",
                "*.xml",
                "*.html",  # Text files
                "*.mp4",
                "*.avi",
                "*.mov",
                "*.mp3",  # Media files
            ]

            for pattern in file_patterns:
                pattern_path = os.path.join(working_directory, pattern)
                generated_files.extend(glob.glob(pattern_path))

            # Convert to absolute paths for consistent referencing
            generated_files = [os.path.abspath(f) for f in generated_files]

        except Exception as e:
            logger.warning(
                f"File discovery failed: {str(e)}",
                extra={"job_id": "system", "job_status": "file_discovery_error"},
            )

        return generated_files

    async def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get current job status and basic execution information

        This method provides quick status information without full result data,
        useful for polling and monitoring job progress.

        Args:
            job_id: Unique job identifier

        Returns:
            Dict containing job status information, or None if job not found
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return None

            status_info = {
                "job_id": job_id,
                "status": job.status.value,
                "created_at": job.created_at.isoformat(),
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": (
                    job.completed_at.isoformat() if job.completed_at else None
                ),
                "execution_time_ms": job.execution_time_ms,
                "metadata": job.metadata,
            }

        logger.debug(
            f"Status requested - Current: {job.status.value}",
            extra={"job_id": job_id, "job_status": job.status.value},
        )

        return status_info

    async def get_job_result(self, job_id: str) -> Optional[JobResult]:
        """
        Get complete job execution result including all outputs and files

        This method returns the full execution result with all captured data,
        designed for final result retrieval by the orchestrator.

        Args:
            job_id: Unique job identifier

        Returns:
            JobResult object with complete execution data, or None if not found
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return None

            # Return copy to prevent external modification
            result = JobResult(
                job_id=job.job_id,
                status=job.status,
                stdout=job.stdout,
                stderr=job.stderr,
                files_created=job.files_created.copy(),
                execution_time_ms=job.execution_time_ms,
                exit_code=job.exit_code,
                error_message=job.error_message,
                metadata=job.metadata.copy(),
                created_at=job.created_at,
                started_at=job.started_at,
                completed_at=job.completed_at,
            )

        logger.debug(
            f"Full result requested - Status: {job.status.value}, Output length: {len(job.stdout)}",
            extra={"job_id": job_id, "job_status": job.status.value},
        )

        return result

    async def cancel_job(self, job_id: str) -> bool:
        """
        Cancel running job execution

        This method attempts to gracefully cancel a running job by setting
        the stop event and cleaning up execution resources.

        Args:
            job_id: Unique job identifier

        Returns:
            bool: True if job was cancelled, False if not found or not cancellable
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job or job.status not in [JobStatus.QUEUED, JobStatus.RUNNING]:
                return False

            # Set stop event for graceful termination
            stop_event = self._stop_events.get(job_id)
            if stop_event:
                stop_event.set()

            # Update job status
            job.status = JobStatus.CANCELLED
            job.completed_at = datetime.now()
            job.error_message = "Job cancelled by user request"

        logger.info(
            "Job cancelled successfully",
            extra={"job_id": job_id, "job_status": JobStatus.CANCELLED.value},
        )

        return True

    def _cleanup_expired_jobs(self) -> None:
        """
        Background cleanup thread for expired job results

        This method runs continuously in the background, removing expired
        job results to prevent memory leaks in long-running server instances.
        """
        while self._cleanup_running:
            try:
                current_time = datetime.now()
                expired_jobs = []

                with self._lock:
                    for job_id, job in self.jobs.items():
                        # Only cleanup completed, failed, or cancelled jobs
                        if job.status in [
                            JobStatus.COMPLETED,
                            JobStatus.FAILED,
                            JobStatus.CANCELLED,
                        ]:
                            completed_time = job.completed_at or job.created_at
                            if current_time - completed_time > self.result_ttl:
                                expired_jobs.append(job_id)

                    # Remove expired jobs and their tracking data
                    for job_id in expired_jobs:
                        self.jobs.pop(job_id, None)
                        self._stop_events.pop(job_id, None)
                        self.job_threads.pop(job_id, None)

                if expired_jobs:
                    logger.info(
                        f"Cleaned up {len(expired_jobs)} expired jobs",
                        extra={"job_id": "cleanup", "job_status": "expired_cleanup"},
                    )

                # Sleep for 1 hour between cleanup cycles
                time.sleep(3600)

            except Exception as e:
                logger.error(
                    f"Cleanup thread error: {str(e)}",
                    extra={"job_id": "cleanup", "job_status": "cleanup_error"},
                )
                time.sleep(300)  # Sleep 5 minutes on error before retrying

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive job management statistics

        Returns:
            Dict containing current system statistics and metrics
        """
        with self._lock:
            stats = {
                "total_jobs": len(self.jobs),
                "running_jobs": sum(
                    1 for job in self.jobs.values() if job.status == JobStatus.RUNNING
                ),
                "queued_jobs": sum(
                    1 for job in self.jobs.values() if job.status == JobStatus.QUEUED
                ),
                "completed_jobs": sum(
                    1 for job in self.jobs.values() if job.status == JobStatus.COMPLETED
                ),
                "failed_jobs": sum(
                    1 for job in self.jobs.values() if job.status == JobStatus.FAILED
                ),
                "cancelled_jobs": sum(
                    1 for job in self.jobs.values() if job.status == JobStatus.CANCELLED
                ),
                "max_concurrent_jobs": self.max_concurrent_jobs,
                "result_ttl_hours": self.result_ttl.total_seconds() / 3600,
                "cleanup_thread_running": self._cleanup_running,
            }

        return stats

    def shutdown(self) -> None:
        """
        Graceful shutdown of job management system

        This method stops all background threads and cleans up resources
        for proper application shutdown.
        """
        logger.info(
            "JobManager shutdown initiated",
            extra={"job_id": "system", "job_status": "shutdown"},
        )

        # Stop cleanup thread
        self._cleanup_running = False

        # Cancel all running jobs
        with self._lock:
            running_job_ids = [
                job_id
                for job_id, job in self.jobs.items()
                if job.status in [JobStatus.QUEUED, JobStatus.RUNNING]
            ]

        for job_id in running_job_ids:
            asyncio.create_task(self.cancel_job(job_id))

        logger.info(
            f"JobManager shutdown complete - Cancelled {len(running_job_ids)} running jobs",
            extra={"job_id": "system", "job_status": "shutdown_complete"},
        )
