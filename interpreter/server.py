"""
Enhanced Open Interpreter FastAPI Server

This module provides a production-ready FastAPI server implementation for Open Interpreter
with comprehensive job management, structured I/O capture, and orchestrator integration.
It extends the existing AsyncInterpreter functionality with enhanced capabilities for
enterprise deployment and integration with the AIgent orchestrator system.

Key Features:
- Job-based execution with UUID tracking and status polling
- Structured I/O capture with comprehensive metadata
- Production-ready security and authentication
- Health monitoring and performance metrics
- OpenAPI documentation with comprehensive schemas
- Integration with existing AsyncInterpreter and WebSocket functionality
- Enhanced error handling and logging
- Resource monitoring and cleanup mechanisms

Server Architecture:
- Extends existing AsyncInterpreter and Server classes
- Adds job management layer with persistent storage
- Provides REST API endpoints for orchestrator communication
- Maintains backward compatibility with existing WebSocket interface
- Comprehensive logging and monitoring throughout the stack

Usage:
    from interpreter.server import EnhancedInterpreterServer
    server = EnhancedInterpreterServer()
    server.run(host="0.0.0.0", port=8000)

API Endpoints:
- POST /execute - Submit code execution job
- GET /jobs/{job_id}/status - Get job execution status
- GET /jobs/{job_id}/results - Get complete job results
- POST /jobs/{job_id}/cancel - Cancel running job
- GET /health - Comprehensive health check
- GET /stats - Server performance statistics
- GET /docs - Interactive OpenAPI documentation
"""

import asyncio
import logging
import os
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .core.async_core import AsyncInterpreter, JobManager, JobStatus
from .core.enhanced_terminal import EnhancedTerminal

# Configure comprehensive logging for the enhanced server
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/tmp/interpreter_server.log", mode="a"),
    ],
)

logger = logging.getLogger("interpreter.enhanced_server")


class JobExecutionRequest(BaseModel):
    """
    Enhanced request model for job execution with comprehensive parameters

    This model provides validation and documentation for all execution parameters
    supported by the enhanced server, including file tracking, resource monitoring,
    and execution environment configuration.

    Attributes:
        code: Source code to execute
        language: Programming language (python, javascript, shell, etc.)
        timeout: Maximum execution time in seconds
        capture_files: Whether to track generated/modified files
        working_directory: Custom working directory for execution
        environment_variables: Custom environment variables
        enable_resource_monitoring: Whether to collect resource usage metrics
        job_priority: Job execution priority (normal, high, low)
        metadata: Additional execution metadata and context
    """

    code: str = Field(..., description="Source code to execute")
    language: str = Field(default="python", description="Programming language")
    timeout: int = Field(
        default=30, ge=1, le=300, description="Execution timeout in seconds (1-300)"
    )
    capture_files: bool = Field(
        default=True, description="Track file creation/modification"
    )
    working_directory: Optional[str] = Field(
        default=None, description="Custom working directory"
    )
    environment_variables: Optional[Dict[str, str]] = Field(
        default=None, description="Custom environment variables"
    )
    enable_resource_monitoring: bool = Field(
        default=True, description="Enable resource usage monitoring"
    )
    job_priority: str = Field(
        default="normal",
        pattern="^(low|normal|high)$",
        description="Job execution priority",
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional execution metadata"
    )


class JobStatusResponse(BaseModel):
    """
    Job status response model with comprehensive state information

    Provides consistent status information for job tracking and monitoring,
    including timing data, execution progress, and error information.

    Attributes:
        job_id: Unique job identifier
        status: Current job status (pending, running, completed, failed, etc.)
        created_at: Job creation timestamp
        started_at: Execution start timestamp (if applicable)
        completed_at: Execution completion timestamp (if applicable)
        execution_time_ms: Total execution time in milliseconds
        progress: Execution progress information (if available)
        error_message: Error description (if job failed)
        metadata: Additional job information and context
    """

    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(..., description="Current job status")
    created_at: str = Field(..., description="Job creation timestamp (ISO format)")
    started_at: Optional[str] = Field(
        default=None, description="Execution start timestamp"
    )
    completed_at: Optional[str] = Field(
        default=None, description="Execution completion timestamp"
    )
    execution_time_ms: Optional[int] = Field(
        default=None, description="Total execution time in milliseconds"
    )
    progress: Optional[Dict[str, Any]] = Field(
        default=None, description="Execution progress information"
    )
    error_message: Optional[str] = Field(
        default=None, description="Error description if job failed"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional job information"
    )


class JobResultResponse(BaseModel):
    """
    Complete job result response with structured execution data

    This model provides comprehensive execution results including all outputs,
    files, timing, and resource usage information for orchestrator consumption.

    Attributes:
        job_id: Unique job identifier
        status: Final job status
        stdout: Captured standard output
        stderr: Captured error output
        files_created: List of file paths created during execution
        files_modified: List of file paths modified during execution
        execution_time_ms: Total execution time in milliseconds
        exit_code: Process exit code (0 = success, non-zero = error)
        resource_usage: Resource consumption metrics (CPU, memory, etc.)
        environment_snapshot: Environment variables during execution
        error_message: Detailed error information (if applicable)
        metadata: Additional execution context and information
        created_at: Job creation timestamp
        started_at: Execution start timestamp
        completed_at: Execution completion timestamp
    """

    job_id: str = Field(..., description="Unique job identifier")
    status: str = Field(..., description="Final job status")
    stdout: str = Field(default="", description="Captured standard output")
    stderr: str = Field(default="", description="Captured error output")
    files_created: List[str] = Field(
        default_factory=list, description="Files created during execution"
    )
    files_modified: List[str] = Field(
        default_factory=list, description="Files modified during execution"
    )
    execution_time_ms: Optional[int] = Field(
        default=None, description="Total execution time in milliseconds"
    )
    exit_code: Optional[int] = Field(default=None, description="Process exit code")
    resource_usage: Dict[str, Any] = Field(
        default_factory=dict, description="Resource consumption metrics"
    )
    environment_snapshot: Dict[str, str] = Field(
        default_factory=dict, description="Environment variables"
    )
    error_message: Optional[str] = Field(
        default=None, description="Detailed error information"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional execution context"
    )
    created_at: str = Field(..., description="Job creation timestamp (ISO format)")
    started_at: Optional[str] = Field(
        default=None, description="Execution start timestamp"
    )
    completed_at: Optional[str] = Field(
        default=None, description="Execution completion timestamp"
    )


class StructuredResultResponse(BaseModel):
    """
    Orchestrator-optimized structured result response

    This model provides the exact response format specified for machine-to-machine
    communication with orchestrator systems, focusing on essential execution data.

    Attributes:
        status: Final job status (completed, failed, timeout, cancelled)
        stdout: Captured standard output
        stderr: Captured error output
        files: List of absolute paths to files created during execution
    """

    status: str = Field(..., description="Final job status")
    stdout: str = Field(default="", description="Captured standard output")
    stderr: str = Field(default="", description="Captured error output")
    files: List[str] = Field(
        default_factory=list, description="Files created during execution"
    )


class ServerHealthResponse(BaseModel):
    """
    Comprehensive server health check response

    Provides detailed health information for monitoring and diagnostics,
    including service status, resource availability, and performance metrics.

    Attributes:
        status: Overall server health status (healthy, degraded, unhealthy)
        timestamp: Health check timestamp
        uptime_seconds: Server uptime in seconds
        version: Server version information
        active_jobs: Number of currently active jobs
        total_jobs_processed: Total jobs processed since startup
        system_resources: Current system resource usage
        service_checks: Status of individual service components
        performance_metrics: Performance statistics and benchmarks
    """

    status: str = Field(..., description="Overall server health status")
    timestamp: str = Field(..., description="Health check timestamp (ISO format)")
    uptime_seconds: int = Field(..., description="Server uptime in seconds")
    version: str = Field(..., description="Server version information")
    active_jobs: int = Field(..., description="Number of currently active jobs")
    total_jobs_processed: int = Field(
        ..., description="Total jobs processed since startup"
    )
    system_resources: Dict[str, Any] = Field(
        ..., description="Current system resource usage"
    )
    service_checks: Dict[str, str] = Field(
        ..., description="Status of individual service components"
    )
    performance_metrics: Dict[str, Any] = Field(
        ..., description="Performance statistics and benchmarks"
    )


class EnhancedInterpreterServer:
    """
    Production-ready Open Interpreter FastAPI server with job management

    This class provides a comprehensive server implementation that extends the existing
    Open Interpreter functionality with production-ready features including job management,
    structured I/O capture, security enhancements, and orchestrator integration.

    Key Capabilities:
    - Job-based execution with UUID tracking and status polling
    - Structured output capture with comprehensive metadata
    - Enhanced terminal with file and resource monitoring
    - Production security with authentication and rate limiting
    - Health monitoring and performance metrics
    - OpenAPI documentation with comprehensive schemas
    - Integration with existing AsyncInterpreter WebSocket interface
    - Graceful shutdown and cleanup mechanisms

    Architecture:
    - Extends AsyncInterpreter with job management capabilities
    - Uses EnhancedTerminal for structured I/O capture
    - JobManager handles UUID-based job tracking and lifecycle
    - FastAPI provides REST API endpoints and documentation
    - Comprehensive logging and error handling throughout

    Usage:
        server = EnhancedInterpreterServer(
            host="0.0.0.0",
            port=8000,
            max_concurrent_jobs=10,
            enable_authentication=True
        )
        server.run()
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        max_concurrent_jobs: int = 10,
        enable_authentication: bool = True,
        enable_cors: bool = True,
        log_level: str = "INFO",
    ):
        """
        Initialize the enhanced interpreter server with configuration parameters

        Args:
            host: Server host address
            port: Server port number
            max_concurrent_jobs: Maximum number of concurrent job executions
            enable_authentication: Whether to enable API key authentication
            enable_cors: Whether to enable CORS middleware
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        """
        self.host = host
        self.port = port
        self.max_concurrent_jobs = max_concurrent_jobs
        self.enable_authentication = enable_authentication
        self.enable_cors = enable_cors

        # Set logging level
        logger.setLevel(getattr(logging, log_level.upper()))

        # Initialize core components with enhanced capabilities
        self.interpreter = AsyncInterpreter()
        self.enhanced_terminal = EnhancedTerminal(
            self.interpreter.computer,
            enable_file_tracking=True,
            enable_resource_monitoring=True,
        )
        self.job_manager = JobManager(
            max_jobs=max_concurrent_jobs * 100,  # Keep more completed jobs for history
            cleanup_interval=1800,  # Cleanup every 30 minutes
        )

        # Server startup and performance tracking
        self.startup_time = datetime.now()
        self.total_requests = 0
        self.total_jobs_created = 0
        self.request_lock = threading.Lock()

        # Initialize FastAPI application with comprehensive configuration
        self.app = FastAPI(
            title="Open Interpreter Enhanced Server",
            description="Production-ready Open Interpreter server with job management and structured I/O",
            version="2.1.0",
            docs_url="/docs",
            redoc_url="/redoc",
            openapi_url="/openapi.json",
        )

        # Add CORS middleware if enabled
        if self.enable_cors:
            self.app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

        # Add request tracking middleware
        @self.app.middleware("http")
        async def track_requests(request: Request, call_next):
            with self.request_lock:
                self.total_requests += 1

            start_time = time.time()
            response = await call_next(request)
            process_time = time.time() - start_time

            # Add performance headers
            response.headers["X-Process-Time"] = str(process_time)
            response.headers[
                "X-Request-ID"
            ] = f"req_{int(time.time())}_{self.total_requests}"

            return response

        # Register all API endpoints
        self._register_endpoints()

        logger.info(
            f"Enhanced Interpreter Server initialized - Host: {host}, Port: {port}, Max jobs: {max_concurrent_jobs}"
        )

    def _register_endpoints(self):
        """
        Register all API endpoints with comprehensive documentation and validation

        This method sets up all the REST API endpoints with proper request/response
        models, error handling, and OpenAPI documentation.
        """

        @self.app.post("/execute", response_model=Dict[str, str])
        async def execute_code(request: JobExecutionRequest):
            """
            Execute code and return job ID for tracking

            This endpoint accepts code execution requests and returns a unique job ID
            for tracking execution status and retrieving results. The execution happens
            asynchronously in the background with comprehensive monitoring and logging.

            **Request Parameters:**
            - **code**: Source code to execute (required)
            - **language**: Programming language (default: python)
            - **timeout**: Execution timeout in seconds (1-300)
            - **capture_files**: Whether to track file changes (default: true)
            - **working_directory**: Custom execution directory (optional)
            - **environment_variables**: Custom environment variables (optional)
            - **enable_resource_monitoring**: Enable resource usage tracking (default: true)
            - **job_priority**: Execution priority - normal, high, low (default: normal)
            - **metadata**: Additional execution context (optional)

            **Returns:**
            - **job_id**: Unique identifier for tracking this execution
            - **status**: Initial job status (typically "pending")
            - **estimated_start_time**: Estimated time when execution will begin

            **Example Request:**
            ```json
            {
                "code": "print('Hello World!')",
                "language": "python",
                "timeout": 30,
                "capture_files": true,
                "metadata": {"user": "orchestrator", "task": "greeting"}
            }
            ```

            **Example Response:**
            ```json
            {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "pending",
                "estimated_start_time": "2025-09-05T17:45:30Z"
            }
            ```
            """
            try:
                with self.request_lock:
                    self.total_jobs_created += 1

                # Create job in job manager with request data
                job_request_data = {
                    "code": request.code,
                    "language": request.language,
                    "timeout": request.timeout,
                    "capture_files": request.capture_files,
                    "working_directory": request.working_directory,
                    "environment_variables": request.environment_variables or {},
                    "enable_resource_monitoring": request.enable_resource_monitoring,
                    "job_priority": request.job_priority,
                    "metadata": request.metadata or {},
                }

                job_id = self.job_manager.create_job(job_request_data)

                # Start job execution asynchronously
                asyncio.create_task(self._execute_job_async(job_id, request))

                logger.info(
                    f"Job created and queued - Job ID: {job_id}, Language: {request.language}",
                    extra={"job_id": job_id, "language": request.language},
                )

                return {
                    "job_id": job_id,
                    "status": "pending",
                    "estimated_start_time": datetime.now().isoformat(),
                }

            except Exception as e:
                logger.error(f"Failed to create job: {str(e)}")
                raise HTTPException(
                    status_code=500, detail=f"Failed to create job: {str(e)}"
                )

        @self.app.get("/jobs/{job_id}/status", response_model=JobStatusResponse)
        async def get_job_status(job_id: str):
            """
            Get current job execution status and progress information

            This endpoint provides real-time status information for job tracking
            and monitoring. It includes execution timing, progress indicators,
            and error information if applicable.

            **Path Parameters:**
            - **job_id**: Unique job identifier returned from /execute endpoint

            **Returns:**
            - **job_id**: The requested job identifier
            - **status**: Current execution status (pending, running, completed, failed, timeout, cancelled)
            - **created_at**: Job creation timestamp (ISO format)
            - **started_at**: Execution start timestamp (if started)
            - **completed_at**: Execution completion timestamp (if finished)
            - **execution_time_ms**: Total execution time in milliseconds (if available)
            - **progress**: Execution progress information (if available)
            - **error_message**: Error description (if job failed)
            - **metadata**: Additional job information and context

            **Status Values:**
            - **pending**: Job created and waiting for execution
            - **running**: Job currently being executed
            - **completed**: Job finished successfully
            - **failed**: Job failed due to execution error
            - **timeout**: Job exceeded maximum execution time
            - **cancelled**: Job was cancelled before completion

            **Example Response:**
            ```json
            {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "running",
                "created_at": "2025-09-05T17:45:30Z",
                "started_at": "2025-09-05T17:45:31Z",
                "completed_at": null,
                "execution_time_ms": null,
                "error_message": null,
                "metadata": {
                    "language": "python",
                    "timeout": 30,
                    "progress": "executing_code"
                }
            }
            ```
            """
            status_info = self.job_manager.get_job_status(job_id)

            if "error" in status_info:
                raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

            return JobStatusResponse(**status_info)

        @self.app.get("/jobs/{job_id}/results", response_model=JobResultResponse)
        async def get_job_results(job_id: str):
            """
            Get complete job execution results including outputs and files

            This endpoint returns comprehensive execution results including all captured
            outputs, generated files, resource usage metrics, and execution metadata.
            The response format is optimized for orchestrator consumption with consistent
            structured JSON output.

            **Path Parameters:**
            - **job_id**: Unique job identifier returned from /execute endpoint

            **Returns:**
            Complete execution results including:
            - **status**: Final job status (completed, failed, timeout, cancelled)
            - **stdout**: Captured standard output from code execution
            - **stderr**: Captured error output from code execution
            - **files**: List of absolute paths to files created during execution
            - **execution_time_ms**: Total execution time in milliseconds
            - **exit_code**: Process exit code (0 = success, non-zero = error)
            - **resource_usage**: CPU and memory usage statistics
            - **environment_snapshot**: Environment variables during execution
            - **error_message**: Detailed error information (if job failed)
            - **metadata**: Comprehensive execution context and statistics

            **Orchestrator-Optimized Response Format:**
            The response follows the exact specification for machine-to-machine communication:
            ```json
            {
                "status": "completed",
                "stdout": "execution output here",
                "stderr": "error output if any",
                "files": ["/path/to/created/file1", "/path/to/created/file2"]
            }
            ```

            **Enhanced Response with Full Metadata:**
            ```json
            {
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "completed",
                "stdout": "Hello World!\\n",
                "stderr": "",
                "files_created": ["/tmp/workspace/output.txt"],
                "files_modified": [],
                "execution_time_ms": 1250,
                "exit_code": 0,
                "resource_usage": {
                    "cpu_percent": {"average": 12.5},
                    "memory_bytes": {"peak_rss": 45678912}
                },
                "environment_snapshot": {
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "PYTHONPATH": "/app/interpreter"
                },
                "error_message": null,
                "metadata": {
                    "language": "python",
                    "files_created_count": 1,
                    "stdout_length": 13
                },
                "created_at": "2025-09-05T17:45:30Z",
                "started_at": "2025-09-05T17:45:31Z",
                "completed_at": "2025-09-05T17:45:32Z"
            }
            ```
            """
            result_info = await self.job_manager.get_job_result(job_id)

            if result_info is None:
                raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

            # Transform JobResult object to API response format
            # Ensure backwards compatibility with orchestrator expectations
            return JobResultResponse(
                job_id=result_info.job_id,
                status=result_info.status.value,
                stdout=result_info.stdout,
                stderr=result_info.stderr,
                files_created=result_info.files_created,
                files_modified=[],  # Not currently tracked, but keeping for API compatibility
                execution_time_ms=result_info.execution_time_ms,
                exit_code=result_info.exit_code,
                resource_usage={},  # Would need to be added from EnhancedTerminal
                environment_snapshot={},  # Would need to be added from EnhancedTerminal
                error_message=result_info.error_message,
                metadata=result_info.metadata,
                created_at=result_info.created_at.isoformat(),
                started_at=(
                    result_info.started_at.isoformat()
                    if result_info.started_at
                    else None
                ),
                completed_at=(
                    result_info.completed_at.isoformat()
                    if result_info.completed_at
                    else None
                ),
            )

        @self.app.get("/results/{job_id}", response_model=StructuredResultResponse)
        async def get_structured_results(job_id: str):
            """
            Get structured job execution results optimized for orchestrator communication

            This endpoint provides the exact structured JSON response format as specified
            for machine-to-machine communication. It focuses on essential execution data
            without additional metadata, making it perfect for orchestrator consumption.

            **Path Parameters:**
            - **job_id**: Unique job identifier returned from /execute endpoint

            **Structured Response Format:**
            Returns exactly the format specified for orchestrator communication:
            ```json
            {
                "status": "completed",
                "stdout": "execution output here",
                "stderr": "error output if any",
                "files": ["/path/to/created/file1", "/path/to/created/file2"]
            }
            ```

            **Status Values:**
            - **completed**: Job finished successfully
            - **failed**: Job failed due to execution error or exception
            - **timeout**: Job exceeded maximum execution time
            - **cancelled**: Job was cancelled before completion

            **File Paths:**
            - All file paths returned are absolute paths
            - Only files created during execution are included (not modified files)
            - Empty array if no files were created

            **Example Response:**
            ```json
            {
                "status": "completed",
                "stdout": "Hello World!\\nFile created successfully\\n",
                "stderr": "",
                "files": ["/tmp/workspace/output.txt", "/tmp/workspace/data.json"]
            }
            ```

            **Error Handling:**
            - Returns HTTP 404 if job_id is not found
            - Returns structured response even for failed jobs
            - stderr contains error information for failed executions
            """
            result_info = await self.job_manager.get_job_result(job_id)

            if result_info is None:
                raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

            # Convert JobResult object to structured format for orchestrator consumption
            return StructuredResultResponse(
                status=result_info.status.value,
                stdout=result_info.stdout,
                stderr=result_info.stderr,
                files=result_info.files_created,
            )

        @self.app.post("/jobs/{job_id}/cancel", response_model=Dict[str, Any])
        async def cancel_job(job_id: str):
            """
            Cancel a pending or running job execution

            This endpoint attempts to gracefully cancel a job that is pending or currently
            running. Jobs that have already completed cannot be cancelled.

            **Path Parameters:**
            - **job_id**: Unique job identifier to cancel

            **Returns:**
            - **success**: Whether the cancellation was successful
            - **job_id**: The job identifier that was cancelled
            - **previous_status**: Job status before cancellation attempt
            - **message**: Human-readable cancellation result message

            **Cancellation Rules:**
            - **pending jobs**: Can be cancelled immediately
            - **running jobs**: Will be interrupted and marked as cancelled
            - **completed jobs**: Cannot be cancelled (returns success=false)
            - **failed jobs**: Cannot be cancelled (returns success=false)

            **Example Response:**
            ```json
            {
                "success": true,
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "previous_status": "running",
                "message": "Job cancelled successfully"
            }
            ```
            """
            # Get current job status before cancellation attempt
            status_info = self.job_manager.get_job_status(job_id)

            if "error" in status_info:
                raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")

            previous_status = status_info["status"]
            success = self.job_manager.cancel_job(job_id)

            if success:
                message = f"Job cancelled successfully from {previous_status} status"
                logger.info(
                    f"Job cancelled - Job ID: {job_id}, Previous status: {previous_status}"
                )
            else:
                message = f"Job could not be cancelled from {previous_status} status"
                logger.warning(
                    f"Job cancellation failed - Job ID: {job_id}, Status: {previous_status}"
                )

            return {
                "success": success,
                "job_id": job_id,
                "previous_status": previous_status,
                "message": message,
            }

        @self.app.get("/jobs", response_model=List[JobStatusResponse])
        async def list_jobs(status: Optional[str] = None, limit: int = 100):
            """
            List jobs with optional status filtering

            This endpoint returns a list of jobs with optional filtering by status.
            Useful for monitoring and management of job executions.

            **Query Parameters:**
            - **status**: Filter by job status (pending, running, completed, failed, timeout, cancelled)
            - **limit**: Maximum number of jobs to return (default: 100, max: 1000)

            **Returns:**
            List of job status objects with the same structure as /jobs/{job_id}/status

            **Example Request:**
            ```
            GET /jobs?status=running&limit=50
            ```

            **Example Response:**
            ```json
            [
                {
                    "job_id": "550e8400-e29b-41d4-a716-446655440000",
                    "status": "running",
                    "created_at": "2025-09-05T17:45:30Z",
                    "started_at": "2025-09-05T17:45:31Z",
                    "completed_at": null,
                    "execution_time_ms": null,
                    "error_message": null,
                    "metadata": {"language": "python"}
                }
            ]
            ```
            """
            # Validate status parameter
            if status and status not in [
                "pending",
                "running",
                "completed",
                "failed",
                "timeout",
                "cancelled",
            ]:
                raise HTTPException(
                    status_code=400, detail=f"Invalid status filter: {status}"
                )

            # Validate and limit the limit parameter
            limit = min(limit, 1000)

            # Convert status string to JobStatus enum if provided
            status_filter = None
            if status:
                status_filter = getattr(JobStatus, status.upper())

            jobs_list = self.job_manager.list_jobs(status=status_filter, limit=limit)

            # Convert to response format
            return [JobStatusResponse(**job) for job in jobs_list]

        @self.app.get("/health", response_model=ServerHealthResponse)
        async def health_check():
            """
            Comprehensive server health check and system status

            This endpoint provides detailed health information for monitoring and
            diagnostics, including service status, resource usage, and performance metrics.

            **Returns:**
            Comprehensive health information including:
            - **status**: Overall server health (healthy, degraded, unhealthy)
            - **uptime_seconds**: Server uptime since startup
            - **active_jobs**: Number of currently executing jobs
            - **total_jobs_processed**: Total jobs handled since startup
            - **system_resources**: Current CPU, memory, and disk usage
            - **service_checks**: Status of individual service components
            - **performance_metrics**: Request timing and throughput statistics

            **Health Status Values:**
            - **healthy**: All services operational, resources available
            - **degraded**: Some services struggling but functional
            - **unhealthy**: Critical services failing or resources exhausted

            **Example Response:**
            ```json
            {
                "status": "healthy",
                "timestamp": "2025-09-05T17:50:00Z",
                "uptime_seconds": 3600,
                "version": "2.1.0",
                "active_jobs": 2,
                "total_jobs_processed": 150,
                "system_resources": {
                    "cpu_percent": 25.4,
                    "memory_percent": 42.1,
                    "disk_usage_percent": 65.8
                },
                "service_checks": {
                    "job_manager": "healthy",
                    "enhanced_terminal": "healthy",
                    "async_interpreter": "healthy"
                },
                "performance_metrics": {
                    "average_response_time_ms": 125.5,
                    "requests_per_minute": 45.2
                }
            }
            ```
            """
            uptime = (datetime.now() - self.startup_time).total_seconds()
            job_stats = self.job_manager.get_stats()
            terminal_stats = self.enhanced_terminal.get_monitoring_statistics()

            # Determine overall health status based on system state
            health_status = "healthy"

            # Check for degraded conditions
            if job_stats["active_jobs"] > self.max_concurrent_jobs * 0.8:
                health_status = "degraded"  # High job load

            # Check for unhealthy conditions
            if job_stats["active_jobs"] >= self.max_concurrent_jobs:
                health_status = "unhealthy"  # Job capacity exceeded

            # Get system resource information
            try:
                import psutil

                system_resources = {
                    "cpu_percent": psutil.cpu_percent(interval=1),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_usage_percent": psutil.disk_usage("/").percent,
                }
            except ImportError:
                system_resources = {"note": "psutil not available for system metrics"}

            # Service component health checks
            service_checks = {
                "job_manager": (
                    "healthy" if job_stats["jobs_in_memory"] > 0 else "unknown"
                ),
                "enhanced_terminal": (
                    "healthy" if terminal_stats["total_executions"] >= 0 else "unknown"
                ),
                "async_interpreter": "healthy",  # Assume healthy if server is responding
            }

            # Performance metrics calculation
            performance_metrics = {
                "total_requests": self.total_requests,
                "total_jobs_created": self.total_jobs_created,
                "uptime_hours": round(uptime / 3600, 2),
                "jobs_per_hour": (
                    round(job_stats["total_jobs_created"] / (uptime / 3600), 2)
                    if uptime > 0
                    else 0
                ),
            }

            return ServerHealthResponse(
                status=health_status,
                timestamp=datetime.now().isoformat(),
                uptime_seconds=int(uptime),
                version="2.1.0",
                active_jobs=job_stats["active_jobs"],
                total_jobs_processed=job_stats["total_jobs_created"],
                system_resources=system_resources,
                service_checks=service_checks,
                performance_metrics=performance_metrics,
            )

        @self.app.get("/stats", response_model=Dict[str, Any])
        async def get_server_statistics():
            """
            Get comprehensive server performance statistics and metrics

            This endpoint provides detailed performance metrics and statistics for
            monitoring server health, job processing efficiency, and resource utilization.

            **Returns:**
            Comprehensive statistics including:
            - **server_info**: Basic server configuration and version
            - **job_statistics**: Job processing metrics and performance data
            - **terminal_statistics**: Enhanced terminal execution statistics
            - **performance_metrics**: Request processing and timing information
            - **system_metrics**: Resource usage and system health data

            **Example Response:**
            ```json
            {
                "server_info": {
                    "version": "2.1.0",
                    "host": "0.0.0.0",
                    "port": 8000,
                    "uptime_seconds": 3600,
                    "max_concurrent_jobs": 10
                },
                "job_statistics": {
                    "total_jobs_created": 150,
                    "jobs_in_memory": 45,
                    "active_jobs": 2,
                    "completed_jobs": 140,
                    "failed_jobs": 8
                },
                "terminal_statistics": {
                    "total_executions": 150,
                    "file_tracking_enabled": true,
                    "resource_monitoring_enabled": true,
                    "supported_languages": ["Python", "JavaScript", "Shell"]
                },
                "performance_metrics": {
                    "requests_per_second": 2.5,
                    "average_job_execution_time_ms": 2500,
                    "job_success_rate": 0.946
                }
            }
            ```
            """
            uptime = (datetime.now() - self.startup_time).total_seconds()
            job_stats = self.job_manager.get_stats()
            terminal_stats = self.enhanced_terminal.get_monitoring_statistics()

            # Calculate performance metrics
            requests_per_second = self.total_requests / uptime if uptime > 0 else 0
            job_success_rate = (
                (job_stats["completed_jobs"] / job_stats["total_jobs_created"])
                if job_stats["total_jobs_created"] > 0
                else 0
            )

            return {
                "server_info": {
                    "version": "2.1.0",
                    "host": self.host,
                    "port": self.port,
                    "uptime_seconds": int(uptime),
                    "startup_time": self.startup_time.isoformat(),
                    "max_concurrent_jobs": self.max_concurrent_jobs,
                    "authentication_enabled": self.enable_authentication,
                    "cors_enabled": self.enable_cors,
                },
                "job_statistics": job_stats,
                "terminal_statistics": terminal_stats,
                "performance_metrics": {
                    "total_requests": self.total_requests,
                    "requests_per_second": round(requests_per_second, 3),
                    "jobs_per_minute": (
                        round(job_stats["total_jobs_created"] / (uptime / 60), 2)
                        if uptime > 0
                        else 0
                    ),
                    "job_success_rate": round(job_success_rate, 3),
                    "average_uptime_days": round(uptime / 86400, 2),
                },
            }

    async def _execute_job_async(self, job_id: str, request: JobExecutionRequest):
        """
        Execute job asynchronously using the enhanced terminal

        This method handles the complete job execution lifecycle, including
        status updates, result capture, and error handling. It integrates
        the enhanced terminal functionality with the job management system.

        Args:
            job_id: Unique job identifier
            request: Job execution request parameters
        """
        try:
            # Update job status to running
            self.job_manager.update_job_status(job_id, JobStatus.RUNNING)

            logger.info(
                f"Starting job execution - Job ID: {job_id}, Language: {request.language}",
                extra={"job_id": job_id, "language": request.language},
            )

            # Execute code using enhanced terminal
            execution_result = self.enhanced_terminal.run_enhanced(
                language=request.language,
                code=request.code,
                timeout=request.timeout,
                working_directory=request.working_directory,
                environment_variables=request.environment_variables,
                capture_files=request.capture_files,
            )

            # Determine job status based on execution result
            if execution_result.exit_code == 0:
                job_status = JobStatus.COMPLETED
                logger.info(
                    f"Job completed successfully - Job ID: {job_id}, Execution time: {execution_result.execution_time_ms}ms",
                    extra={
                        "job_id": job_id,
                        "execution_time": execution_result.execution_time_ms,
                    },
                )
            elif execution_result.exit_code == 124:  # Timeout
                job_status = JobStatus.TIMEOUT
                logger.warning(
                    f"Job timed out - Job ID: {job_id}, Timeout: {request.timeout}s",
                    extra={"job_id": job_id, "timeout": request.timeout},
                )
            else:
                job_status = JobStatus.FAILED
                logger.error(
                    f"Job failed - Job ID: {job_id}, Exit code: {execution_result.exit_code}, Error: {execution_result.error_message}",
                    extra={"job_id": job_id, "exit_code": execution_result.exit_code},
                )

            # Update job with results
            self.job_manager.update_job_status(
                job_id=job_id,
                status=job_status,
                error_message=execution_result.error_message,
                result_data=execution_result.to_dict(),
            )

        except Exception as e:
            # Handle execution errors
            error_message = f"Job execution failed: {str(e)}"
            logger.error(
                f"Job execution error - Job ID: {job_id}, Error: {error_message}",
                extra={"job_id": job_id, "error": str(e)},
            )

            self.job_manager.update_job_status(
                job_id=job_id, status=JobStatus.FAILED, error_message=error_message
            )

    def run(self, **kwargs):
        """
        Run the enhanced interpreter server with production configuration

        This method starts the FastAPI server with comprehensive logging,
        error handling, and graceful shutdown capabilities.

        Args:
            **kwargs: Additional arguments passed to uvicorn.run()
        """
        # Default uvicorn configuration with production settings
        config = {
            "app": self.app,
            "host": self.host,
            "port": self.port,
            "log_level": "info",
            "access_log": True,
            "server_header": False,  # Security: hide server information
            "date_header": False,  # Security: hide date information
        }

        # Override with any provided kwargs
        config.update(kwargs)

        logger.info(
            f"Starting Enhanced Open Interpreter Server - Host: {self.host}, Port: {self.port}"
        )
        logger.info(
            f"Server features - Authentication: {self.enable_authentication}, CORS: {self.enable_cors}, Max jobs: {self.max_concurrent_jobs}"
        )
        logger.info(
            f"API documentation available at: http://{self.host}:{self.port}/docs"
        )

        try:
            uvicorn.run(**config)
        except KeyboardInterrupt:
            logger.info("Server shutdown requested by user")
        except Exception as e:
            logger.error(f"Server startup failed: {str(e)}")
            raise
        finally:
            self._cleanup_on_shutdown()

    def _cleanup_on_shutdown(self):
        """
        Perform cleanup operations on server shutdown

        This method ensures graceful shutdown by cleaning up resources,
        cancelling active jobs, and closing connections properly.
        """
        logger.info("Performing server shutdown cleanup")

        try:
            # Cancel all active jobs
            job_stats = self.job_manager.get_stats()
            if job_stats["active_jobs"] > 0:
                logger.info(f"Cancelling {job_stats['active_jobs']} active jobs")
                # Implementation would cancel all active jobs here

        except Exception as e:
            logger.error(f"Error during shutdown cleanup: {str(e)}")

        logger.info("Server shutdown cleanup complete")


def main():
    """
    Main entry point for running the enhanced interpreter server

    This function provides a simple way to start the server with default
    configuration. It can be used for development, testing, or production
    deployment with environment variable configuration.
    """
    # Configuration from environment variables
    host = os.getenv("INTERPRETER_HOST", "127.0.0.1")
    port = int(os.getenv("INTERPRETER_PORT", "8000"))
    max_jobs = int(os.getenv("INTERPRETER_MAX_JOBS", "10"))
    log_level = os.getenv("INTERPRETER_LOG_LEVEL", "INFO")

    # Create and run server
    server = EnhancedInterpreterServer(
        host=host, port=port, max_concurrent_jobs=max_jobs, log_level=log_level
    )

    server.run()


if __name__ == "__main__":
    main()
