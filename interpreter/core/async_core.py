import asyncio
import json
import os
import shutil
import socket
import threading
import time
import traceback
import uuid
from collections import deque
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import shortuuid
from pydantic import BaseModel, Field
from starlette.websockets import WebSocketState

from .core import OpenInterpreter

last_start_time = 0

try:
    import janus
    import uvicorn
    from fastapi import APIRouter, FastAPI, File, Form, Request, UploadFile, WebSocket
    from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
    from starlette.status import HTTP_403_FORBIDDEN
except:
    # Server dependencies are not required by the main package.
    pass


complete_message = {"role": "server", "type": "status", "content": "complete"}


class JobStatus(str, Enum):
    """
    Enumeration of possible job statuses for tracking execution lifecycle.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class Job(BaseModel):
    """
    Data model representing a job with execution tracking information.
    """

    id: str = Field(..., description="Unique job identifier")
    status: JobStatus = Field(
        default=JobStatus.PENDING, description="Current job status"
    )
    created_at: datetime = Field(
        default_factory=datetime.now, description="Job creation timestamp"
    )
    started_at: Optional[datetime] = Field(
        default=None, description="Job execution start timestamp"
    )
    completed_at: Optional[datetime] = Field(
        default=None, description="Job completion timestamp"
    )
    request_data: Dict[str, Any] = Field(
        default_factory=dict, description="Original request data"
    )
    result_data: Dict[str, Any] = Field(
        default_factory=dict, description="Job execution results"
    )
    error_message: Optional[str] = Field(
        default=None, description="Error message if job failed"
    )
    execution_time_ms: Optional[int] = Field(
        default=None, description="Total execution time in milliseconds"
    )

    class Config:
        use_enum_values = True


class ExecuteRequest(BaseModel):
    """
    Request model for code execution jobs.
    """

    code: str = Field(..., description="Code to execute")
    language: str = Field(default="python", description="Programming language")
    timeout: Optional[int] = Field(
        default=30, description="Execution timeout in seconds"
    )
    capture_files: bool = Field(
        default=True, description="Whether to capture created files"
    )
    working_directory: Optional[str] = Field(
        default=None, description="Working directory for execution"
    )


class JobManager:
    """
    Manages job lifecycle, tracking, and storage for AsyncInterpreter execution.
    Provides UUID-based job tracking with in-memory storage and cleanup mechanisms.
    """

    def __init__(self, max_jobs: int = 1000, cleanup_interval: int = 3600):
        """
        Initialize JobManager with configurable limits and cleanup.

        Args:
            max_jobs: Maximum number of jobs to keep in memory
            cleanup_interval: Interval in seconds for automatic cleanup
        """
        self.jobs: Dict[str, Job] = {}
        self.max_jobs = max_jobs
        self.cleanup_interval = cleanup_interval
        self._lock = threading.RLock()
        self._last_cleanup = datetime.now()

        # Performance tracking
        self._job_count = 0
        self._completed_jobs = 0
        self._failed_jobs = 0

    def create_job(self, request_data: Dict[str, Any]) -> str:
        """
        Create a new job with unique UUID and track it.

        Args:
            request_data: Original request data for the job

        Returns:
            str: Unique job ID
        """
        job_id = str(uuid.uuid4())

        with self._lock:
            job = Job(id=job_id, status=JobStatus.PENDING, request_data=request_data)

            self.jobs[job_id] = job
            self._job_count += 1

            # Trigger cleanup if needed
            self._cleanup_if_needed()

            return job_id

    def get_job(self, job_id: str) -> Optional[Job]:
        """
        Retrieve job by ID.

        Args:
            job_id: Job identifier

        Returns:
            Job object or None if not found
        """
        with self._lock:
            return self.jobs.get(job_id)

    def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        error_message: str = None,
        result_data: Dict[str, Any] = None,
    ) -> bool:
        """
        Update job status and associated metadata.

        Args:
            job_id: Job identifier
            status: New job status
            error_message: Error message if job failed
            result_data: Results if job completed

        Returns:
            bool: True if update successful, False if job not found
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return False

            old_status = job.status
            job.status = status

            # Update timestamps based on status transitions
            now = datetime.now()
            if old_status == JobStatus.PENDING and status == JobStatus.RUNNING:
                job.started_at = now
            elif status in [
                JobStatus.COMPLETED,
                JobStatus.FAILED,
                JobStatus.TIMEOUT,
                JobStatus.CANCELLED,
            ]:
                job.completed_at = now
                if job.started_at:
                    job.execution_time_ms = int(
                        (now - job.started_at).total_seconds() * 1000
                    )

            # Update result data and error messages
            if error_message:
                job.error_message = error_message
            if result_data:
                job.result_data = result_data

            # Update counters
            if status == JobStatus.COMPLETED:
                self._completed_jobs += 1
            elif status == JobStatus.FAILED:
                self._failed_jobs += 1

            return True

    def get_job_status(self, job_id: str) -> Dict[str, Any]:
        """
        Get comprehensive job status information.

        Args:
            job_id: Job identifier

        Returns:
            dict: Job status information or error if not found
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return {"error": "Job not found", "job_id": job_id}

            return {
                "job_id": job.id,
                "status": job.status,
                "created_at": job.created_at.isoformat(),
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": (
                    job.completed_at.isoformat() if job.completed_at else None
                ),
                "execution_time_ms": job.execution_time_ms,
                "error_message": job.error_message,
            }

    def get_job_result(self, job_id: str) -> Dict[str, Any]:
        """
        Get complete job results including output data.

        Args:
            job_id: Job identifier

        Returns:
            dict: Complete job information including results
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return {"error": "Job not found", "job_id": job_id}

            result = {
                "job_id": job.id,
                "status": job.status,
                "created_at": job.created_at.isoformat(),
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "completed_at": (
                    job.completed_at.isoformat() if job.completed_at else None
                ),
                "execution_time_ms": job.execution_time_ms,
                "error_message": job.error_message,
                "request_data": job.request_data,
                "result_data": job.result_data,
            }

            return result

    def list_jobs(
        self, status: Optional[JobStatus] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        List jobs with optional status filtering.

        Args:
            status: Filter by job status (optional)
            limit: Maximum number of jobs to return

        Returns:
            list: List of job status information
        """
        with self._lock:
            jobs = list(self.jobs.values())

            # Filter by status if specified
            if status:
                jobs = [job for job in jobs if job.status == status]

            # Sort by creation time (newest first) and limit
            jobs.sort(key=lambda x: x.created_at, reverse=True)
            jobs = jobs[:limit]

            # Convert to status dict format
            return [self.get_job_status(job.id) for job in jobs]

    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or running job.

        Args:
            job_id: Job identifier

        Returns:
            bool: True if cancellation successful, False otherwise
        """
        with self._lock:
            job = self.jobs.get(job_id)
            if not job:
                return False

            # Only cancel if job is pending or running
            if job.status in [JobStatus.PENDING, JobStatus.RUNNING]:
                self.update_job_status(job_id, JobStatus.CANCELLED)
                return True

            return False

    def cleanup_completed_jobs(self, max_age_hours: int = 24) -> int:
        """
        Clean up old completed jobs to manage memory usage.

        Args:
            max_age_hours: Maximum age in hours for completed jobs

        Returns:
            int: Number of jobs cleaned up
        """
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        cleaned_count = 0

        with self._lock:
            jobs_to_remove = []

            for job_id, job in self.jobs.items():
                # Remove completed/failed jobs older than cutoff
                if (
                    job.status
                    in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]
                    and job.completed_at
                    and job.completed_at < cutoff_time
                ):
                    jobs_to_remove.append(job_id)

            # Remove oldest jobs if we exceed max_jobs limit
            if len(self.jobs) > self.max_jobs:
                all_jobs = sorted(self.jobs.values(), key=lambda x: x.created_at)
                excess_count = len(self.jobs) - self.max_jobs
                for i in range(excess_count):
                    if all_jobs[i].id not in jobs_to_remove:
                        jobs_to_remove.append(all_jobs[i].id)

            # Perform cleanup
            for job_id in jobs_to_remove:
                if job_id in self.jobs:
                    del self.jobs[job_id]
                    cleaned_count += 1

            self._last_cleanup = datetime.now()

        return cleaned_count

    def _cleanup_if_needed(self) -> None:
        """
        Perform cleanup if enough time has passed since last cleanup.
        """
        now = datetime.now()
        if (now - self._last_cleanup).total_seconds() > self.cleanup_interval:
            self.cleanup_completed_jobs()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get performance and usage statistics.

        Returns:
            dict: Job manager statistics
        """
        with self._lock:
            active_jobs = sum(
                1
                for job in self.jobs.values()
                if job.status in [JobStatus.PENDING, JobStatus.RUNNING]
            )

            return {
                "total_jobs_created": self._job_count,
                "jobs_in_memory": len(self.jobs),
                "active_jobs": active_jobs,
                "completed_jobs": self._completed_jobs,
                "failed_jobs": self._failed_jobs,
                "last_cleanup": self._last_cleanup.isoformat(),
            }


class AsyncInterpreter(OpenInterpreter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.respond_thread = None
        self.stop_event = threading.Event()
        self.output_queue = None
        self.unsent_messages = deque()
        self.id = os.getenv("INTERPRETER_ID", str(uuid.uuid4()))
        self.print = False  # Will print output

        self.require_acknowledge = (
            os.getenv("INTERPRETER_REQUIRE_ACKNOWLEDGE", "False").lower() == "true"
        )
        self.acknowledged_outputs = []

        # Initialize job management system
        self.job_manager = JobManager(
            max_jobs=int(os.getenv("INTERPRETER_MAX_JOBS", "1000")),
            cleanup_interval=int(os.getenv("INTERPRETER_CLEANUP_INTERVAL", "3600")),
        )

        # Job execution tracking
        self.current_job_id = None
        self.job_output_buffer = []

        self.server = Server(self)

        # For the 01. This lets the OAI compatible server accumulate context before responding.
        self.context_mode = False

    async def input(self, chunk):
        """
        Accumulates LMC chunks onto interpreter.messages.
        When it hits an "end" flag, calls interpreter.respond().
        """

        if "start" in chunk:
            # If the user is starting something, the interpreter should stop.
            if self.respond_thread is not None and self.respond_thread.is_alive():
                self.stop_event.set()
                self.respond_thread.join()
            self.accumulate(chunk)
        elif "content" in chunk:
            self.accumulate(chunk)
        elif "end" in chunk:
            # If the user is done talking, the interpreter should respond.

            run_code = None  # Will later default to auto_run unless the user makes a command here

            # But first, process any commands.
            if self.messages[-1].get("type") == "command":
                command = self.messages[-1]["content"]
                self.messages = self.messages[:-1]

                if command == "stop":
                    # Any start flag would have stopped it a moment ago, but to be sure:
                    self.stop_event.set()
                    self.respond_thread.join()
                    return
                if command == "go":
                    # This is to approve code.
                    run_code = True
                    pass

            self.stop_event.clear()
            self.respond_thread = threading.Thread(
                target=self.respond, args=(run_code,)
            )
            self.respond_thread.start()

    async def output(self):
        if self.output_queue == None:
            self.output_queue = janus.Queue()
        return await self.output_queue.async_q.get()

    def respond(self, run_code=None, job_id=None):
        """
        Enhanced respond method with job tracking and structured output capture.

        Args:
            run_code: Whether to automatically run code
            job_id: Job ID for tracking this execution
        """

        # Initialize job tracking if job_id provided
        if job_id:
            self.current_job_id = job_id
            self.job_output_buffer = []
            self.job_manager.update_job_status(job_id, JobStatus.RUNNING)
        for attempt in range(5):  # 5 attempts
            try:
                if run_code == None:
                    run_code = self.auto_run

                sent_chunks = False

                for chunk_og in self._respond_and_store():
                    chunk = (
                        chunk_og.copy()
                    )  # This fixes weird double token chunks. Probably a deeper problem?

                    if chunk["type"] == "confirmation":
                        if run_code:
                            run_code = False
                            continue
                        else:
                            break

                    if self.stop_event.is_set():
                        return

                    if self.print:
                        if "start" in chunk:
                            print("\n")
                        if chunk["type"] in ["code", "console"] and "format" in chunk:
                            if "start" in chunk:
                                print(
                                    "\n------------\n\n```" + chunk["format"],
                                    flush=True,
                                )
                            if "end" in chunk:
                                print("\n```\n\n------------\n\n", flush=True)
                        if chunk.get("format") != "active_line":
                            if "format" in chunk and "base64" in chunk["format"]:
                                print("\n[An image was produced]")
                            else:
                                content = chunk.get("content", "")
                                content = (
                                    str(content)
                                    .encode("ascii", "ignore")
                                    .decode("ascii")
                                )
                                print(content, end="", flush=True)

                    if self.debug:
                        print("Interpreter produced this chunk:", chunk)

                    self.output_queue.sync_q.put(chunk)
                    sent_chunks = True

                    # Capture job output for structured results
                    if self.current_job_id:
                        self._capture_job_output(chunk)

                if not sent_chunks:
                    print("ERROR. NO CHUNKS SENT. TRYING AGAIN.")
                    print("Messages:", self.messages)
                    messages = [
                        "Hello? Answer please.",
                        "Just say something, anything.",
                        "Are you there?",
                        "Can you respond?",
                        "Please reply.",
                    ]
                    self.messages.append(
                        {
                            "role": "user",
                            "type": "message",
                            "content": messages[attempt % len(messages)],
                        }
                    )
                    time.sleep(1)
                else:
                    self.output_queue.sync_q.put(complete_message)
                    if self.debug:
                        print("\nServer response complete.\n")

                    # Finalize job tracking if active
                    if self.current_job_id:
                        self._finalize_job_execution(self.current_job_id, success=True)

                    return

            except Exception as e:
                error = traceback.format_exc() + "\n" + str(e)
                error_message = {
                    "role": "server",
                    "type": "error",
                    "content": traceback.format_exc() + "\n" + str(e),
                }
                self.output_queue.sync_q.put(error_message)
                self.output_queue.sync_q.put(complete_message)
                print("\n\n--- SENT ERROR: ---\n\n")
                print(error)
                print("\n\n--- (ERROR ABOVE WAS SENT) ---\n\n")

                # Mark job as failed if active
                if self.current_job_id:
                    self._finalize_job_execution(
                        self.current_job_id, success=False, error_message=str(e)
                    )
                return

        error_message = {
            "role": "server",
            "type": "error",
            "content": "No chunks sent or unknown error.",
        }
        self.output_queue.sync_q.put(error_message)
        self.output_queue.sync_q.put(complete_message)

        # Mark job as failed if active
        if self.current_job_id:
            self._finalize_job_execution(
                self.current_job_id,
                success=False,
                error_message="No chunks sent or unknown error.",
            )

        raise Exception("No chunks sent or unknown error.")

    def accumulate(self, chunk):
        """
        Accumulates LMC chunks onto interpreter.messages.
        """
        if type(chunk) == str:
            chunk = json.loads(chunk)

        if type(chunk) == dict:
            if chunk.get("format") == "active_line":
                # We don't do anything with these.
                pass

            elif "content" in chunk and not (
                len(self.messages) > 0
                and (
                    (
                        "type" in self.messages[-1]
                        and chunk.get("type") != self.messages[-1].get("type")
                    )
                    or (
                        "format" in self.messages[-1]
                        and chunk.get("format") != self.messages[-1].get("format")
                    )
                )
            ):
                if len(self.messages) == 0:
                    raise Exception(
                        "You must send a 'start: True' chunk first to create this message."
                    )
                # Append to an existing message
                if (
                    "type" not in self.messages[-1]
                ):  # It was created with a type-less start message
                    self.messages[-1]["type"] = chunk["type"]
                if (
                    chunk.get("format") and "format" not in self.messages[-1]
                ):  # It was created with a type-less start message
                    self.messages[-1]["format"] = chunk["format"]
                if "content" not in self.messages[-1]:
                    self.messages[-1]["content"] = chunk["content"]
                else:
                    self.messages[-1]["content"] += chunk["content"]

            # elif "content" in chunk and (len(self.messages) > 0 and self.messages[-1] == {'role': 'user', 'start': True}):
            #     # Last message was {'role': 'user', 'start': True}. Just populate that with this chunk
            #     self.messages[-1] = chunk.copy()

            elif "start" in chunk or (
                len(self.messages) > 0
                and (
                    chunk.get("type") != self.messages[-1].get("type")
                    or chunk.get("format") != self.messages[-1].get("format")
                )
            ):
                # Create a new message
                chunk_copy = (
                    chunk.copy()
                )  # So we don't modify the original chunk, which feels wrong.
                if "start" in chunk_copy:
                    chunk_copy.pop("start")
                if "content" not in chunk_copy:
                    chunk_copy["content"] = ""
                self.messages.append(chunk_copy)

        elif type(chunk) == bytes:
            if self.messages[-1]["content"] == "":  # We initialize as an empty string ^
                self.messages[-1]["content"] = b""  # But it actually should be bytes
            self.messages[-1]["content"] += chunk

    def _capture_job_output(self, chunk):
        """
        Capture structured output for job result tracking.

        Args:
            chunk: Output chunk from interpreter execution
        """
        if not self.current_job_id or not chunk:
            return

        # Structure the chunk for job output buffer
        captured_chunk = {
            "timestamp": datetime.now().isoformat(),
            "role": chunk.get("role", "unknown"),
            "type": chunk.get("type", "unknown"),
            "content": chunk.get("content", ""),
            "format": chunk.get("format", None),
        }

        self.job_output_buffer.append(captured_chunk)

    def _finalize_job_execution(self, job_id, success=True, error_message=None):
        """
        Finalize job execution and update result data.

        Args:
            job_id: Job identifier
            success: Whether execution was successful
            error_message: Error message if execution failed
        """
        if not job_id:
            return

        try:
            # Compile structured output results
            stdout_content = []
            stderr_content = []
            files_created = []
            code_executed = []

            for chunk in self.job_output_buffer:
                if chunk["type"] == "console" and chunk["format"] == "output":
                    stdout_content.append(chunk["content"])
                elif chunk["type"] == "console" and chunk["format"] == "error":
                    stderr_content.append(chunk["content"])
                elif chunk["type"] == "code":
                    code_executed.append(chunk["content"])
                # TODO: Add file creation detection logic

            result_data = {
                "stdout": "".join(stdout_content),
                "stderr": "".join(stderr_content),
                "code_executed": "".join(code_executed),
                "files_created": files_created,  # Will be populated when file tracking is implemented
                "messages": self.job_output_buffer,
                "exit_code": 0 if success else 1,
            }

            # Update job status
            final_status = JobStatus.COMPLETED if success else JobStatus.FAILED
            self.job_manager.update_job_status(
                job_id,
                final_status,
                error_message=error_message,
                result_data=result_data,
            )

        except Exception as e:
            # Log error but don't fail the whole execution
            print(f"Error finalizing job {job_id}: {str(e)}")

        finally:
            # Clean up job tracking state
            self.current_job_id = None
            self.job_output_buffer = []

    async def execute_job(self, request: ExecuteRequest) -> str:
        """
        Execute code with job tracking.

        Args:
            request: Execute request containing code and parameters

        Returns:
            str: Job ID for tracking execution
        """
        # Create job for tracking
        job_id = self.job_manager.create_job(request.model_dump())

        try:
            # Set up job execution context
            self.current_job_id = job_id
            self.job_output_buffer = []

            # Create message for execution
            message = {
                "role": "user",
                "type": "message",
                "content": f"Execute this {request.language} code:\n\n```{request.language}\n{request.code}\n```",
            }

            # Add to messages and trigger execution
            self.messages.append(message)

            # Start execution in separate thread
            self.stop_event.clear()
            self.respond_thread = threading.Thread(
                target=self.respond, args=(True, job_id)  # auto_run=True, job_id=job_id
            )
            self.respond_thread.start()

            return job_id

        except Exception as e:
            # Mark job as failed if something goes wrong during setup
            self.job_manager.update_job_status(
                job_id, JobStatus.FAILED, error_message=str(e)
            )
            raise


def authenticate_function(key):
    """
    This function checks if the provided key is valid for authentication.

    Returns True if the key is valid, False otherwise.
    """
    # Fetch the API key from the environment variables. If it's not set, return True.
    api_key = os.getenv("INTERPRETER_API_KEY", None)

    # If the API key is not set in the environment variables, return True.
    # Otherwise, check if the provided key matches the fetched API key.
    # Return True if they match, False otherwise.
    if api_key is None:
        return True
    else:
        return key == api_key


def create_router(async_interpreter):
    router = APIRouter()

    @router.get("/heartbeat")
    async def heartbeat():
        return {"status": "alive"}

    @router.get("/")
    async def home():
        return PlainTextResponse(
            """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Chat</title>
            </head>
            <body>
                <form action="" onsubmit="sendMessage(event)">
                    <textarea id="messageInput" rows="10" cols="50" autocomplete="off"></textarea>
                    <button>Send</button>
                </form>
                <button id="approveCodeButton">Approve Code</button>
                <button id="authButton">Send Auth</button>
                <div id="messages"></div>
                <script>
                    var ws = new WebSocket("ws://"""
            + async_interpreter.server.host
            + ":"
            + str(async_interpreter.server.port)
            + """/");
                    var lastMessageElement = null;

                    ws.onmessage = function(event) {

                        var eventData = JSON.parse(event.data);

                        """
            + (
                """
                        
                        // Acknowledge receipt
                        var acknowledge_message = {
                            "ack": eventData.id
                        };
                        ws.send(JSON.stringify(acknowledge_message));

                        """
                if async_interpreter.require_acknowledge
                else ""
            )
            + """

                        if (lastMessageElement == null) {
                            lastMessageElement = document.createElement('p');
                            document.getElementById('messages').appendChild(lastMessageElement);
                            lastMessageElement.innerHTML = "<br>"
                        }

                        if ((eventData.role == "assistant" && eventData.type == "message" && eventData.content) ||
                            (eventData.role == "computer" && eventData.type == "console" && eventData.format == "output" && eventData.content) ||
                            (eventData.role == "assistant" && eventData.type == "code" && eventData.content)) {
                            lastMessageElement.innerHTML += eventData.content;
                        } else {
                            lastMessageElement.innerHTML += "<br><br>" + JSON.stringify(eventData) + "<br><br>";
                        }
                    };
                    function sendMessage(event) {
                        event.preventDefault();
                        var input = document.getElementById("messageInput");
                        var message = input.value;
                        if (message.startsWith('{') && message.endsWith('}')) {
                            message = JSON.stringify(JSON.parse(message));
                            ws.send(message);
                        } else {
                            var startMessageBlock = {
                                "role": "user",
                                //"type": "message",
                                "start": true
                            };
                            ws.send(JSON.stringify(startMessageBlock));

                            var messageBlock = {
                                "role": "user",
                                "type": "message",
                                "content": message
                            };
                            ws.send(JSON.stringify(messageBlock));

                            var endMessageBlock = {
                                "role": "user",
                                //"type": "message",
                                "end": true
                            };
                            ws.send(JSON.stringify(endMessageBlock));
                        }
                        var userMessageElement = document.createElement('p');
                        userMessageElement.innerHTML = '<b>' + input.value + '</b><br>';
                        document.getElementById('messages').appendChild(userMessageElement);
                        lastMessageElement = document.createElement('p');
                        document.getElementById('messages').appendChild(lastMessageElement);
                        input.value = '';
                    }
                function approveCode() {
                    var startCommandBlock = {
                        "role": "user",
                        "type": "command",
                        "start": true
                    };
                    ws.send(JSON.stringify(startCommandBlock));

                    var commandBlock = {
                        "role": "user",
                        "type": "command",
                        "content": "go"
                    };
                    ws.send(JSON.stringify(commandBlock));

                    var endCommandBlock = {
                        "role": "user",
                        "type": "command",
                        "end": true
                    };
                    ws.send(JSON.stringify(endCommandBlock));
                }
                function authenticate() {
                    var authBlock = {
                        "auth": "dummy-api-key"
                    };
                    ws.send(JSON.stringify(authBlock));
                }

                document.getElementById("approveCodeButton").addEventListener("click", approveCode);
                document.getElementById("authButton").addEventListener("click", authenticate);
                </script>
            </body>
            </html>
            """,
            media_type="text/html",
        )

    @router.websocket("/")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()

        try:  # solving it ;)/ # killian super wrote this

            async def receive_input():
                authenticated = False
                while True:
                    try:
                        if websocket.client_state != WebSocketState.CONNECTED:
                            return
                        data = await websocket.receive()

                        if (
                            not authenticated
                            and os.getenv("INTERPRETER_REQUIRE_AUTH") != "False"
                        ):
                            if "text" in data:
                                data = json.loads(data["text"])
                                if "auth" in data:
                                    if async_interpreter.server.authenticate(
                                        data["auth"]
                                    ):
                                        authenticated = True
                                        await websocket.send_text(
                                            json.dumps({"auth": True})
                                        )
                            if not authenticated:
                                await websocket.send_text(json.dumps({"auth": False}))
                            continue

                        if data.get("type") == "websocket.receive":
                            if "text" in data:
                                data = json.loads(data["text"])
                                if (
                                    async_interpreter.require_acknowledge
                                    and "ack" in data
                                ):
                                    async_interpreter.acknowledged_outputs.append(
                                        data["ack"]
                                    )
                                    continue
                            elif "bytes" in data:
                                data = data["bytes"]
                            await async_interpreter.input(data)
                        elif data.get("type") == "websocket.disconnect":
                            print("Client wants to disconnect, that's fine..")
                            return
                        else:
                            print("Invalid data:", data)
                            continue

                    except Exception as e:
                        error = traceback.format_exc() + "\n" + str(e)
                        error_message = {
                            "role": "server",
                            "type": "error",
                            "content": traceback.format_exc() + "\n" + str(e),
                        }
                        if websocket.client_state == WebSocketState.CONNECTED:
                            await websocket.send_text(json.dumps(error_message))
                            await websocket.send_text(json.dumps(complete_message))
                            print("\n\n--- SENT ERROR: ---\n\n")
                        else:
                            print(
                                "\n\n--- ERROR (not sent due to disconnected state): ---\n\n"
                            )
                        print(error)
                        print("\n\n--- (ERROR ABOVE) ---\n\n")

            async def send_output():
                while True:
                    if websocket.client_state != WebSocketState.CONNECTED:
                        return
                    try:
                        # First, try to send any unsent messages
                        while async_interpreter.unsent_messages:
                            output = async_interpreter.unsent_messages[0]
                            if async_interpreter.debug:
                                print("This was unsent, sending it again:", output)

                            success = await send_message(output)
                            if success:
                                async_interpreter.unsent_messages.popleft()

                        # If we've sent all unsent messages, get a new output
                        if not async_interpreter.unsent_messages:
                            output = await async_interpreter.output()
                            success = await send_message(output)
                            if not success:
                                async_interpreter.unsent_messages.append(output)
                                if async_interpreter.debug:
                                    print(
                                        f"Added message to unsent_messages queue after failed attempts: {output}"
                                    )

                    except Exception as e:
                        error = traceback.format_exc() + "\n" + str(e)
                        error_message = {
                            "role": "server",
                            "type": "error",
                            "content": error,
                        }
                        async_interpreter.unsent_messages.append(error_message)
                        async_interpreter.unsent_messages.append(complete_message)
                        print("\n\n--- ERROR (will be sent when possible): ---\n\n")
                        print(error)
                        print(
                            "\n\n--- (ERROR ABOVE WILL BE SENT WHEN POSSIBLE) ---\n\n"
                        )

            async def send_message(output):
                if isinstance(output, dict) and "id" in output:
                    id = output["id"]
                else:
                    id = shortuuid.uuid()
                    if (
                        isinstance(output, dict)
                        and async_interpreter.require_acknowledge
                    ):
                        output["id"] = id

                for attempt in range(20):
                    # time.sleep(0.5)

                    if websocket.client_state != WebSocketState.CONNECTED:
                        return False

                    try:
                        # print("sending:", output)

                        if isinstance(output, bytes):
                            await websocket.send_bytes(output)
                            return True  # Haven't set up ack for this
                        else:
                            if async_interpreter.require_acknowledge:
                                output["id"] = id
                            if async_interpreter.debug:
                                print("Sending this over the websocket:", output)
                            await websocket.send_text(json.dumps(output))

                        if async_interpreter.require_acknowledge:
                            acknowledged = False
                            for _ in range(100):
                                if id in async_interpreter.acknowledged_outputs:
                                    async_interpreter.acknowledged_outputs.remove(id)
                                    acknowledged = True
                                    if async_interpreter.debug:
                                        print("This output was acknowledged:", output)
                                    break
                                await asyncio.sleep(0.0001)

                            if acknowledged:
                                return True
                            else:
                                if async_interpreter.debug:
                                    print("Acknowledgement not received for:", output)
                                return False
                        else:
                            return True

                    except Exception as e:
                        print(
                            f"Failed to send output on attempt number: {attempt + 1}. Output was: {output}"
                        )
                        print(f"Error: {str(e)}")
                        traceback.print_exc()
                        await asyncio.sleep(0.01)

                # If we've reached this point, we've failed to send after 100 attempts
                if output not in async_interpreter.unsent_messages:
                    print("Failed to send message:", output)
                else:
                    print(
                        "Failed to send message, also it was already in unsent queue???:",
                        output,
                    )

                return False

            await asyncio.gather(receive_input(), send_output())

        except Exception as e:
            error = traceback.format_exc() + "\n" + str(e)
            error_message = {
                "role": "server",
                "type": "error",
                "content": error,
            }
            async_interpreter.unsent_messages.append(error_message)
            async_interpreter.unsent_messages.append(complete_message)
            print("\n\n--- ERROR (will be sent when possible): ---\n\n")
            print(error)
            print("\n\n--- (ERROR ABOVE WILL BE SENT WHEN POSSIBLE) ---\n\n")

    # TODO
    @router.post("/")
    async def post_input(payload: Dict[str, Any]):
        try:
            async_interpreter.input(payload)
            return {"status": "success"}
        except Exception as e:
            return {"error": str(e)}, 500

    @router.post("/settings")
    async def set_settings(payload: Dict[str, Any]):
        for key, value in payload.items():
            print("Updating settings...")
            # print(f"Updating settings: {key} = {value}")
            if key in ["llm", "computer"] and isinstance(value, dict):
                if key == "auto_run":
                    return {
                        "error": f"The setting {key} is not modifiable through the server due to security constraints."
                    }, 403
                if hasattr(async_interpreter, key):
                    for sub_key, sub_value in value.items():
                        if hasattr(getattr(async_interpreter, key), sub_key):
                            setattr(getattr(async_interpreter, key), sub_key, sub_value)
                        else:
                            return {
                                "error": f"Sub-setting {sub_key} not found in {key}"
                            }, 404
                else:
                    return {"error": f"Setting {key} not found"}, 404
            elif hasattr(async_interpreter, key):
                setattr(async_interpreter, key, value)
            else:
                return {"error": f"Setting {key} not found"}, 404

        return {"status": "success"}

    @router.get("/settings/{setting}")
    async def get_setting(setting: str):
        if hasattr(async_interpreter, setting):
            setting_value = getattr(async_interpreter, setting)
            try:
                return json.dumps({setting: setting_value})
            except TypeError:
                return {"error": "Failed to serialize the setting value"}, 500
        else:
            return json.dumps({"error": "Setting not found"}), 404

    # Job Management Endpoints
    @router.post("/execute")
    async def execute_code(request: ExecuteRequest):
        """
        Execute code with job tracking and return job ID.
        """
        try:
            job_id = await async_interpreter.execute_job(request)
            return {
                "job_id": job_id,
                "status": "queued",
                "message": "Job created and queued for execution",
            }
        except Exception as e:
            return {"error": str(e)}, 500

    @router.get("/jobs/{job_id}/status")
    async def get_job_status(job_id: str):
        """
        Get job status information.
        """
        try:
            status_info = async_interpreter.job_manager.get_job_status(job_id)
            if "error" in status_info:
                return status_info, 404
            return status_info
        except Exception as e:
            return {"error": str(e)}, 500

    @router.get("/jobs/{job_id}/result")
    async def get_job_result(job_id: str):
        """
        Get complete job results including output data.
        """
        try:
            result = async_interpreter.job_manager.get_job_result(job_id)
            if "error" in result:
                return result, 404
            return result
        except Exception as e:
            return {"error": str(e)}, 500

    @router.get("/jobs")
    async def list_jobs(status: Optional[str] = None, limit: int = 100):
        """
        List jobs with optional status filtering.
        """
        try:
            job_status = None
            if status:
                try:
                    job_status = JobStatus(status)
                except ValueError:
                    return {
                        "error": f"Invalid status: {status}. Valid statuses: {[s.value for s in JobStatus]}"
                    }, 400

            jobs = async_interpreter.job_manager.list_jobs(
                status=job_status, limit=limit
            )
            return {"jobs": jobs, "total": len(jobs)}
        except Exception as e:
            return {"error": str(e)}, 500

    @router.delete("/jobs/{job_id}")
    async def cancel_job(job_id: str):
        """
        Cancel a pending or running job.
        """
        try:
            success = async_interpreter.job_manager.cancel_job(job_id)
            if success:
                return {"message": f"Job {job_id} cancelled successfully"}
            else:
                return {"error": "Job not found or cannot be cancelled"}, 404
        except Exception as e:
            return {"error": str(e)}, 500

    @router.get("/jobs/stats")
    async def get_job_stats():
        """
        Get job management statistics.
        """
        try:
            stats = async_interpreter.job_manager.get_stats()
            return stats
        except Exception as e:
            return {"error": str(e)}, 500

    if os.getenv("INTERPRETER_INSECURE_ROUTES", "").lower() == "true":

        @router.post("/run")
        async def run_code(payload: Dict[str, Any]):
            language, code = payload.get("language"), payload.get("code")
            if not (language and code):
                return {"error": "Both 'language' and 'code' are required."}, 400
            try:
                print(f"Running {language}:", code)
                output = async_interpreter.computer.run(language, code)
                print("Output:", output)
                return {"output": output}
            except Exception as e:
                return {"error": str(e)}, 500

        @router.post("/upload")
        async def upload_file(file: UploadFile = File(...), path: str = Form(...)):
            try:
                with open(path, "wb") as output_file:
                    shutil.copyfileobj(file.file, output_file)
                return {"status": "success"}
            except Exception as e:
                return {"error": str(e)}, 500

        @router.get("/download/{filename}")
        async def download_file(filename: str):
            try:
                return StreamingResponse(
                    open(filename, "rb"), media_type="application/octet-stream"
                )
            except Exception as e:
                return {"error": str(e)}, 500

    ### OPENAI COMPATIBLE ENDPOINT

    class ChatMessage(BaseModel):
        role: str
        content: Union[str, List[Dict[str, Any]]]

    class ChatCompletionRequest(BaseModel):
        model: str = "default-model"
        messages: List[ChatMessage]
        max_tokens: Optional[int] = None
        temperature: Optional[float] = None
        stream: Optional[bool] = False

    async def openai_compatible_generator(run_code):
        if run_code:
            print("Running code.\n")
            for i, chunk in enumerate(async_interpreter._respond_and_store()):
                if "content" in chunk:
                    print(chunk["content"], end="")  # Sorry! Shitty display for now
                if "start" in chunk:
                    print("\n")

                output_content = None

                if chunk["type"] == "message" and "content" in chunk:
                    output_content = chunk["content"]
                if chunk["type"] == "code" and "start" in chunk:
                    output_content = "```" + chunk["format"] + "\n"
                if chunk["type"] == "code" and "content" in chunk:
                    output_content = chunk["content"]
                if chunk["type"] == "code" and "end" in chunk:
                    output_content = "\n```\n"

                if output_content:
                    await asyncio.sleep(0)
                    output_chunk = {
                        "id": i,
                        "object": "chat.completion.chunk",
                        "created": time.time(),
                        "model": "open-interpreter",
                        "choices": [{"delta": {"content": output_content}}],
                    }
                    yield f"data: {json.dumps(output_chunk)}\n\n"

            return

        made_chunk = False

        for message in [
            ".",
            "Just say something, anything.",
            "Hello? Answer please.",
            "Are you there?",
            "Can you respond?",
            "Please reply.",
        ]:
            for i, chunk in enumerate(
                async_interpreter.chat(message=message, stream=True, display=True)
            ):
                await asyncio.sleep(0)  # Yield control to the event loop
                made_chunk = True

                if (
                    chunk["type"] == "confirmation"
                    and async_interpreter.auto_run == False
                ):
                    await asyncio.sleep(0)
                    output_content = "Do you want to run this code?"
                    output_chunk = {
                        "id": i,
                        "object": "chat.completion.chunk",
                        "created": time.time(),
                        "model": "open-interpreter",
                        "choices": [{"delta": {"content": output_content}}],
                    }
                    yield f"data: {json.dumps(output_chunk)}\n\n"
                    break

                if async_interpreter.stop_event.is_set():
                    break

                output_content = None

                if chunk["type"] == "message" and "content" in chunk:
                    output_content = chunk["content"]
                if chunk["type"] == "code" and "start" in chunk:
                    output_content = "```" + chunk["format"] + "\n"
                if chunk["type"] == "code" and "content" in chunk:
                    output_content = chunk["content"]
                if chunk["type"] == "code" and "end" in chunk:
                    output_content = "\n```\n"

                if output_content:
                    await asyncio.sleep(0)
                    output_chunk = {
                        "id": i,
                        "object": "chat.completion.chunk",
                        "created": time.time(),
                        "model": "open-interpreter",
                        "choices": [{"delta": {"content": output_content}}],
                    }
                    yield f"data: {json.dumps(output_chunk)}\n\n"

            if made_chunk:
                break

    @router.post("/openai/chat/completions")
    async def chat_completion(request: ChatCompletionRequest):
        global last_start_time

        # Convert to LMC
        last_message = request.messages[-1]

        if last_message.role != "user":
            raise ValueError("Last message must be from the user.")

        if last_message.content == "{STOP}":
            # Handle special STOP token
            async_interpreter.stop_event.set()
            time.sleep(5)
            async_interpreter.stop_event.clear()
            return

        if last_message.content in ["{CONTEXT_MODE_ON}", "{REQUIRE_START_ON}"]:
            async_interpreter.context_mode = True
            return

        if last_message.content in ["{CONTEXT_MODE_OFF}", "{REQUIRE_START_OFF}"]:
            async_interpreter.context_mode = False
            return

        if last_message.content == "{AUTO_RUN_ON}":
            async_interpreter.auto_run = True
            return

        if last_message.content == "{AUTO_RUN_OFF}":
            async_interpreter.auto_run = False
            return

        run_code = False
        if (
            async_interpreter.messages
            and async_interpreter.messages[-1]["type"] == "code"
            and last_message.content.lower().strip(".!?").strip() == "yes"
        ):
            run_code = True
        elif type(last_message.content) == str:
            async_interpreter.messages.append(
                {
                    "role": "user",
                    "type": "message",
                    "content": last_message.content,
                }
            )
            print(">", last_message.content)
        elif type(last_message.content) == list:
            for content in last_message.content:
                if content["type"] == "text":
                    async_interpreter.messages.append(
                        {"role": "user", "type": "message", "content": str(content)}
                    )
                    print(">", content)
                elif content["type"] == "image_url":
                    if "url" not in content["image_url"]:
                        raise Exception("`url` must be in `image_url`.")
                    url = content["image_url"]["url"]
                    print("> [user sent an image]", url[:100])
                    if "base64," not in url:
                        raise Exception(
                            '''Image must be in the format: "data:image/jpeg;base64,{base64_image}"'''
                        )

                    # data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAA6oA...

                    data = url.split("base64,")[1]
                    format = "base64." + url.split(";")[0].split("/")[1]
                    async_interpreter.messages.append(
                        {
                            "role": "user",
                            "type": "image",
                            "format": format,
                            "content": data,
                        }
                    )

        else:
            if async_interpreter.context_mode:
                # In context mode, we only respond if we recieved a {START} message
                # Otherwise, we're just accumulating context
                if last_message.content == "{START}":
                    if async_interpreter.messages[-1]["content"] == "{START}":
                        # Remove that {START} message that would have just been added
                        async_interpreter.messages = async_interpreter.messages[:-1]
                    last_start_time = time.time()
                    if (
                        async_interpreter.messages
                        and async_interpreter.messages[-1].get("role") != "user"
                    ):
                        return
                else:
                    # Check if we're within 6 seconds of last_start_time
                    current_time = time.time()
                    if current_time - last_start_time <= 6:
                        # Continue processing
                        pass
                    else:
                        # More than 6 seconds have passed, so return
                        return

            else:
                if last_message.content == "{START}":
                    # This just sometimes happens I guess
                    # Remove that {START} message that would have just been added
                    async_interpreter.messages = async_interpreter.messages[:-1]
                    return

        async_interpreter.stop_event.set()
        time.sleep(0.1)
        async_interpreter.stop_event.clear()

        if request.stream:
            return StreamingResponse(
                openai_compatible_generator(run_code), media_type="application/x-ndjson"
            )
        else:
            messages = async_interpreter.chat(message=".", stream=False, display=True)
            content = messages[-1]["content"]
            return {
                "id": "200",
                "object": "chat.completion",
                "created": time.time(),
                "model": request.model,
                "choices": [{"message": {"role": "assistant", "content": content}}],
            }

    return router


class Server:
    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 8000

    def __init__(self, async_interpreter, host=None, port=None):
        self.app = FastAPI()
        router = create_router(async_interpreter)
        self.authenticate = authenticate_function

        # Add authentication middleware
        @self.app.middleware("http")
        async def validate_api_key(request: Request, call_next):
            # Ignore authentication for the /heartbeat route
            if request.url.path == "/heartbeat":
                return await call_next(request)

            api_key = request.headers.get("X-API-KEY")
            if self.authenticate(api_key):
                response = await call_next(request)
                return response
            else:
                return JSONResponse(
                    status_code=HTTP_403_FORBIDDEN,
                    content={"detail": "Authentication failed"},
                )

        self.app.include_router(router)
        h = host or os.getenv("INTERPRETER_HOST", Server.DEFAULT_HOST)
        p = port or int(os.getenv("INTERPRETER_PORT", Server.DEFAULT_PORT))
        self.config = uvicorn.Config(app=self.app, host=h, port=p)
        self.uvicorn_server = uvicorn.Server(self.config)

    @property
    def host(self):
        return self.config.host

    @host.setter
    def host(self, value):
        self.config.host = value
        self.uvicorn_server = uvicorn.Server(self.config)

    @property
    def port(self):
        return self.config.port

    @port.setter
    def port(self, value):
        self.config.port = value
        self.uvicorn_server = uvicorn.Server(self.config)

    def run(self, host=None, port=None, retries=5):
        if host is not None:
            self.host = host
        if port is not None:
            self.port = port

        # Print server information
        if self.host == "0.0.0.0":
            print(
                "Warning: Using host `0.0.0.0` will expose Open Interpreter over your local network."
            )
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))  # Google's public DNS server
            print(f"Server will run at http://{s.getsockname()[0]}:{self.port}")
            s.close()
        else:
            print(f"Server will run at http://{self.host}:{self.port}")

        self.uvicorn_server.run()

        # for _ in range(retries):
        #     try:
        #         self.uvicorn_server.run()
        #         break
        #     except KeyboardInterrupt:
        #         break
        #     except ImportError as e:
        #         if _ == 4:  # If this is the last attempt
        #             raise ImportError(
        #                 str(e)
        #                 + """\n\nPlease ensure you have run `pip install "open-interpreter[server]"` to install server dependencies."""
        #             )
        #     except:
        #         print("An unexpected error occurred:", traceback.format_exc())
        #         print("Server restarting.")
