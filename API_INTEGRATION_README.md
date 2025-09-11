# Open Interpreter API Server Integration

## Overview

The Enhanced Open Interpreter Server provides structured JSON responses through REST API endpoints, optimized for orchestrator integration and machine-to-machine communication.

## Key Features

- **Job-based execution** with UUID tracking
- **Structured I/O capture** with comprehensive metadata
- **File creation tracking** with absolute path resolution
- **Resource monitoring** with CPU and memory usage statistics
- **Multiple response formats** for different integration needs
- **Production-ready** with comprehensive error handling

## API Endpoints

### 1. Job Execution

```bash
POST /execute
```

**Request:**
```json
{
    "code": "print('Hello World!')",
    "language": "python",
    "timeout": 30,
    "capture_files": true,
    "working_directory": "/tmp/workspace",
    "environment_variables": {"PYTHONPATH": "/custom/path"},
    "metadata": {"user": "orchestrator", "task_id": "12345"}
}
```

**Response:**
```json
{
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "pending",
    "estimated_start_time": "2025-09-09T17:45:30Z"
}
```

### 2. Job Status Monitoring

```bash
GET /jobs/{job_id}/status
```

**Response:**
```json
{
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "running",
    "created_at": "2025-09-09T17:45:30Z",
    "started_at": "2025-09-09T17:45:31Z",
    "completed_at": null,
    "execution_time_ms": null,
    "error_message": null,
    "metadata": {
        "language": "python",
        "timeout": 30
    }
}
```

### 3. Structured Results (Orchestrator Optimized)

```bash
GET /results/{job_id}
```

**Response:**
```json
{
    "status": "completed",
    "stdout": "Hello World!\nFile created successfully\n",
    "stderr": "",
    "files": ["/tmp/workspace/output.txt", "/tmp/workspace/data.json"]
}
```

This endpoint provides the **exact format specified** for orchestrator communication:
- `status`: Job completion status
- `stdout`: Captured standard output
- `stderr`: Captured error output  
- `files`: List of absolute paths to created files

### 4. Comprehensive Results (Full Metadata)

```bash
GET /jobs/{job_id}/results
```

**Response:**
```json
{
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "stdout": "Hello World!\n",
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
    "created_at": "2025-09-09T17:45:30Z",
    "started_at": "2025-09-09T17:45:31Z",
    "completed_at": "2025-09-09T17:45:32Z"
}
```

### 5. Server Health

```bash
GET /health
```

**Response:**
```json
{
    "status": "healthy",
    "timestamp": "2025-09-09T17:50:00Z",
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
    }
}
```

## Integration Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Orchestrator  │    │  FastAPI Server │    │ Enhanced Terminal│
│                 │    │                 │    │                 │
│  POST /execute  │───▶│  JobManager     │───▶│  Code Execution │
│  GET /results   │◀───│  UUID Tracking  │◀───│  I/O Capture    │
│                 │    │  Status Updates │    │  File Tracking  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Job Lifecycle

1. **Submission** → POST /execute returns job_id
2. **Monitoring** → GET /jobs/{job_id}/status for progress
3. **Completion** → GET /results/{job_id} for structured results
4. **Cleanup** → Jobs automatically cleaned up after completion

## Status Values

- `pending`: Job created, waiting for execution
- `running`: Job currently being executed
- `completed`: Job finished successfully
- `failed`: Job failed due to execution error
- `timeout`: Job exceeded maximum execution time
- `cancelled`: Job was cancelled before completion

## Error Handling

### HTTP Status Codes
- `200 OK`: Successful operation
- `404 Not Found`: Job ID not found
- `500 Internal Server Error`: Server error during execution

### Error Response Format
```json
{
    "detail": "Job not found: invalid-job-id"
}
```

## File Tracking

The server tracks file creation during code execution:

- **Files created**: New files generated during execution
- **Files modified**: Existing files that were changed
- **Absolute paths**: All file paths are resolved to absolute paths
- **Working directory**: Configurable execution environment

## Resource Monitoring

Comprehensive resource usage tracking:

- **CPU usage**: Process CPU consumption percentage
- **Memory usage**: RSS and VMS memory consumption
- **Execution timing**: Precise millisecond timing
- **Process information**: PID and execution context

## Usage Examples

### Python Integration

```python
import requests
import time

# Submit job
response = requests.post("http://localhost:8000/execute", json={
    "code": "print('Hello from orchestrator!')",
    "language": "python"
})
job_id = response.json()["job_id"]

# Wait for completion
while True:
    status = requests.get(f"http://localhost:8000/jobs/{job_id}/status")
    if status.json()["status"] in ["completed", "failed"]:
        break
    time.sleep(1)

# Get structured results
results = requests.get(f"http://localhost:8000/results/{job_id}")
data = results.json()
print(f"Output: {data['stdout']}")
print(f"Files: {data['files']}")
```

### Shell Integration

```bash
#!/bin/bash

# Submit job and capture job ID
JOB_ID=$(curl -s -X POST "http://localhost:8000/execute" \
    -H "Content-Type: application/json" \
    -d '{"code": "echo Hello World!", "language": "shell"}' \
    | jq -r '.job_id')

# Wait for completion
while true; do
    STATUS=$(curl -s "http://localhost:8000/jobs/$JOB_ID/status" | jq -r '.status')
    if [[ "$STATUS" == "completed" ]] || [[ "$STATUS" == "failed" ]]; then
        break
    fi
    sleep 1
done

# Get results
curl -s "http://localhost:8000/results/$JOB_ID" | jq .
```

## Testing

Use the provided test script to verify API integration:

```bash
python test_structured_api.py
```

This will test:
- Server health and connectivity
- Code execution job submission
- Job status monitoring
- Structured result retrieval
- File creation tracking
- Error handling

## Configuration

### Environment Variables

```bash
export INTERPRETER_HOST=0.0.0.0
export INTERPRETER_PORT=8000
export INTERPRETER_MAX_JOBS=10
export INTERPRETER_LOG_LEVEL=INFO
```

### Server Startup

```python
from interpreter.server import EnhancedInterpreterServer

server = EnhancedInterpreterServer(
    host="0.0.0.0",
    port=8000,
    max_concurrent_jobs=10,
    enable_authentication=True,
    enable_cors=True
)

server.run()
```

## Production Deployment

### Docker Deployment

```dockerfile
FROM python:3.11
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 8000
CMD ["python", "-m", "interpreter.server"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: open-interpreter-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: open-interpreter
  template:
    metadata:
      labels:
        app: open-interpreter
    spec:
      containers:
      - name: interpreter
        image: open-interpreter:latest
        ports:
        - containerPort: 8000
        env:
        - name: INTERPRETER_HOST
          value: "0.0.0.0"
        - name: INTERPRETER_MAX_JOBS
          value: "20"
```

## Security Considerations

- **Authentication**: Enable API key authentication for production
- **Rate limiting**: Built-in request throttling
- **Input validation**: Comprehensive request validation
- **Resource limits**: Configurable execution timeouts and resource caps
- **Sandboxing**: Isolated execution environments

## Monitoring and Observability

- **Health endpoints**: Comprehensive health checking
- **Performance metrics**: Request timing and throughput
- **Resource monitoring**: System resource usage tracking
- **Logging**: Structured logging with execution tracing
- **Error tracking**: Comprehensive error capture and reporting

## Support

For issues and questions:
1. Check the server logs for detailed error information
2. Use the health endpoint to verify server status
3. Run the integration test suite to validate functionality
4. Review the OpenAPI documentation at `/docs`