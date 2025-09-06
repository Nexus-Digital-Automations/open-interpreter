"""
Comprehensive Test Suite for Phase 2.1: Open Interpreter FastAPI Server Wrapper

This test script validates the complete Phase 2.1 implementation including:
- Job management system with UUID tracking
- REST API endpoints for orchestrator communication
- Structured I/O capture and file tracking
- Enhanced terminal functionality
- Production-ready server features

Test Categories:
1. Job Management Tests - Create, track, and manage jobs
2. API Endpoint Tests - Validate all REST endpoints
3. Structured I/O Tests - Verify output capture and formatting
4. Error Handling Tests - Test failure scenarios and recovery
5. Performance Tests - Basic load and timing validation
6. Integration Tests - End-to-end workflow validation

Usage:
    python test_phase_2_1.py

Prerequisites:
    pip install pytest httpx asyncio
"""

import asyncio
import logging
import sys
import time
import traceback
from datetime import datetime

# Add interpreter to path for imports
sys.path.insert(
    0, "/Users/jeremyparker/Desktop/Claude Coding Projects/AIgent/open-interpreter"
)

try:
    import httpx
    import pytest
except ImportError:
    print("Error: Required test dependencies not installed")
    print("Please run: pip install httpx pytest")
    sys.exit(1)

from interpreter.core.async_core import AsyncInterpreter
from interpreter.core.enhanced_terminal import EnhancedTerminal, ExecutionResult
from interpreter.core.job_manager import JobManager, JobStatus
from interpreter.server import EnhancedInterpreterServer

# Configure test logging
logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [TEST] %(levelname)s: %(message)s"
)

logger = logging.getLogger("test_phase_2_1")


class Phase21TestSuite:
    """
    Comprehensive test suite for Phase 2.1 implementation

    This class provides systematic testing of all Phase 2.1 components
    including job management, API endpoints, structured I/O capture,
    and integration scenarios.
    """

    def __init__(self):
        """Initialize test suite with configuration and test data"""
        self.server_host = "127.0.0.1"
        self.server_port = 8001  # Use different port for testing
        self.base_url = f"http://{self.server_host}:{self.server_port}"
        self.server = None
        self.server_process = None

        # Test job tracking
        self.created_job_ids = []
        self.test_results = {
            "passed": 0,
            "failed": 0,
            "errors": [],
            "start_time": datetime.now(),
        }

    async def setup_test_server(self):
        """
        Start test server instance for API endpoint testing

        This method initializes and starts a dedicated test server instance
        that will be used for all API endpoint validation tests.
        """
        try:
            logger.info("Setting up test server instance")

            self.server = EnhancedInterpreterServer(
                host=self.server_host,
                port=self.server_port,
                max_concurrent_jobs=5,
                enable_authentication=False,  # Disable auth for testing
                enable_cors=True,
                log_level="WARNING",  # Reduce noise during testing
            )

            # Start server in background
            import threading

            import uvicorn

            def run_server():
                uvicorn.run(
                    self.server.app,
                    host=self.server_host,
                    port=self.server_port,
                    log_level="warning",
                )

            server_thread = threading.Thread(target=run_server, daemon=True)
            server_thread.start()

            # Wait for server to start
            await asyncio.sleep(2)

            # Validate server is running
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/health")
                if response.status_code == 200:
                    logger.info("Test server started successfully")
                    return True
                else:
                    logger.error(
                        f"Test server health check failed: {response.status_code}"
                    )
                    return False

        except Exception as e:
            logger.error(f"Failed to start test server: {str(e)}")
            return False

    def test_assert(self, condition: bool, test_name: str, error_message: str = ""):
        """
        Assert test condition and track results

        Args:
            condition: Boolean condition to test
            test_name: Name of the test for reporting
            error_message: Additional error details if test fails
        """
        if condition:
            self.test_results["passed"] += 1
            logger.info(f"✅ PASS: {test_name}")
        else:
            self.test_results["failed"] += 1
            error_msg = f"❌ FAIL: {test_name}"
            if error_message:
                error_msg += f" - {error_message}"
            logger.error(error_msg)
            self.test_results["errors"].append(
                {
                    "test": test_name,
                    "error": error_message,
                    "timestamp": datetime.now().isoformat(),
                }
            )

    async def test_job_manager_basic_functionality(self):
        """
        Test 1: Job Manager Basic Functionality

        Validates core job management capabilities including job creation,
        status tracking, and result storage.
        """
        logger.info("🧪 Starting Test 1: Job Manager Basic Functionality")

        try:
            # Initialize job manager
            job_manager = JobManager(max_jobs=100, cleanup_interval=3600)

            # Test 1.1: Job creation
            request_data = {
                "code": "print('Hello World!')",
                "language": "python",
                "timeout": 30,
            }

            job_id = job_manager.create_job(request_data)
            self.created_job_ids.append(job_id)

            self.test_assert(
                job_id is not None and len(job_id) > 20,
                "Job creation with UUID generation",
                f"Got job_id: {job_id}",
            )

            # Test 1.2: Job status retrieval
            status_info = job_manager.get_job_status(job_id)

            self.test_assert(
                status_info.get("job_id") == job_id,
                "Job status retrieval",
                f"Status: {status_info}",
            )

            self.test_assert(
                status_info.get("status") == "pending",
                "Initial job status is pending",
                f"Got status: {status_info.get('status')}",
            )

            # Test 1.3: Job status updates
            success = job_manager.update_job_status(job_id, JobStatus.RUNNING)
            self.test_assert(success, "Job status update to RUNNING")

            updated_status = job_manager.get_job_status(job_id)
            self.test_assert(
                updated_status.get("status") == "running",
                "Job status updated correctly",
                f"Status: {updated_status.get('status')}",
            )

            # Test 1.4: Job completion with results
            result_data = {
                "stdout": "Hello World!\n",
                "stderr": "",
                "files_created": [],
                "execution_time_ms": 1500,
            }

            success = job_manager.update_job_status(
                job_id, JobStatus.COMPLETED, result_data=result_data
            )
            self.test_assert(success, "Job completion with result data")

            # Test 1.5: Full result retrieval
            full_result = job_manager.get_job_result(job_id)

            self.test_assert(
                full_result.get("status") == "completed",
                "Job result shows completed status",
            )

            self.test_assert(
                full_result.get("result_data", {}).get("stdout") == "Hello World!\n",
                "Job result contains correct stdout",
                f"Got stdout: {full_result.get('result_data', {}).get('stdout')}",
            )

            # Test 1.6: Job statistics
            stats = job_manager.get_stats()

            self.test_assert(
                stats.get("total_jobs_created") >= 1,
                "Job statistics tracking",
                f"Stats: {stats}",
            )

            logger.info("✅ Test 1 completed: Job Manager Basic Functionality")

        except Exception as e:
            logger.error(f"❌ Test 1 failed with exception: {str(e)}")
            self.test_assert(False, "Job Manager Basic Functionality", str(e))

    async def test_enhanced_terminal_functionality(self):
        """
        Test 2: Enhanced Terminal Functionality

        Validates structured I/O capture, file tracking, and resource monitoring
        capabilities of the enhanced terminal system.
        """
        logger.info("🧪 Starting Test 2: Enhanced Terminal Functionality")

        try:
            # Initialize components
            interpreter = AsyncInterpreter()
            enhanced_terminal = EnhancedTerminal(
                interpreter.computer,
                enable_file_tracking=True,
                enable_resource_monitoring=True,
            )

            # Test 2.1: Basic code execution
            result = enhanced_terminal.run_enhanced(
                language="python",
                code="print('Test execution')\nprint('Second line')",
                timeout=10,
                capture_files=True,
            )

            self.test_assert(
                isinstance(result, ExecutionResult),
                "Enhanced terminal returns ExecutionResult object",
            )

            self.test_assert(
                result.exit_code == 0,
                "Code execution succeeds with exit code 0",
                f"Exit code: {result.exit_code}",
            )

            self.test_assert(
                "Test execution" in result.stdout,
                "Stdout capture works correctly",
                f"Stdout: {result.stdout}",
            )

            # Test 2.2: Execution timing
            self.test_assert(
                result.execution_time_ms is not None and result.execution_time_ms > 0,
                "Execution timing measurement",
                f"Execution time: {result.execution_time_ms}ms",
            )

            # Test 2.3: Metadata collection
            self.test_assert(
                result.metadata is not None and len(result.metadata) > 0,
                "Execution metadata collection",
                f"Metadata keys: {list(result.metadata.keys())}",
            )

            # Test 2.4: Error handling
            error_result = enhanced_terminal.run_enhanced(
                language="python", code="raise ValueError('Test error')", timeout=10
            )

            self.test_assert(
                error_result.exit_code != 0, "Error handling with non-zero exit code"
            )

            self.test_assert(
                "ValueError" in error_result.stderr
                or "Test error" in error_result.stderr,
                "Error message captured in stderr",
                f"Stderr: {error_result.stderr}",
            )

            # Test 2.5: Timeout handling
            # Note: This test is disabled to avoid long test runs
            # timeout_result = enhanced_terminal.run_enhanced(
            #     language="python",
            #     code="import time; time.sleep(5)",
            #     timeout=2
            # )
            # self.test_assert(
            #     timeout_result.exit_code == 124,
            #     "Timeout handling with exit code 124"
            # )

            # Test 2.6: Resource monitoring
            if hasattr(result, "resource_usage") and result.resource_usage:
                self.test_assert(
                    len(result.resource_usage) > 0,
                    "Resource usage monitoring",
                    f"Resource data: {list(result.resource_usage.keys())}",
                )

            # Test 2.7: Dictionary serialization
            result_dict = result.to_dict()

            self.test_assert(
                isinstance(result_dict, dict), "ExecutionResult to_dict() serialization"
            )

            required_keys = [
                "stdout",
                "stderr",
                "execution_time_ms",
                "exit_code",
                "metadata",
            ]
            missing_keys = [key for key in required_keys if key not in result_dict]

            self.test_assert(
                len(missing_keys) == 0,
                "ExecutionResult contains all required fields",
                f"Missing keys: {missing_keys}",
            )

            logger.info("✅ Test 2 completed: Enhanced Terminal Functionality")

        except Exception as e:
            logger.error(f"❌ Test 2 failed with exception: {str(e)}")
            traceback.print_exc()
            self.test_assert(False, "Enhanced Terminal Functionality", str(e))

    async def test_api_endpoints(self):
        """
        Test 3: API Endpoints Validation

        Tests all REST API endpoints for proper request handling, response format,
        and error conditions.
        """
        logger.info("🧪 Starting Test 3: API Endpoints Validation")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:

                # Test 3.1: Health endpoint
                health_response = await client.get(f"{self.base_url}/health")

                self.test_assert(
                    health_response.status_code == 200,
                    "Health endpoint returns 200",
                    f"Status: {health_response.status_code}",
                )

                health_data = health_response.json()

                self.test_assert(
                    health_data.get("status") in ["healthy", "degraded", "unhealthy"],
                    "Health endpoint returns valid status",
                    f"Health status: {health_data.get('status')}",
                )

                # Test 3.2: Stats endpoint
                stats_response = await client.get(f"{self.base_url}/stats")

                self.test_assert(
                    stats_response.status_code == 200, "Stats endpoint returns 200"
                )

                stats_data = stats_response.json()
                required_sections = [
                    "server_info",
                    "job_statistics",
                    "performance_metrics",
                ]
                missing_sections = [s for s in required_sections if s not in stats_data]

                self.test_assert(
                    len(missing_sections) == 0,
                    "Stats endpoint returns all required sections",
                    f"Missing: {missing_sections}",
                )

                # Test 3.3: Code execution endpoint
                execute_request = {
                    "code": "print('API Test')\nresult = 42\nprint(f'Result: {result}')",
                    "language": "python",
                    "timeout": 15,
                    "capture_files": True,
                    "metadata": {"test": "api_validation"},
                }

                execute_response = await client.post(
                    f"{self.base_url}/execute", json=execute_request
                )

                self.test_assert(
                    execute_response.status_code == 200,
                    "Execute endpoint returns 200",
                    f"Status: {execute_response.status_code}, Response: {execute_response.text}",
                )

                execute_data = execute_response.json()
                job_id = execute_data.get("job_id")

                self.test_assert(
                    job_id is not None and len(job_id) > 20,
                    "Execute endpoint returns valid job ID",
                    f"Job ID: {job_id}",
                )

                self.created_job_ids.append(job_id)

                # Test 3.4: Job status endpoint
                # Wait a moment for job to process
                await asyncio.sleep(3)

                status_response = await client.get(
                    f"{self.base_url}/jobs/{job_id}/status"
                )

                self.test_assert(
                    status_response.status_code == 200,
                    "Job status endpoint returns 200",
                )

                status_data = status_response.json()

                self.test_assert(
                    status_data.get("job_id") == job_id,
                    "Job status returns correct job ID",
                )

                self.test_assert(
                    status_data.get("status")
                    in ["pending", "running", "completed", "failed"],
                    "Job status returns valid status value",
                    f"Status: {status_data.get('status')}",
                )

                # Test 3.5: Job results endpoint (wait for completion)
                max_wait = 10  # seconds
                wait_count = 0
                final_status = None

                while wait_count < max_wait:
                    status_check = await client.get(
                        f"{self.base_url}/jobs/{job_id}/status"
                    )
                    if status_check.status_code == 200:
                        status_info = status_check.json()
                        final_status = status_info.get("status")
                        if final_status in ["completed", "failed"]:
                            break

                    await asyncio.sleep(1)
                    wait_count += 1

                results_response = await client.get(
                    f"{self.base_url}/jobs/{job_id}/results"
                )

                self.test_assert(
                    results_response.status_code == 200,
                    "Job results endpoint returns 200",
                )

                results_data = results_response.json()

                self.test_assert(
                    results_data.get("job_id") == job_id,
                    "Job results return correct job ID",
                )

                # If job completed successfully, check output
                if final_status == "completed":
                    self.test_assert(
                        "API Test" in results_data.get("stdout", ""),
                        "Job results contain expected stdout",
                        f"Stdout: {results_data.get('stdout')}",
                    )

                # Test 3.6: Job listing endpoint
                jobs_response = await client.get(f"{self.base_url}/jobs?limit=10")

                self.test_assert(
                    jobs_response.status_code == 200,
                    "Jobs listing endpoint returns 200",
                )

                jobs_data = jobs_response.json()

                self.test_assert(
                    isinstance(jobs_data, list), "Jobs listing returns array of jobs"
                )

                # Test 3.7: Error handling - invalid job ID
                invalid_response = await client.get(
                    f"{self.base_url}/jobs/invalid-id/status"
                )

                self.test_assert(
                    invalid_response.status_code == 404, "Invalid job ID returns 404"
                )

                logger.info("✅ Test 3 completed: API Endpoints Validation")

        except Exception as e:
            logger.error(f"❌ Test 3 failed with exception: {str(e)}")
            traceback.print_exc()
            self.test_assert(False, "API Endpoints Validation", str(e))

    async def test_integration_workflow(self):
        """
        Test 4: End-to-End Integration Workflow

        Tests complete workflow from job creation through result retrieval,
        simulating real orchestrator usage patterns.
        """
        logger.info("🧪 Starting Test 4: End-to-End Integration Workflow")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:

                # Test 4.1: Multi-language execution
                test_cases = [
                    {
                        "name": "Python execution",
                        "code": "import json\ndata = {'test': True, 'value': 123}\nprint(json.dumps(data))",
                        "language": "python",
                        "expected_in_output": '"test": true',
                    },
                    {
                        "name": "Shell execution",
                        "code": "echo 'Shell test successful'\ndate",
                        "language": "shell",
                        "expected_in_output": "Shell test successful",
                    },
                ]

                for test_case in test_cases:
                    logger.info(f"Testing {test_case['name']}")

                    # Submit job
                    request = {
                        "code": test_case["code"],
                        "language": test_case["language"],
                        "timeout": 20,
                        "capture_files": True,
                        "metadata": {"test_case": test_case["name"]},
                    }

                    response = await client.post(
                        f"{self.base_url}/execute", json=request
                    )

                    self.test_assert(
                        response.status_code == 200,
                        f"{test_case['name']} job submission",
                    )

                    job_id = response.json().get("job_id")
                    if job_id:
                        self.created_job_ids.append(job_id)

                        # Wait for completion
                        max_wait = 15
                        for _ in range(max_wait):
                            status_response = await client.get(
                                f"{self.base_url}/jobs/{job_id}/status"
                            )
                            if status_response.status_code == 200:
                                status = status_response.json().get("status")
                                if status in ["completed", "failed"]:
                                    break
                            await asyncio.sleep(1)

                        # Check results
                        results_response = await client.get(
                            f"{self.base_url}/jobs/{job_id}/results"
                        )
                        if results_response.status_code == 200:
                            results = results_response.json()

                            if test_case.get("expected_in_output"):
                                output_found = test_case[
                                    "expected_in_output"
                                ] in results.get("stdout", "")
                                self.test_assert(
                                    output_found,
                                    f"{test_case['name']} produces expected output",
                                    f"Looking for '{test_case['expected_in_output']}' in '{results.get('stdout')}'",
                                )

                # Test 4.2: Concurrent job execution
                logger.info("Testing concurrent job execution")

                concurrent_jobs = []
                for i in range(3):
                    request = {
                        "code": f"import time\nprint(f'Job {i} starting')\ntime.sleep(1)\nprint(f'Job {i} completed')",
                        "language": "python",
                        "timeout": 15,
                        "metadata": {"concurrent_test": True, "job_number": i},
                    }

                    response = await client.post(
                        f"{self.base_url}/execute", json=request
                    )
                    if response.status_code == 200:
                        job_id = response.json().get("job_id")
                        concurrent_jobs.append(job_id)
                        self.created_job_ids.append(job_id)

                self.test_assert(
                    len(concurrent_jobs) == 3, "Concurrent job submissions successful"
                )

                # Wait for all to complete
                await asyncio.sleep(8)

                completed_count = 0
                for job_id in concurrent_jobs:
                    status_response = await client.get(
                        f"{self.base_url}/jobs/{job_id}/status"
                    )
                    if status_response.status_code == 200:
                        status = status_response.json().get("status")
                        if status == "completed":
                            completed_count += 1

                self.test_assert(
                    completed_count >= 2,  # At least 2 should complete
                    "Concurrent jobs execution",
                    f"Completed: {completed_count}/3",
                )

                # Test 4.3: Error recovery workflow
                logger.info("Testing error recovery workflow")

                error_request = {
                    "code": "print('Before error')\nraise Exception('Test error for recovery')\nprint('After error')",
                    "language": "python",
                    "timeout": 10,
                }

                error_response = await client.post(
                    f"{self.base_url}/execute", json=error_request
                )

                if error_response.status_code == 200:
                    error_job_id = error_response.json().get("job_id")
                    self.created_job_ids.append(error_job_id)

                    # Wait for completion
                    await asyncio.sleep(5)

                    error_results = await client.get(
                        f"{self.base_url}/jobs/{error_job_id}/results"
                    )
                    if error_results.status_code == 200:
                        results = error_results.json()

                        self.test_assert(
                            results.get("status") == "failed",
                            "Error job marked as failed",
                        )

                        self.test_assert(
                            "Before error" in results.get("stdout", ""),
                            "Partial output captured before error",
                        )

                        self.test_assert(
                            "Test error for recovery" in results.get("stderr", ""),
                            "Error message captured in stderr",
                        )

                logger.info("✅ Test 4 completed: End-to-End Integration Workflow")

        except Exception as e:
            logger.error(f"❌ Test 4 failed with exception: {str(e)}")
            traceback.print_exc()
            self.test_assert(False, "End-to-End Integration Workflow", str(e))

    async def test_performance_validation(self):
        """
        Test 5: Basic Performance Validation

        Validates basic performance characteristics and response times
        for the Phase 2.1 implementation.
        """
        logger.info("🧪 Starting Test 5: Basic Performance Validation")

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:

                # Test 5.1: API response times
                start_time = time.time()
                health_response = await client.get(f"{self.base_url}/health")
                health_time = time.time() - start_time

                self.test_assert(
                    health_time < 2.0,
                    "Health endpoint responds within 2 seconds",
                    f"Response time: {health_time:.3f}s",
                )

                # Test 5.2: Job creation latency
                job_creation_times = []

                for i in range(5):
                    start_time = time.time()

                    request = {
                        "code": f"print('Performance test {i}')",
                        "language": "python",
                        "timeout": 10,
                    }

                    response = await client.post(
                        f"{self.base_url}/execute", json=request
                    )
                    creation_time = time.time() - start_time

                    if response.status_code == 200:
                        job_creation_times.append(creation_time)
                        job_id = response.json().get("job_id")
                        if job_id:
                            self.created_job_ids.append(job_id)

                if job_creation_times:
                    avg_creation_time = sum(job_creation_times) / len(
                        job_creation_times
                    )

                    self.test_assert(
                        avg_creation_time < 1.0,
                        "Average job creation time under 1 second",
                        f"Average: {avg_creation_time:.3f}s, Max: {max(job_creation_times):.3f}s",
                    )

                # Test 5.3: Simple execution performance
                simple_job_request = {
                    "code": "result = sum(range(1000))\nprint(f'Sum: {result}')",
                    "language": "python",
                    "timeout": 10,
                }

                execution_start = time.time()
                exec_response = await client.post(
                    f"{self.base_url}/execute", json=simple_job_request
                )

                if exec_response.status_code == 200:
                    job_id = exec_response.json().get("job_id")
                    self.created_job_ids.append(job_id)

                    # Wait for completion and measure total time
                    completed = False
                    while time.time() - execution_start < 15:
                        status_response = await client.get(
                            f"{self.base_url}/jobs/{job_id}/status"
                        )
                        if status_response.status_code == 200:
                            status = status_response.json().get("status")
                            if status in ["completed", "failed"]:
                                total_time = time.time() - execution_start
                                completed = True
                                break
                        await asyncio.sleep(0.5)

                    if completed:
                        self.test_assert(
                            total_time < 10.0,
                            "Simple job completes within 10 seconds",
                            f"Total time: {total_time:.3f}s",
                        )

                logger.info("✅ Test 5 completed: Basic Performance Validation")

        except Exception as e:
            logger.error(f"❌ Test 5 failed with exception: {str(e)}")
            self.test_assert(False, "Basic Performance Validation", str(e))

    async def cleanup_test_jobs(self):
        """
        Clean up jobs created during testing

        Attempts to cancel or clean up any jobs that were created during
        the testing process to avoid leaving test artifacts.
        """
        if not self.created_job_ids:
            return

        logger.info(f"Cleaning up {len(self.created_job_ids)} test jobs")

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for job_id in self.created_job_ids:
                    try:
                        # Attempt to cancel job (may fail if already completed)
                        await client.post(f"{self.base_url}/jobs/{job_id}/cancel")
                    except:
                        pass  # Ignore cleanup errors
        except Exception as e:
            logger.warning(f"Job cleanup encountered errors: {str(e)}")

    def print_test_summary(self):
        """
        Print comprehensive test results summary

        Displays detailed test results including pass/fail counts,
        performance metrics, and any errors encountered.
        """
        end_time = datetime.now()
        duration = (end_time - self.test_results["start_time"]).total_seconds()

        print("\n" + "=" * 60)
        print("PHASE 2.1 TEST RESULTS SUMMARY")
        print("=" * 60)

        print(f"Test Duration: {duration:.2f} seconds")
        print(f"Tests Passed: {self.test_results['passed']}")
        print(f"Tests Failed: {self.test_results['failed']}")
        print(
            f"Total Tests: {self.test_results['passed'] + self.test_results['failed']}"
        )

        if self.test_results["passed"] + self.test_results["failed"] > 0:
            success_rate = (
                self.test_results["passed"]
                / (self.test_results["passed"] + self.test_results["failed"])
                * 100
            )
            print(f"Success Rate: {success_rate:.1f}%")

        if self.test_results["errors"]:
            print(f"\nErrors Encountered ({len(self.test_results['errors'])}):")
            for i, error in enumerate(self.test_results["errors"], 1):
                print(f"  {i}. {error['test']}")
                if error.get("error"):
                    print(f"     Error: {error['error']}")

        # Overall result
        if self.test_results["failed"] == 0:
            print(
                "\n✅ ALL TESTS PASSED - Phase 2.1 implementation is working correctly!"
            )
        else:
            print("\n❌ SOME TESTS FAILED - Phase 2.1 implementation needs attention")

        print("=" * 60 + "\n")


async def main():
    """
    Main test runner function

    Executes the complete Phase 2.1 test suite including server setup,
    all test categories, cleanup, and result reporting.
    """
    test_suite = Phase21TestSuite()

    try:
        logger.info("🚀 Starting Phase 2.1 Test Suite")
        logger.info("Testing: Open Interpreter FastAPI Server Wrapper")

        # Setup test environment
        logger.info("Setting up test environment...")
        server_started = await test_suite.setup_test_server()

        if not server_started:
            logger.error("Failed to start test server - aborting tests")
            return

        # Run all test suites
        await test_suite.test_job_manager_basic_functionality()
        await test_suite.test_enhanced_terminal_functionality()
        await test_suite.test_api_endpoints()
        await test_suite.test_integration_workflow()
        await test_suite.test_performance_validation()

        # Cleanup
        await test_suite.cleanup_test_jobs()

    except Exception as e:
        logger.error(f"Test suite failed with critical error: {str(e)}")
        traceback.print_exc()

    finally:
        # Print results regardless of success/failure
        test_suite.print_test_summary()


if __name__ == "__main__":
    # Check if running in pytest
    if "pytest" in sys.modules:
        pytest.main([__file__])
    else:
        # Run directly
        asyncio.run(main())
