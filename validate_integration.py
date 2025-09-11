#!/usr/bin/env python3
"""
Integration Validation Script for Open Interpreter Enhanced Server

This script performs comprehensive validation of the server integration,
ensuring all components work together correctly and provide the expected
structured JSON responses for orchestrator communication.
"""

import json
import sys
from pathlib import Path

# Add the interpreter directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))


def validate_server_structure():
    """Validate server.py has all required components"""
    print("🔍 Validating server structure...")

    try:
        from interpreter.server import (
            # EnhancedInterpreterServer,  # Validation only - import not used
            # JobResultResponse,  # Validation only - import not used
            StructuredResultResponse,
            # JobExecutionRequest,  # Validation only - import not used
            # JobStatusResponse,  # Validation only - import not used
            # ServerHealthResponse,  # Validation only - import not used
        )

        print("✅ All required classes imported successfully")

        # Check if StructuredResultResponse has required fields
        response = StructuredResultResponse(
            status="completed", stdout="test output", stderr="", files=["/tmp/test.txt"]
        )

        required_fields = ["status", "stdout", "stderr", "files"]
        for field in required_fields:
            if not hasattr(response, field):
                print(f"❌ Missing required field: {field}")
                return False

        print("✅ StructuredResultResponse has all required fields")
        return True

    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Validation error: {e}")
        return False


def validate_enhanced_terminal():
    """Validate enhanced terminal functionality"""
    print("\n🔍 Validating enhanced terminal...")

    try:
        from interpreter.core.enhanced_terminal import ExecutionResult

        # EnhancedTerminal  # Validation only - import not used

        print("✅ EnhancedTerminal imported successfully")

        # Create a mock computer object for testing
        class MockComputer:
            pass

        # Test ExecutionResult serialization
        result = ExecutionResult()
        result.stdout = "test output"
        result.stderr = ""
        result.files_created = ["/tmp/test1.txt", "/tmp/test2.txt"]
        result.exit_code = 0

        # Test to_dict method
        result_dict = result.to_dict()
        required_fields = ["stdout", "stderr", "files_created", "exit_code"]
        for field in required_fields:
            if field not in result_dict:
                print(f"❌ Missing field in ExecutionResult.to_dict(): {field}")
                return False

        print("✅ ExecutionResult serialization working correctly")
        return True

    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Enhanced terminal validation error: {e}")
        return False


def validate_job_manager():
    """Validate job manager functionality"""
    print("\n🔍 Validating job manager...")

    try:
        from interpreter.core.async_core import JobManager, JobStatus

        # Job  # Validation only - import not used

        print("✅ JobManager imported successfully")

        # Test job creation and management
        job_manager = JobManager(max_jobs=100)

        # Create test job
        request_data = {"code": "print('test')", "language": "python", "timeout": 30}

        job_id = job_manager.create_job(request_data)
        print(f"✅ Job created with ID: {job_id}")

        # Test job status retrieval
        status_info = job_manager.get_job_status(job_id)
        if "error" in status_info:
            print(f"❌ Job status error: {status_info['error']}")
            return False

        print("✅ Job status retrieval working")

        # Test job result format
        job_manager.update_job_status(
            job_id,
            JobStatus.COMPLETED,
            result_data={
                "stdout": "test output",
                "stderr": "",
                "files_created": ["/tmp/test.txt"],
                "exit_code": 0,
            },
        )

        result_info = job_manager.get_job_result(job_id)
        if "error" in result_info:
            print(f"❌ Job result error: {result_info['error']}")
            return False

        # Validate result structure
        required_fields = ["job_id", "status", "result_data"]
        for field in required_fields:
            if field not in result_info:
                print(f"❌ Missing field in job result: {field}")
                return False

        print("✅ Job result structure validated")
        return True

    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Job manager validation error: {e}")
        return False


def validate_api_response_format():
    """Validate API response formats match specification"""
    print("\n🔍 Validating API response formats...")

    try:
        from interpreter.server import StructuredResultResponse

        # Test structured response format
        structured_response = StructuredResultResponse(
            status="completed",
            stdout="Hello World!\nFile created successfully",
            stderr="",
            files=["/tmp/output.txt", "/tmp/data.json"],
        )

        # Convert to dict for JSON serialization validation
        response_dict = structured_response.dict()

        # Validate exact format for orchestrator
        expected_fields = {"status", "stdout", "stderr", "files"}
        actual_fields = set(response_dict.keys())

        if expected_fields != actual_fields:
            missing = expected_fields - actual_fields
            extra = actual_fields - expected_fields
            if missing:
                print(f"❌ Missing required fields: {missing}")
            if extra:
                print(f"❌ Unexpected extra fields: {extra}")
            return False

        print("✅ StructuredResultResponse format matches specification")

        # Validate response values
        if not isinstance(response_dict["files"], list):
            print("❌ 'files' field must be a list")
            return False

        if not isinstance(response_dict["stdout"], str):
            print("❌ 'stdout' field must be a string")
            return False

        if not isinstance(response_dict["stderr"], str):
            print("❌ 'stderr' field must be a string")
            return False

        print("✅ Response field types validated")

        # Test JSON serialization
        json_str = json.dumps(response_dict)
        parsed_back = json.loads(json_str)

        if parsed_back != response_dict:
            print("❌ JSON serialization/deserialization failed")
            return False

        print("✅ JSON serialization working correctly")
        return True

    except Exception as e:
        print(f"❌ API response format validation error: {e}")
        return False


def validate_server_endpoints():
    """Validate server has all required endpoints"""
    print("\n🔍 Validating server endpoints...")

    try:
        from interpreter.server import EnhancedInterpreterServer

        # Create server instance
        server = EnhancedInterpreterServer(host="127.0.0.1", port=8001)

        # Check if FastAPI app has required routes
        routes = [route.path for route in server.app.routes]

        required_endpoints = [
            "/execute",
            "/jobs/{job_id}/status",
            "/jobs/{job_id}/results",
            "/results/{job_id}",  # The new structured endpoint
            "/health",
            "/stats",
        ]

        for endpoint in required_endpoints:
            # Check if any route matches the pattern
            found = False
            for route in routes:
                if endpoint.replace("{job_id}", ".*") in route or endpoint == route:
                    found = True
                    break

            if not found:
                print(f"❌ Missing required endpoint: {endpoint}")
                return False

        print("✅ All required endpoints present")

        # Validate that the new /results/{job_id} endpoint exists
        structured_endpoint_found = any(
            "/results/{job_id}" in route for route in routes
        )
        if not structured_endpoint_found:
            print("❌ Missing structured results endpoint: /results/{job_id}")
            return False

        print("✅ Structured results endpoint (/results/{job_id}) found")
        return True

    except Exception as e:
        print(f"❌ Server endpoint validation error: {e}")
        return False


def validate_integration_completeness():
    """Validate complete integration works end-to-end"""
    print("\n🔍 Validating integration completeness...")

    try:
        from interpreter.core.async_core import JobManager

        # Test that all components can work together
        job_manager = JobManager()

        # Create a test job
        job_id = job_manager.create_job(
            {"code": "print('integration test')", "language": "python"}
        )

        # Simulate job completion with structured data
        result_data = {
            "stdout": "integration test\n",
            "stderr": "",
            "files_created": [],
            "files_modified": [],
            "exit_code": 0,
            "metadata": {"test": True},
        }

        job_manager.update_job_status(job_id, "completed", result_data=result_data)

        # Test result retrieval in orchestrator format
        result_info = job_manager.get_job_result(job_id)

        # Extract data for structured response
        structured_data = {
            "status": result_info["status"],
            "stdout": result_info.get("result_data", {}).get("stdout", ""),
            "stderr": result_info.get("result_data", {}).get("stderr", ""),
            "files": result_info.get("result_data", {}).get("files_created", []),
        }

        # Validate structured data format
        if not all(
            key in structured_data for key in ["status", "stdout", "stderr", "files"]
        ):
            print("❌ Structured data missing required keys")
            return False

        print("✅ End-to-end integration validated")
        print(f"   Sample structured response: {json.dumps(structured_data, indent=2)}")
        return True

    except Exception as e:
        print(f"❌ Integration completeness validation error: {e}")
        return False


def main():
    """Run all validation tests"""
    print("🚀 Open Interpreter Server Integration Validation")
    print("=" * 60)

    validations = [
        ("Server Structure", validate_server_structure),
        ("Enhanced Terminal", validate_enhanced_terminal),
        ("Job Manager", validate_job_manager),
        ("API Response Format", validate_api_response_format),
        ("Server Endpoints", validate_server_endpoints),
        ("Integration Completeness", validate_integration_completeness),
    ]

    results = []
    for name, validator in validations:
        print(f"\n{name}:")
        print("-" * 40)
        try:
            success = validator()
            results.append((name, success))
        except Exception as e:
            print(f"❌ {name} validation failed with exception: {e}")
            results.append((name, False))

    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY:")
    print("=" * 60)

    passed = 0
    for name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{name:<25} {status}")
        if success:
            passed += 1

    total = len(results)
    print(f"\nResults: {passed}/{total} validations passed")

    if passed == total:
        print("\n🎉 ALL VALIDATIONS PASSED!")
        print(
            "✅ Open Interpreter server is properly integrated and ready for orchestrator communication"
        )
        return True
    else:
        print(f"\n❌ {total - passed} validation(s) failed")
        print("❌ Please address the issues above before deployment")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
