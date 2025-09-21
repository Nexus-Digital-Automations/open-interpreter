#!/usr/bin/env python3
"""
Test script for Open Interpreter Enhanced Server API integration

This script tests the structured JSON API endpoints to ensure they provide
the correct response format for orchestrator communication.
"""

import json
import time

import requests


class InterpreterAPITester:
    """
    Test class for validating Open Interpreter server API integration
    """

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url
        self.session = requests.Session()

    def test_health_endpoint(self) -> bool:
        """Test server health endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                data = response.json()
                print("✅ Health endpoint working:")
                print(f"   Status: {data.get('status')}")
                print(f"   Active jobs: {data.get('active_jobs')}")
                return True
            else:
                print(f"❌ Health endpoint failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Health endpoint error: {e}")
            return False

    def test_execute_simple_code(self) -> str:
        """Test code execution and return job ID"""
        try:
            payload = {
                "code": "print('Hello from Open Interpreter!')\nprint('Testing structured output')",
                "language": "python",
                "timeout": 30,
                "capture_files": True,
            }

            response = self.session.post(f"{self.base_url}/execute", json=payload)
            if response.status_code == 200:
                data = response.json()
                job_id = data.get("job_id")
                print("✅ Code execution submitted:")
                print(f"   Job ID: {job_id}")
                print(f"   Status: {data.get('status')}")
                return job_id
            else:
                print(f"❌ Code execution failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
        except Exception as e:
            print(f"❌ Code execution error: {e}")
            return None

    def test_execute_file_creation(self) -> str:
        """Test code execution that creates files"""
        try:
            code = """
import os
import json

# Create a temporary test file
test_data = {"message": "Hello from Open Interpreter!", "timestamp": "2025-09-09"}
with open("test_output.json", "w") as f:
    json.dump(test_data, f, indent=2)

# Create another file
with open("execution_log.txt", "w") as f:
    f.write("Execution completed successfully\\n")
    f.write("Files created: test_output.json, execution_log.txt\\n")

print("Files created successfully!")
print(f"Current directory: {os.getcwd()}")
print(f"Files in directory: {os.listdir('.')}")
"""

            payload = {
                "code": code,
                "language": "python",
                "timeout": 30,
                "capture_files": True,
            }

            response = self.session.post(f"{self.base_url}/execute", json=payload)
            if response.status_code == 200:
                data = response.json()
                job_id = data.get("job_id")
                print("✅ File creation job submitted:")
                print(f"   Job ID: {job_id}")
                print(f"   Status: {data.get('status')}")
                return job_id
            else:
                print(f"❌ File creation job failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return None
        except Exception as e:
            print(f"❌ File creation job error: {e}")
            return None

    def wait_for_job_completion(self, job_id: str, timeout: int = 60) -> bool:
        """Wait for job to complete"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = self.session.get(f"{self.base_url}/jobs/{job_id}/status")
                if response.status_code == 200:
                    data = response.json()
                    status = data.get("status")
                    print(f"   Job {job_id} status: {status}")

                    if status in ["completed", "failed", "timeout", "cancelled"]:
                        return status == "completed"

                    time.sleep(2)
                else:
                    print(f"❌ Status check failed: {response.status_code}")
                    return False
            except Exception as e:
                print(f"❌ Status check error: {e}")
                return False

        print(f"❌ Job {job_id} timed out waiting for completion")
        return False

    def test_structured_results_endpoint(self, job_id: str) -> bool:
        """Test the structured results endpoint (/results/{job_id})"""
        try:
            response = self.session.get(f"{self.base_url}/results/{job_id}")
            if response.status_code == 200:
                data = response.json()
                print("✅ Structured results endpoint working:")
                print(f"   Status: {data.get('status')}")
                print(f"   Stdout length: {len(data.get('stdout', ''))}")
                print(f"   Stderr length: {len(data.get('stderr', ''))}")
                print(f"   Files created: {len(data.get('files', []))}")

                # Validate response structure
                required_fields = ["status", "stdout", "stderr", "files"]
                missing_fields = [
                    field for field in required_fields if field not in data
                ]

                if missing_fields:
                    print(f"❌ Missing required fields: {missing_fields}")
                    return False

                # Print the full structured response
                print("\n📋 Full Structured Response:")
                print(json.dumps(data, indent=2))
                return True
            else:
                print(f"❌ Structured results failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Structured results error: {e}")
            return False

    def test_comprehensive_results_endpoint(self, job_id: str) -> bool:
        """Test the comprehensive results endpoint (/jobs/{job_id}/results)"""
        try:
            response = self.session.get(f"{self.base_url}/jobs/{job_id}/results")
            if response.status_code == 200:
                data = response.json()
                print("✅ Comprehensive results endpoint working:")
                print(f"   Job ID: {data.get('job_id')}")
                print(f"   Status: {data.get('status')}")
                print(f"   Execution time: {data.get('execution_time_ms')}ms")
                print(f"   Exit code: {data.get('exit_code')}")
                print(f"   Files created: {len(data.get('files_created', []))}")
                print(f"   Files modified: {len(data.get('files_modified', []))}")

                if data.get("files_created"):
                    print(f"   Created files: {data.get('files_created')}")

                return True
            else:
                print(f"❌ Comprehensive results failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Comprehensive results error: {e}")
            return False

    def run_full_test_suite(self):
        """Run complete API integration test suite"""
        print("🚀 Starting Open Interpreter API Integration Tests")
        print("=" * 60)

        # Test 1: Health check
        print("\n1. Testing Health Endpoint...")
        if not self.test_health_endpoint():
            print("❌ Health check failed - server may not be running")
            return False

        # Test 2: Simple code execution
        print("\n2. Testing Simple Code Execution...")
        simple_job_id = self.test_execute_simple_code()
        if not simple_job_id:
            print("❌ Simple code execution failed")
            return False

        # Wait for completion
        print("\n   Waiting for simple job completion...")
        if not self.wait_for_job_completion(simple_job_id):
            print("❌ Simple job did not complete successfully")
            return False

        # Test structured results for simple job
        print("\n   Testing structured results for simple job...")
        if not self.test_structured_results_endpoint(simple_job_id):
            print("❌ Structured results test failed for simple job")
            return False

        # Test 3: File creation execution
        print("\n3. Testing File Creation Execution...")
        file_job_id = self.test_execute_file_creation()
        if not file_job_id:
            print("❌ File creation execution failed")
            return False

        # Wait for completion
        print("\n   Waiting for file creation job completion...")
        if not self.wait_for_job_completion(file_job_id):
            print("❌ File creation job did not complete successfully")
            return False

        # Test structured results for file creation job
        print("\n   Testing structured results for file creation job...")
        if not self.test_structured_results_endpoint(file_job_id):
            print("❌ Structured results test failed for file creation job")
            return False

        # Test comprehensive results
        print("\n   Testing comprehensive results endpoint...")
        if not self.test_comprehensive_results_endpoint(file_job_id):
            print("❌ Comprehensive results test failed")
            return False

        print("\n🎉 All tests passed successfully!")
        print(
            "✅ Open Interpreter server is properly providing structured JSON responses"
        )
        return True


def main():
    """Main test execution function"""
    tester = InterpreterAPITester()

    print("Open Interpreter API Integration Tester")
    print("Verifying structured JSON output for orchestrator communication")
    print()

    try:
        success = tester.run_full_test_suite()
        if success:
            print("\n✅ SUCCESS: All API integration tests passed")
            exit(0)
        else:
            print("\n❌ FAILURE: Some tests failed")
            exit(1)
    except KeyboardInterrupt:
        print("\n⏹️  Tests interrupted by user")
        exit(2)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        exit(3)


if __name__ == "__main__":
    main()
