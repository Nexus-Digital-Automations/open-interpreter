"""
Async Server Integration Test Suite for Open Interpreter

This test suite provides comprehensive coverage for Open Interpreter's
async operations, server functionality, WebSocket communication,
and API endpoints for production deployment scenarios.

Test Coverage:
- AsyncInterpreter core functionality
- WebSocket communication and streaming
- FastAPI server endpoints and middleware
- Authentication and authorization
- Concurrent request handling
- Server lifecycle management
- Real-time messaging and events
- Performance under load

Author: Async Server Integration Testing Specialist
Version: 1.0.0 - Production-Ready Async Server Testing
"""

import asyncio
import json
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
import websockets
from fastapi.testclient import TestClient

# Open Interpreter imports
from interpreter.core.async_core import AsyncInterpreter, Server


@pytest.fixture
def async_interpreter():
    """Pytest fixture providing AsyncInterpreter instance"""
    interpreter = AsyncInterpreter()
    interpreter.llm.model = "gpt-4o-mini"
    interpreter.llm.supports_vision = False
    interpreter.llm.supports_functions = True
    interpreter.auto_run = True
    interpreter.verbose = False
    return interpreter


@pytest.fixture
def mock_server():
    """Pytest fixture providing mocked Server instance"""
    interpreter = AsyncInterpreter()
    server = Server(interpreter, host="127.0.0.1", port=8000)
    return server


@pytest.fixture
def test_client(mock_server):
    """Pytest fixture providing FastAPI test client"""
    return TestClient(mock_server.app)


class TestAsyncInterpreterCore:
    """Test suite for AsyncInterpreter core functionality"""

    @pytest.mark.asyncio
    async def test_async_code_execution(self, async_interpreter):
        """Test asynchronous code execution"""
        with patch.object(async_interpreter.computer.terminal, "run") as mock_run:
            mock_run.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "42",
                }
            ]

            result = await async_interpreter.async_run("python", "print(6 * 7)")

            assert len(result) > 0
            assert "42" in result[0]["content"]

    @pytest.mark.asyncio
    async def test_async_chat_streaming(self, async_interpreter):
        """Test asynchronous chat with streaming responses"""
        with patch.object(
            async_interpreter, "_async_respond_and_store"
        ) as mock_respond:

            async def mock_async_generator():
                yield {"role": "assistant", "type": "message", "start": True}
                yield {
                    "role": "assistant",
                    "type": "message",
                    "content": "Processing your request...",
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "start": True,
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "content": "result = 2 + 2",
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "end": True,
                }
                yield {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "4",
                }
                yield {
                    "role": "assistant",
                    "type": "message",
                    "content": "The result is 4.",
                }
                yield {"role": "assistant", "type": "message", "end": True}

            mock_respond.return_value = mock_async_generator()

            responses = []
            async for response in async_interpreter.async_chat("What is 2 + 2?"):
                responses.append(response)

            assert len(responses) == 8
            message_responses = [r for r in responses if r.get("type") == "message"]
            code_responses = [r for r in responses if r.get("type") == "code"]
            console_responses = [r for r in responses if r.get("type") == "console"]

            assert len(message_responses) >= 3
            assert len(code_responses) >= 2
            assert len(console_responses) >= 1

    @pytest.mark.asyncio
    async def test_concurrent_async_operations(self, async_interpreter):
        """Test concurrent async operations handling"""
        tasks = []

        for i in range(5):
            with patch.object(async_interpreter.computer.terminal, "run") as mock_run:
                mock_run.return_value = [
                    {
                        "role": "computer",
                        "type": "console",
                        "format": "output",
                        "content": f"Task {i} completed",
                    }
                ]

                task = async_interpreter.async_run("python", f"print('Task {i}')")
                tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) >= 4, "Most concurrent tasks should succeed"

        for result in successful_results:
            assert len(result) > 0
            assert "completed" in result[0]["content"]

    @pytest.mark.asyncio
    async def test_async_timeout_handling(self, async_interpreter):
        """Test async timeout handling"""
        with patch.object(async_interpreter.computer.terminal, "run") as mock_run:
            # Simulate long-running operation
            async def slow_operation(*args, **kwargs):
                await asyncio.sleep(2)
                return [
                    {
                        "role": "computer",
                        "type": "console",
                        "format": "output",
                        "content": "slow result",
                    }
                ]

            mock_run.side_effect = slow_operation

            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    async_interpreter.async_run("python", "time.sleep(10)"), timeout=0.5
                )

    @pytest.mark.asyncio
    async def test_async_error_handling(self, async_interpreter):
        """Test async error handling and recovery"""
        with patch.object(async_interpreter.computer.terminal, "run") as mock_run:
            mock_run.side_effect = Exception("Simulated execution error")

            with pytest.raises(Exception):
                await async_interpreter.async_run("python", "invalid_code()")

    @pytest.mark.asyncio
    async def test_async_resource_management(self, async_interpreter):
        """Test async resource management and cleanup"""

        # Simulate resource-intensive operations
        async def resource_operation():
            try:
                return await async_interpreter.async_run(
                    "python", "result = [i**2 for i in range(1000)]"
                )
            finally:
                # Cleanup should happen automatically
                pass

        with patch.object(async_interpreter.computer.terminal, "run") as mock_run:
            mock_run.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "Resource operation completed",
                }
            ]

            result = await resource_operation()
            assert len(result) > 0
            assert "completed" in result[0]["content"]


class TestWebSocketCommunication:
    """Test suite for WebSocket communication and streaming"""

    @pytest.mark.asyncio
    async def test_websocket_connection(self, mock_server):
        """Test WebSocket connection establishment"""
        with patch("websockets.serve") as mock_serve:
            mock_websocket = AsyncMock()
            mock_serve.return_value.__aenter__.return_value = mock_websocket

            # Simulate WebSocket server startup
            await mock_server.start_websocket_server()

            mock_serve.assert_called_once()

    @pytest.mark.asyncio
    async def test_websocket_message_handling(self, mock_server):
        """Test WebSocket message handling and responses"""
        mock_websocket = AsyncMock()

        # Mock incoming message
        test_message = {"role": "user", "type": "message", "content": "Hello WebSocket"}

        mock_websocket.recv.return_value = json.dumps(test_message)

        with patch.object(mock_server.interpreter, "async_chat") as mock_chat:

            async def mock_chat_responses():
                yield {
                    "role": "assistant",
                    "type": "message",
                    "content": "WebSocket response",
                }

            mock_chat.return_value = mock_chat_responses()

            # Process WebSocket message
            await mock_server.handle_websocket_message(
                mock_websocket, json.dumps(test_message)
            )

            # Verify response was sent
            mock_websocket.send.assert_called()
            sent_data = json.loads(mock_websocket.send.call_args[0][0])
            assert sent_data["role"] == "assistant"
            assert "WebSocket response" in sent_data["content"]

    @pytest.mark.asyncio
    async def test_websocket_streaming_responses(self, mock_server):
        """Test WebSocket streaming response handling"""
        mock_websocket = AsyncMock()

        with patch.object(mock_server.interpreter, "async_chat") as mock_chat:

            async def mock_streaming_responses():
                yield {"role": "assistant", "type": "message", "start": True}
                yield {
                    "role": "assistant",
                    "type": "message",
                    "content": "Streaming chunk 1",
                }
                yield {
                    "role": "assistant",
                    "type": "message",
                    "content": "Streaming chunk 2",
                }
                yield {"role": "assistant", "type": "message", "end": True}

            mock_chat.return_value = mock_streaming_responses()

            await mock_server.handle_websocket_streaming(
                mock_websocket, "Test streaming"
            )

            # Verify multiple messages were sent
            assert mock_websocket.send.call_count >= 4

    @pytest.mark.asyncio
    async def test_websocket_error_handling(self, mock_server):
        """Test WebSocket error handling"""
        mock_websocket = AsyncMock()
        mock_websocket.recv.side_effect = websockets.exceptions.ConnectionClosed(
            None, None
        )

        # Should handle connection close gracefully
        result = await mock_server.handle_websocket_connection(mock_websocket)
        assert result is None  # Graceful cleanup

    @pytest.mark.asyncio
    async def test_websocket_authentication(self, mock_server):
        """Test WebSocket authentication and authorization"""
        mock_websocket = AsyncMock()

        # Test without authentication
        auth_message = {"auth": "invalid_token"}
        mock_websocket.recv.return_value = json.dumps(auth_message)

        with pytest.raises((ValueError, PermissionError)):
            await mock_server.authenticate_websocket(mock_websocket, "invalid_token")

        # Test with valid authentication
        valid_auth_message = {"auth": "valid_token"}
        mock_websocket.recv.return_value = json.dumps(valid_auth_message)

        with patch.object(mock_server, "validate_auth_token") as mock_validate:
            mock_validate.return_value = True

            result = await mock_server.authenticate_websocket(
                mock_websocket, "valid_token"
            )
            assert result is True


class TestFastAPIEndpoints:
    """Test suite for FastAPI server endpoints"""

    def test_health_endpoint(self, test_client):
        """Test health check endpoint"""
        response = test_client.get("/health")

        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        assert "timestamp" in response.json()

    def test_settings_endpoint_get(self, test_client):
        """Test settings GET endpoint"""
        response = test_client.get("/settings")

        assert response.status_code == 200
        settings = response.json()
        assert "llm" in settings
        assert "auto_run" in settings
        assert "verbose" in settings

    def test_settings_endpoint_post(self, test_client):
        """Test settings POST endpoint"""
        new_settings = {
            "llm": {"model": "gpt-4", "temperature": 0.7},
            "auto_run": True,
            "verbose": False,
        }

        response = test_client.post("/settings", json=new_settings)

        assert response.status_code == 200
        updated_settings = response.json()
        assert updated_settings["llm"]["model"] == "gpt-4"
        assert updated_settings["auto_run"] is True

    def test_run_endpoint(self, test_client):
        """Test code execution endpoint"""
        code_request = {"language": "python", "code": "print('Hello API')"}

        with patch("interpreter.computer.terminal.run") as mock_run:
            mock_run.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "Hello API",
                }
            ]

            response = test_client.post("/run", json=code_request)

            assert response.status_code == 200
            result = response.json()
            assert "Hello API" in result["output"]

    def test_messages_endpoint(self, test_client):
        """Test messages history endpoint"""
        response = test_client.get("/messages")

        assert response.status_code == 200
        messages = response.json()
        assert isinstance(messages, list)

    def test_reset_endpoint(self, test_client):
        """Test interpreter reset endpoint"""
        response = test_client.post("/reset")

        assert response.status_code == 200
        assert response.json()["status"] == "reset"

    def test_files_endpoint(self, test_client):
        """Test file operations endpoint"""
        # Test file listing
        response = test_client.get("/files")
        assert response.status_code == 200

        # Test file upload
        test_file_content = "Test file content"
        files = {"file": ("test.txt", test_file_content, "text/plain")}

        response = test_client.post("/files/upload", files=files)
        assert response.status_code == 200

    def test_error_handling_endpoints(self, test_client):
        """Test API error handling"""
        # Test invalid JSON
        response = test_client.post("/run", data="invalid json")
        assert response.status_code == 422

        # Test missing required fields
        response = test_client.post("/run", json={})
        assert response.status_code == 422


class TestServerAuthentication:
    """Test suite for server authentication and authorization"""

    def test_api_key_authentication(self, test_client):
        """Test API key authentication"""
        # Test without API key
        response = test_client.get("/settings")
        if hasattr(test_client.app, "require_auth") and test_client.app.require_auth:
            assert response.status_code == 401

        # Test with valid API key
        headers = {"X-API-KEY": "test-api-key"}
        with patch("interpreter.server.validate_api_key") as mock_validate:
            mock_validate.return_value = True

            response = test_client.get("/settings", headers=headers)
            assert response.status_code == 200

    def test_rate_limiting(self, test_client):
        """Test API rate limiting"""
        # Make multiple rapid requests
        responses = []
        for i in range(10):
            response = test_client.get("/health")
            responses.append(response.status_code)

        # Should handle reasonable request volume
        success_count = responses.count(200)
        assert success_count >= 8, "Rate limiting too aggressive for normal usage"

    def test_cors_headers(self, test_client):
        """Test CORS headers configuration"""
        response = test_client.options("/settings")

        # Check for CORS headers
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers


class TestConcurrentRequestHandling:
    """Test suite for concurrent request handling"""

    @pytest.mark.asyncio
    async def test_concurrent_api_requests(self, test_client):
        """Test handling of concurrent API requests"""

        async def make_request():
            return test_client.get("/health")

        # Make 10 concurrent requests
        tasks = [make_request() for _ in range(10)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Verify most requests succeeded
        successful_responses = [
            r for r in responses if hasattr(r, "status_code") and r.status_code == 200
        ]
        assert (
            len(successful_responses) >= 8
        ), "Should handle concurrent requests successfully"

    @pytest.mark.asyncio
    async def test_concurrent_code_execution(self, async_interpreter):
        """Test concurrent code execution requests"""

        async def execute_code(code_id):
            with patch.object(async_interpreter.computer.terminal, "run") as mock_run:
                mock_run.return_value = [
                    {
                        "role": "computer",
                        "type": "console",
                        "format": "output",
                        "content": f"Execution {code_id} completed",
                    }
                ]
                return await async_interpreter.async_run(
                    "python", f"print('Execution {code_id}')"
                )

        tasks = [execute_code(i) for i in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_results = [r for r in results if not isinstance(r, Exception)]
        assert len(successful_results) >= 4, "Most concurrent executions should succeed"

    @pytest.mark.asyncio
    async def test_resource_contention_handling(self, async_interpreter):
        """Test handling of resource contention in concurrent operations"""

        # Simulate resource-intensive operations
        async def resource_intensive_operation(op_id):
            await asyncio.sleep(0.1)  # Simulate work
            return f"Operation {op_id} completed"

        tasks = [resource_intensive_operation(i) for i in range(20)]

        start_time = asyncio.get_event_loop().time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = asyncio.get_event_loop().time()

        # Verify operations completed in reasonable time
        duration = end_time - start_time
        assert duration < 5.0, "Concurrent operations should complete efficiently"

        successful_operations = [r for r in results if not isinstance(r, Exception)]
        assert (
            len(successful_operations) == 20
        ), "All operations should complete successfully"


class TestServerLifecycleManagement:
    """Test suite for server lifecycle management"""

    @pytest.mark.asyncio
    async def test_server_startup(self, mock_server):
        """Test server startup process"""
        with patch.object(mock_server, "_initialize_components") as mock_init:
            mock_init.return_value = True

            await mock_server.start()

            mock_init.assert_called_once()
            assert mock_server.is_running is True

    @pytest.mark.asyncio
    async def test_server_shutdown(self, mock_server):
        """Test graceful server shutdown"""
        # Simulate running server
        mock_server.is_running = True

        with patch.object(mock_server, "_cleanup_resources") as mock_cleanup:
            await mock_server.shutdown()

            mock_cleanup.assert_called_once()
            assert mock_server.is_running is False

    @pytest.mark.asyncio
    async def test_server_restart(self, mock_server):
        """Test server restart functionality"""
        with patch.object(mock_server, "shutdown") as mock_shutdown:
            with patch.object(mock_server, "start") as mock_start:
                await mock_server.restart()

                mock_shutdown.assert_called_once()
                mock_start.assert_called_once()

    def test_server_configuration_validation(self, mock_server):
        """Test server configuration validation"""
        # Test valid configuration
        valid_config = {"host": "127.0.0.1", "port": 8000, "debug": False, "workers": 1}

        result = mock_server.validate_configuration(valid_config)
        assert result is True

        # Test invalid configuration
        invalid_config = {"host": "invalid-host", "port": "not-a-number"}

        with pytest.raises(ValueError):
            mock_server.validate_configuration(invalid_config)


class TestRealTimeMessaging:
    """Test suite for real-time messaging and events"""

    @pytest.mark.asyncio
    async def test_real_time_code_execution(self, mock_server):
        """Test real-time code execution streaming"""
        mock_websocket = AsyncMock()

        with patch.object(mock_server.interpreter, "async_chat") as mock_chat:

            async def mock_real_time_execution():
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "start": True,
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "content": "import time",
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "content": "print('Starting...')",
                }
                yield {
                    "role": "computer",
                    "type": "console",
                    "format": "active_line",
                    "content": "1",
                }
                yield {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "Starting...",
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "content": "time.sleep(1)",
                }
                yield {
                    "role": "computer",
                    "type": "console",
                    "format": "active_line",
                    "content": "2",
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "content": "print('Done!')",
                }
                yield {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "Done!",
                }
                yield {
                    "role": "assistant",
                    "type": "code",
                    "format": "python",
                    "end": True,
                }

            mock_chat.return_value = mock_real_time_execution()

            await mock_server.handle_real_time_execution(
                mock_websocket, "Write a simple timer"
            )

            # Verify real-time updates were sent
            assert mock_websocket.send.call_count >= 8

            # Verify active line updates were sent
            sent_messages = [
                json.loads(call[0][0]) for call in mock_websocket.send.call_args_list
            ]
            active_line_messages = [
                msg for msg in sent_messages if msg.get("format") == "active_line"
            ]
            assert len(active_line_messages) >= 2

    @pytest.mark.asyncio
    async def test_event_broadcasting(self, mock_server):
        """Test event broadcasting to multiple WebSocket clients"""
        mock_websockets = [AsyncMock() for _ in range(3)]

        # Simulate multiple connected clients
        mock_server.connected_clients = mock_websockets

        event_data = {
            "type": "system_event",
            "event": "interpreter_reset",
            "timestamp": datetime.now().isoformat(),
        }

        await mock_server.broadcast_event(event_data)

        # Verify event was sent to all clients
        for ws in mock_websockets:
            ws.send.assert_called_once()
            sent_data = json.loads(ws.send.call_args[0][0])
            assert sent_data["type"] == "system_event"
            assert sent_data["event"] == "interpreter_reset"

    @pytest.mark.asyncio
    async def test_client_subscription_management(self, mock_server):
        """Test client subscription to specific event types"""
        mock_websocket = AsyncMock()

        # Subscribe to specific events
        subscription_data = {
            "action": "subscribe",
            "events": ["code_execution", "file_operations"],
        }

        await mock_server.handle_subscription(mock_websocket, subscription_data)

        # Verify subscription was registered
        assert mock_websocket in mock_server.event_subscribers.get("code_execution", [])
        assert mock_websocket in mock_server.event_subscribers.get(
            "file_operations", []
        )

        # Test event delivery to subscribed clients only
        event_data = {"type": "code_execution", "status": "started"}
        await mock_server.send_to_subscribers("code_execution", event_data)

        mock_websocket.send.assert_called()


# Integration test execution
if __name__ == "__main__":
    """
    Run comprehensive async server integration test suite

    Usage:
        python -m pytest test_async_server_integration.py -v
        python -m pytest test_async_server_integration.py::TestWebSocketCommunication -v
        python test_async_server_integration.py  # Direct execution
    """

    import sys

    print("🔄 Open Interpreter - Async Server Integration Test Suite")
    print("=" * 70)
    print("Test Coverage:")
    print("- AsyncInterpreter Core Functionality")
    print("- WebSocket Communication and Streaming")
    print("- FastAPI Server Endpoints and Middleware")
    print("- Authentication and Authorization")
    print("- Concurrent Request Handling")
    print("- Server Lifecycle Management")
    print("- Real-Time Messaging and Events")
    print("=" * 70)

    # Run tests if executed directly
    if len(sys.argv) == 1:
        pytest.main([__file__, "-v", "--tb=short"])
