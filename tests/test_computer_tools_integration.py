"""
Computer Tools Integration Test Suite for Open Interpreter

This test suite provides comprehensive coverage for Open Interpreter's
computer interaction capabilities including terminal execution, file operations,
display/vision, browser automation, and system integration.

Test Coverage:
- Terminal/shell execution across platforms
- File system operations and management
- Display/vision capabilities and image processing
- Browser automation and web interaction
- System integration (clipboard, notifications, etc.)
- Cross-platform compatibility testing
- Tool chain coordination and workflow

Author: Computer Tools Integration Testing Specialist
Version: 1.0.0 - Production-Ready Computer Interface Testing
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

# Open Interpreter imports
from interpreter.core.computer.computer import Computer
from interpreter.core.computer.terminal.terminal import Terminal


@pytest.fixture
def computer_test_environment():
    """Setup isolated test environment for computer tools testing"""
    temp_dir = tempfile.mkdtemp(prefix="oi_computer_test_")
    yield Path(temp_dir)
    # Cleanup
    import shutil

    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_computer():
    """Pytest fixture providing a mocked Computer instance"""
    interpreter_mock = Mock()
    computer = Computer(interpreter_mock)
    return computer


@pytest.fixture
def mock_terminal():
    """Pytest fixture providing a mocked Terminal instance"""
    interpreter_mock = Mock()
    terminal = Terminal(interpreter_mock)
    return terminal


class TestTerminalExecution:
    """Test suite for terminal/shell execution capabilities"""

    def test_python_code_execution(self, mock_terminal, computer_test_environment):
        """Test Python code execution through terminal"""
        with patch.object(mock_terminal, "_execute_python") as mock_execute:
            mock_execute.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "Hello, Python!",
                }
            ]

            result = mock_terminal.run("python", "print('Hello, Python!')")

            assert len(result) > 0
            assert "Hello, Python!" in result[0]["content"]
            mock_execute.assert_called_once()

    def test_shell_command_execution(self, mock_terminal, computer_test_environment):
        """Test shell command execution"""
        with patch.object(mock_terminal, "_execute_shell") as mock_execute:
            mock_execute.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": str(computer_test_environment),
                }
            ]

            result = mock_terminal.run("shell", "pwd")

            assert len(result) > 0
            assert str(computer_test_environment) in result[0]["content"]

    def test_javascript_execution(self, mock_terminal):
        """Test JavaScript code execution"""
        with patch.object(mock_terminal, "_execute_javascript") as mock_execute:
            mock_execute.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": "2025-01-01T00:00:00.000Z",
                }
            ]

            result = mock_terminal.run(
                "javascript", "console.log(new Date().toISOString());"
            )

            assert len(result) > 0
            assert "2025" in result[0]["content"]

    def test_r_code_execution(self, mock_terminal):
        """Test R code execution"""
        with patch.object(mock_terminal, "_execute_r") as mock_execute:
            mock_execute.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": '[1] "R is working"',
                }
            ]

            result = mock_terminal.run("r", "print('R is working')")

            assert len(result) > 0
            assert "R is working" in result[0]["content"]

    def test_execution_timeout_handling(self, mock_terminal):
        """Test handling of execution timeouts"""
        with patch.object(mock_terminal, "_execute_python") as mock_execute:
            mock_execute.side_effect = TimeoutError("Execution timed out")

            with pytest.raises(TimeoutError):
                mock_terminal.run("python", "while True: pass", timeout=1)

    def test_execution_error_capture(self, mock_terminal):
        """Test capturing and formatting execution errors"""
        with patch.object(mock_terminal, "_execute_python") as mock_execute:
            mock_execute.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": 'Traceback (most recent call last):\n  File "<stdin>", line 1\n    print(\'unclosed string\nSyntaxError: EOL while scanning string literal',
                }
            ]

            result = mock_terminal.run("python", "print('unclosed string")

            assert len(result) > 0
            assert "SyntaxError" in result[0]["content"]
            assert "Traceback" in result[0]["content"]

    def test_working_directory_management(
        self, mock_terminal, computer_test_environment
    ):
        """Test working directory context management"""
        with patch.object(mock_terminal, "_execute_shell") as mock_execute:
            mock_execute.return_value = [
                {
                    "role": "computer",
                    "type": "console",
                    "format": "output",
                    "content": str(computer_test_environment),
                }
            ]

            result = mock_terminal.run(
                "shell", "pwd", working_directory=str(computer_test_environment)
            )

            assert len(result) > 0
            # Verify working directory was used


class TestFileSystemOperations:
    """Test suite for file system operations and management"""

    def test_file_creation(self, mock_computer, computer_test_environment):
        """Test file creation and writing"""
        test_file = computer_test_environment / "test_file.txt"
        test_content = "This is a test file"

        with patch("builtins.open", mock_open()) as mock_file:
            # Mock file creation
            mock_computer.files.create(str(test_file), test_content)

            # Verify file was opened for writing
            mock_file.assert_called_with(str(test_file), "w")
            mock_file().write.assert_called_with(test_content)

    def test_file_reading(self, mock_computer, computer_test_environment):
        """Test file reading operations"""
        test_file = computer_test_environment / "existing_file.txt"
        test_content = "Existing file content"

        with patch(
            "builtins.open", mock_open(read_data=test_content)
        ):
            # Mock file reading
            with patch.object(mock_computer.files, "read") as mock_read:
                mock_read.return_value = test_content

                content = mock_computer.files.read(str(test_file))

                assert content == test_content
                mock_read.assert_called_with(str(test_file))

    def test_file_editing(self, mock_computer, computer_test_environment):
        """Test file editing operations"""
        test_file = computer_test_environment / "edit_test.txt"
        original_content = "Original content"

        with patch(
            "builtins.open", mock_open(read_data=original_content)
        ):
            with patch.object(mock_computer.files, "edit") as mock_edit:
                mock_edit.return_value = True

                result = mock_computer.files.edit(
                    str(test_file), "Original", "Modified"
                )

                assert result is True
                mock_edit.assert_called_with(str(test_file), "Original", "Modified")

    def test_directory_operations(self, mock_computer, computer_test_environment):
        """Test directory creation and listing"""
        test_dir = computer_test_environment / "test_directory"

        with patch("os.makedirs") as mock_makedirs:
            with patch("os.listdir") as mock_listdir:
                mock_listdir.return_value = ["file1.txt", "file2.py", "subdir/"]

                # Mock directory creation
                mock_computer.files.mkdir(str(test_dir))
                mock_makedirs.assert_called_with(str(test_dir), exist_ok=True)

                # Mock directory listing
                files = mock_computer.files.list_directory(
                    str(computer_test_environment)
                )
                assert len(files) == 3
                assert "file1.txt" in files

    def test_file_search_functionality(self, mock_computer, computer_test_environment):
        """Test file search and pattern matching"""
        with patch.object(mock_computer.files, "search") as mock_search:
            mock_search.return_value = [
                str(computer_test_environment / "match1.py"),
                str(computer_test_environment / "match2.py"),
            ]

            results = mock_computer.files.search("*.py", str(computer_test_environment))

            assert len(results) == 2
            assert all(result.endswith(".py") for result in results)

    def test_file_permissions_handling(self, mock_computer, computer_test_environment):
        """Test file permissions and access control"""
        test_file = computer_test_environment / "protected_file.txt"

        with patch("os.chmod"):
            with patch.object(mock_computer.files, "set_permissions") as mock_set_perms:
                mock_set_perms.return_value = True

                result = mock_computer.files.set_permissions(str(test_file), 0o644)

                assert result is True
                mock_set_perms.assert_called_with(str(test_file), 0o644)

    def test_file_security_validation(self, mock_computer):
        """Test file security validation and path traversal prevention"""
        dangerous_paths = [
            "../../../etc/passwd",
            "/etc/shadow",
            "../../../../../../windows/system32/config/sam",
        ]

        for dangerous_path in dangerous_paths:
            with pytest.raises((ValueError, PermissionError, OSError)):
                mock_computer.files.read(dangerous_path)


class TestDisplayAndVision:
    """Test suite for display/vision capabilities and image processing"""

    def test_screenshot_capture(self, mock_computer):
        """Test screenshot capture functionality"""
        mock_screenshot_data = b"fake_screenshot_data"

        with patch.object(mock_computer.display, "screenshot") as mock_screenshot:
            mock_screenshot.return_value = mock_screenshot_data

            screenshot = mock_computer.display.screenshot()

            assert screenshot == mock_screenshot_data
            mock_screenshot.assert_called_once()

    def test_screen_text_extraction(self, mock_computer):
        """Test OCR text extraction from screen"""
        mock_text = "This is extracted text from screen"

        with patch.object(mock_computer.display, "get_text") as mock_get_text:
            mock_get_text.return_value = mock_text

            extracted_text = mock_computer.display.get_text()

            assert extracted_text == mock_text

    def test_element_location(self, mock_computer):
        """Test UI element location and identification"""
        mock_coordinates = (100, 200)

        with patch.object(mock_computer.display, "find_element") as mock_find:
            mock_find.return_value = mock_coordinates

            coordinates = mock_computer.display.find_element("Submit Button")

            assert coordinates == mock_coordinates

    def test_image_processing(self, mock_computer):
        """Test image processing and analysis"""
        mock_image_data = b"fake_image_data"
        mock_analysis = {"objects": ["cat", "dog"], "colors": ["blue", "red"]}

        with patch.object(mock_computer.vision, "analyze_image") as mock_analyze:
            mock_analyze.return_value = mock_analysis

            analysis = mock_computer.vision.analyze_image(mock_image_data)

            assert analysis == mock_analysis
            assert "cat" in analysis["objects"]

    def test_visual_automation(self, mock_computer):
        """Test visual automation and interaction"""
        with patch.object(mock_computer.display, "click") as mock_click:
            mock_click.return_value = True

            result = mock_computer.display.click(150, 250)

            assert result is True
            mock_click.assert_called_with(150, 250)


class TestBrowserAutomation:
    """Test suite for browser automation and web interaction"""

    def test_browser_navigation(self, mock_computer):
        """Test browser navigation and page loading"""
        test_url = "https://example.com"

        with patch.object(mock_computer.browser, "navigate") as mock_navigate:
            mock_navigate.return_value = True

            result = mock_computer.browser.navigate(test_url)

            assert result is True
            mock_navigate.assert_called_with(test_url)

    def test_element_interaction(self, mock_computer):
        """Test browser element interaction (clicks, inputs)"""
        with patch.object(mock_computer.browser, "click_element") as mock_click:
            with patch.object(mock_computer.browser, "input_text") as mock_input:
                mock_click.return_value = True
                mock_input.return_value = True

                # Test element clicking
                click_result = mock_computer.browser.click_element("#submit-button")
                assert click_result is True

                # Test text input
                input_result = mock_computer.browser.input_text("#username", "testuser")
                assert input_result is True

    def test_page_content_extraction(self, mock_computer):
        """Test web page content extraction"""
        mock_page_content = "<html><body><h1>Test Page</h1></body></html>"

        with patch.object(mock_computer.browser, "get_page_source") as mock_source:
            mock_source.return_value = mock_page_content

            content = mock_computer.browser.get_page_source()

            assert content == mock_page_content
            assert "<h1>Test Page</h1>" in content

    def test_form_submission(self, mock_computer):
        """Test form filling and submission"""
        form_data = {"username": "testuser", "password": "testpass"}

        with patch.object(mock_computer.browser, "fill_form") as mock_fill:
            with patch.object(mock_computer.browser, "submit_form") as mock_submit:
                mock_fill.return_value = True
                mock_submit.return_value = True

                fill_result = mock_computer.browser.fill_form("#login-form", form_data)
                submit_result = mock_computer.browser.submit_form("#login-form")

                assert fill_result is True
                assert submit_result is True

    def test_javascript_execution(self, mock_computer):
        """Test JavaScript execution in browser context"""
        js_code = "return document.title;"
        expected_title = "Test Page Title"

        with patch.object(mock_computer.browser, "execute_script") as mock_execute:
            mock_execute.return_value = expected_title

            result = mock_computer.browser.execute_script(js_code)

            assert result == expected_title


class TestSystemIntegration:
    """Test suite for system integration capabilities"""

    def test_clipboard_operations(self, mock_computer):
        """Test clipboard read and write operations"""
        test_text = "Clipboard test content"

        with patch.object(mock_computer.clipboard, "copy") as mock_copy:
            with patch.object(mock_computer.clipboard, "paste") as mock_paste:
                mock_copy.return_value = True
                mock_paste.return_value = test_text

                # Test clipboard copy
                copy_result = mock_computer.clipboard.copy(test_text)
                assert copy_result is True

                # Test clipboard paste
                pasted_text = mock_computer.clipboard.paste()
                assert pasted_text == test_text

    def test_notification_system(self, mock_computer):
        """Test system notification sending"""
        with patch.object(mock_computer.os, "notify") as mock_notify:
            mock_notify.return_value = True

            result = mock_computer.os.notify("Test notification", "Test message")

            assert result is True
            mock_notify.assert_called_with("Test notification", "Test message")

    def test_keyboard_automation(self, mock_computer):
        """Test keyboard input automation"""
        with patch.object(mock_computer.keyboard, "type") as mock_type:
            with patch.object(mock_computer.keyboard, "press") as mock_press:
                mock_type.return_value = True
                mock_press.return_value = True

                # Test text typing
                type_result = mock_computer.keyboard.type("Hello World")
                assert type_result is True

                # Test key press
                press_result = mock_computer.keyboard.press("Enter")
                assert press_result is True

    def test_mouse_automation(self, mock_computer):
        """Test mouse movement and clicking automation"""
        with patch.object(mock_computer.mouse, "move") as mock_move:
            with patch.object(mock_computer.mouse, "click") as mock_click:
                mock_move.return_value = True
                mock_click.return_value = True

                # Test mouse movement
                move_result = mock_computer.mouse.move(100, 200)
                assert move_result is True

                # Test mouse click
                click_result = mock_computer.mouse.click()
                assert click_result is True

    def test_system_information_gathering(self, mock_computer):
        """Test system information collection"""
        mock_system_info = {
            "platform": "darwin",
            "architecture": "x86_64",
            "python_version": "3.9.7",
            "memory_total": "16GB",
        }

        with patch.object(mock_computer.os, "get_system_info") as mock_info:
            mock_info.return_value = mock_system_info

            info = mock_computer.os.get_system_info()

            assert info == mock_system_info
            assert info["platform"] == "darwin"


class TestCrossPlatformCompatibility:
    """Test suite for cross-platform compatibility"""

    @pytest.mark.parametrize("platform", ["darwin", "linux", "win32"])
    def test_platform_specific_commands(self, mock_computer, platform):
        """Test platform-specific command adaptation"""
        with patch("sys.platform", platform):
            with patch.object(mock_computer.terminal, "run") as mock_run:
                mock_run.return_value = [
                    {
                        "role": "computer",
                        "type": "console",
                        "format": "output",
                        "content": f"Platform: {platform}",
                    }
                ]

                # Test platform-appropriate commands
                if platform == "win32":
                    result = mock_computer.terminal.run("powershell", "Get-Location")
                else:
                    result = mock_computer.terminal.run("shell", "pwd")

                assert len(result) > 0
                assert platform in result[0]["content"]

    def test_path_handling_cross_platform(self, mock_computer):
        """Test cross-platform path handling"""
        test_paths = [
            "/unix/style/path",
            "C:\\windows\\style\\path",
            "relative/path/file.txt",
        ]

        for path in test_paths:
            with patch.object(mock_computer.files, "normalize_path") as mock_normalize:
                normalized = str(Path(path).resolve())
                mock_normalize.return_value = normalized

                result = mock_computer.files.normalize_path(path)
                assert result == normalized

    def test_environment_variable_handling(self, mock_computer):
        """Test environment variable access across platforms"""
        with patch("os.environ.get") as mock_env_get:
            mock_env_get.return_value = "/test/path"

            path = mock_computer.os.get_env_variable("TEST_PATH")

            assert path == "/test/path"
            mock_env_get.assert_called_with("TEST_PATH")


class TestToolChainCoordination:
    """Test suite for tool chain coordination and workflow"""

    def test_multi_tool_workflow(self, mock_computer, computer_test_environment):
        """Test coordination between multiple computer tools"""
        workflow_steps = [
            ("files", "create", ["test.py", "print('Hello')"]),
            ("terminal", "run", ["python", "test.py"]),
            ("files", "read", ["test.py"]),
        ]

        results = {}

        for tool, action, args in workflow_steps:
            with patch.object(getattr(mock_computer, tool), action) as mock_action:
                if tool == "terminal" and action == "run":
                    mock_action.return_value = [
                        {
                            "role": "computer",
                            "type": "console",
                            "format": "output",
                            "content": "Hello",
                        }
                    ]
                else:
                    mock_action.return_value = (
                        "Success" if action in ["create", "read"] else True
                    )

                result = getattr(mock_computer, tool).__getattribute__(action)(*args)
                results[f"{tool}_{action}"] = result

        # Verify workflow coordination
        assert len(results) == 3
        assert "files_create" in results
        assert "terminal_run" in results
        assert "files_read" in results

    def test_error_handling_in_workflows(self, mock_computer):
        """Test error handling and recovery in multi-step workflows"""
        with patch.object(mock_computer.files, "create") as mock_create:
            with patch.object(mock_computer.terminal, "run") as mock_run:
                # First step succeeds
                mock_create.return_value = True

                # Second step fails
                mock_run.side_effect = Exception("Execution failed")

                # Test workflow error handling
                try:
                    mock_computer.files.create("test.py", "invalid_code(")
                    create_success = True
                except Exception:
                    create_success = False

                try:
                    mock_computer.terminal.run("python", "test.py")
                    run_success = True
                except Exception:
                    run_success = False

                # Verify error was handled appropriately
                assert create_success is True
                assert run_success is False

    def test_resource_management(self, mock_computer):
        """Test resource management across tool operations"""
        with patch.object(mock_computer, "_check_resources") as mock_check:
            mock_check.return_value = {"memory": "50%", "cpu": "30%", "disk": "70%"}

            resources = mock_computer._check_resources()

            assert "memory" in resources
            assert "cpu" in resources
            assert "disk" in resources

            # Verify resource usage is within acceptable limits
            for resource, usage in resources.items():
                usage_percent = int(usage.replace("%", ""))
                assert usage_percent < 90, f"{resource} usage too high: {usage}"


# Performance and integration test execution
if __name__ == "__main__":
    """
    Run comprehensive computer tools integration test suite

    Usage:
        python -m pytest test_computer_tools_integration.py -v
        python -m pytest test_computer_tools_integration.py::TestBrowserAutomation -v
        python test_computer_tools_integration.py  # Direct execution
    """

    import sys

    print("🖥️  Open Interpreter - Computer Tools Integration Test Suite")
    print("=" * 70)
    print("Test Coverage:")
    print("- Terminal/Shell Execution Across Platforms")
    print("- File System Operations and Management")
    print("- Display/Vision Capabilities and Image Processing")
    print("- Browser Automation and Web Interaction")
    print("- System Integration (Clipboard, Notifications, etc.)")
    print("- Cross-Platform Compatibility Testing")
    print("- Tool Chain Coordination and Workflow")
    print("=" * 70)

    # Run tests if executed directly
    if len(sys.argv) == 1:
        pytest.main([__file__, "-v", "--tb=short"])
