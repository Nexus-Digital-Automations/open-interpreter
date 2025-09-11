"""
Enhanced Python Language Implementation with Structured JSON Output Support

This module provides a comprehensive Python code execution environment with
structured JSON output capture, specifically designed for integration with
Jupyter kernels and supporting advanced features like matplotlib plot capture,
file system monitoring, and execution context management.

Key Features:
- Jupyter kernel integration with structured output capture
- Matplotlib plot and image output handling
- Python-specific error parsing and exception handling
- Package import tracking and environment management
- File system monitoring for Python-generated files
- Interactive execution with active line tracking
- Performance profiling and memory usage monitoring

Author: Language-Specific Subclasses Specialist
Date: 2025-09-09
"""

import ast
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from jupyter_client import KernelManager

    JUPYTER_AVAILABLE = True
except ImportError:
    JUPYTER_AVAILABLE = False

from .enhanced_base_language import EnhancedBaseLanguage, StructuredExecutionResult


class EnhancedPython(EnhancedBaseLanguage):
    """
    Enhanced Python language implementation with structured JSON output

    This class provides comprehensive Python code execution with Jupyter kernel
    integration, structured output capture, and advanced monitoring capabilities.

    Features:
    - Jupyter kernel management and execution
    - Structured output capture with JSON formatting
    - Matplotlib and image output handling
    - Python-specific error parsing and exception tracking
    - Interactive execution with active line markers
    - Import tracking and dependency monitoring
    - Performance profiling and resource usage tracking
    """

    file_extension = "py"
    name = "Python"
    aliases = ["py", "python3", "jupyter"]

    def __init__(self, computer=None):
        super().__init__(computer)

        # Jupyter kernel management
        self.km: Optional[KernelManager] = None
        self.kc = None
        self.kernel_ready = False

        # Python-specific tracking
        self.imported_packages = set()
        self.matplotlib_backend = None
        self.active_variables = {}

        # Execution context
        self.listener_thread = None
        self.finish_flag = False
        self.message_queue = None

        # Initialize kernel
        self._initialize_kernel()

    def _initialize_kernel(self):
        """
        Initialize Jupyter kernel for Python execution
        """
        if not JUPYTER_AVAILABLE:
            self.logger.warning("Jupyter not available, using subprocess fallback")
            return

        try:
            self.km = KernelManager(kernel_name="python3")
            self.km.start_kernel()
            self.kc = self.km.client()
            self.kc.start_channels()

            # Wait for kernel to be ready
            timeout = 30  # 30 second timeout
            start_time = time.time()

            while not self.kc.is_alive() and time.time() - start_time < timeout:
                time.sleep(0.1)

            if self.kc.is_alive():
                time.sleep(0.5)  # Additional startup time
                self._setup_kernel_environment()
                self.kernel_ready = True

                self.logger.info("Jupyter Python kernel initialized successfully")
            else:
                self.logger.error("Jupyter kernel failed to start within timeout")

        except Exception as e:
            self.logger.error(f"Failed to initialize Jupyter kernel: {e}")
            self.kernel_ready = False

    def _setup_kernel_environment(self):
        """
        Setup the kernel environment with necessary imports and configuration
        """
        if not self.kernel_ready or not self.kc:
            return

        setup_code = """
# Setup matplotlib for structured output
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt

# Import common libraries
import sys
import os
import json
import traceback
from datetime import datetime
import uuid

# Setup inline plotting
%matplotlib inline

# Configure pandas display options if available
try:
    import pandas as pd
    pd.set_option('display.max_columns', 10)
    pd.set_option('display.max_rows', 10)
except ImportError:
    pass

# Setup numpy if available
try:
    import numpy as np
    np.set_printoptions(precision=4, suppress=True)
except ImportError:
    pass

print("Python kernel environment initialized")
        """.strip()

        # Execute setup code silently
        self.kc.execute(setup_code, silent=True)

    def _get_language_version(self) -> Optional[str]:
        """
        Get Python version information

        Returns:
            Python version string
        """
        try:
            return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        except Exception:
            return None

    def _detect_language_specific_errors(self, output: str) -> Optional[str]:
        """
        Parse Python-specific error patterns from output

        Args:
            output: Output text to analyze

        Returns:
            Parsed error message, or None if no error detected
        """
        # Common Python error patterns
        error_patterns = [
            r"Traceback \(most recent call last\):",
            r"(\w+Error): (.+)",
            r"(\w+Exception): (.+)",
            r"SyntaxError: (.+)",
            r"IndentationError: (.+)",
            r"KeyboardInterrupt",
        ]

        for pattern in error_patterns:
            match = re.search(pattern, output)
            if match:
                if len(match.groups()) >= 2:
                    return f"{match.group(1)}: {match.group(2)}"
                else:
                    return match.group(0)

        return None

    def _execute_with_capture(self, code: str, result: StructuredExecutionResult):
        """
        Execute Python code with comprehensive output capture

        Args:
            code: Python code to execute
            result: StructuredExecutionResult to populate
        """
        if not self.kernel_ready or not self.kc:
            self._fallback_subprocess_execution(code, result)
            return

        try:
            # Preprocess code for structured execution
            processed_code = self._preprocess_python_code(code)

            # Setup message capture
            self.message_queue = queue.Queue()
            self.finish_flag = False

            # Start message listener thread
            self.listener_thread = threading.Thread(
                target=self._jupyter_message_listener, args=(result,), daemon=True
            )
            self.listener_thread.start()

            # Execute code
            msg_id = self.kc.execute(processed_code)
            result.metadata["jupyter_msg_id"] = msg_id

            # Wait for execution completion
            self._wait_for_execution_completion()

            # Process any remaining messages
            self._process_remaining_messages(result)

            # Capture final state
            self._capture_final_execution_state(result)

        except Exception as e:
            result.error = str(e)
            result.exit_code = 1
            self.logger.error(f"Jupyter execution failed: {e}")

    def _preprocess_python_code(self, code: str) -> str:
        """
        Preprocess Python code for structured execution

        Args:
            code: Original Python code

        Returns:
            Preprocessed code with active line markers and error handling
        """
        try:
            # Add active line markers if enabled
            if (
                os.environ.get("INTERPRETER_ACTIVE_LINE_DETECTION", "True").lower()
                == "true"
            ):
                code = self._add_active_line_prints(code)

            # Add execution completion marker
            code += '\nprint("##end_of_execution##")'

            return code

        except Exception as e:
            self.logger.warning(f"Code preprocessing failed: {e}")
            return code + '\nprint("##end_of_execution##")'

    def _add_active_line_prints(self, code: str) -> str:
        """
        Add print statements for active line tracking

        Args:
            code: Original Python code

        Returns:
            Code with active line markers
        """
        try:
            # Parse code into AST for intelligent line marker insertion
            tree = ast.parse(code)
            transformer = ActiveLinePrintTransformer()
            new_tree = transformer.visit(tree)
            return ast.unparse(new_tree)

        except SyntaxError:
            # Fallback to simple line-by-line processing for invalid syntax
            return self._add_simple_active_line_prints(code)
        except Exception:
            # Final fallback - return original code
            return code

    def _add_simple_active_line_prints(self, code: str) -> str:
        """
        Simple active line marker insertion (fallback method)

        Args:
            code: Original Python code

        Returns:
            Code with simple line markers
        """
        lines = code.split("\n")
        processed_lines = []

        for i, line in enumerate(lines, 1):
            # Skip empty lines and comments
            if line.strip() and not line.strip().startswith("#"):
                processed_lines.append(f'print("##active_line{i}##")')
            processed_lines.append(line)

        return "\n".join(processed_lines)

    def _jupyter_message_listener(self, result: StructuredExecutionResult):
        """
        Listen for Jupyter kernel messages and process output

        Args:
            result: StructuredExecutionResult to populate
        """
        try:
            while not self.finish_flag:
                try:
                    msg = self.kc.iopub_channel.get_msg(timeout=0.1)
                    self._process_jupyter_message(msg, result)

                except queue.Empty:
                    continue
                except Exception as e:
                    self.logger.warning(f"Message processing error: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Message listener error: {e}")
        finally:
            self.finish_flag = True

    def _process_jupyter_message(
        self, msg: Dict[str, Any], result: StructuredExecutionResult
    ):
        """
        Process individual Jupyter kernel message

        Args:
            msg: Jupyter message
            result: StructuredExecutionResult to update
        """
        msg_type = msg["msg_type"]
        content = msg["content"]

        if msg_type == "status" and content["execution_state"] == "idle":
            # Kernel finished execution
            self.finish_flag = True
            return

        elif msg_type == "stream":
            # Handle stdout/stderr streams
            stream_content = content["text"]

            # Check for active line markers
            if "##active_line" in stream_content:
                line_number = self._extract_active_line_number(stream_content)
                if line_number:
                    self._update_active_line(line_number)
                # Remove marker from output
                stream_content = re.sub(r"##active_line\d+##\n?", "", stream_content)

            # Check for end of execution marker
            if "##end_of_execution##" in stream_content:
                stream_content = stream_content.replace(
                    "##end_of_execution##", ""
                ).strip()
                self.finish_flag = True

            if stream_content:
                if content["name"] == "stdout":
                    self._append_stdout(stream_content)
                elif content["name"] == "stderr":
                    self._append_stderr(stream_content)

        elif msg_type == "error":
            # Handle execution errors
            error_content = "\n".join(content["traceback"])
            # Remove ANSI escape codes
            error_content = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", error_content)
            self._append_stderr(error_content)
            result.exit_code = 1

        elif msg_type in ["display_data", "execute_result"]:
            # Handle rich output (plots, images, HTML, etc.)
            self._process_rich_output(content["data"], result)

    def _extract_active_line_number(self, text: str) -> Optional[int]:
        """
        Extract active line number from text

        Args:
            text: Text containing active line marker

        Returns:
            Line number or None
        """
        match = re.search(r"##active_line(\d+)##", text)
        return int(match.group(1)) if match else None

    def _process_rich_output(
        self, data: Dict[str, Any], result: StructuredExecutionResult
    ):
        """
        Process rich output from Jupyter (images, HTML, etc.)

        Args:
            data: Rich output data
            result: StructuredExecutionResult to update
        """
        # Handle matplotlib plots
        if "image/png" in data:
            image_data = data["image/png"]
            result.metadata.setdefault("images", []).append(
                {
                    "type": "png",
                    "data": image_data,
                    "timestamp": datetime.now().isoformat(),
                }
            )
            self._append_stdout("[Image generated: PNG plot]\n")

        elif "image/jpeg" in data:
            image_data = data["image/jpeg"]
            result.metadata.setdefault("images", []).append(
                {
                    "type": "jpeg",
                    "data": image_data,
                    "timestamp": datetime.now().isoformat(),
                }
            )
            self._append_stdout("[Image generated: JPEG plot]\n")

        # Handle HTML output
        elif "text/html" in data:
            html_content = data["text/html"]
            result.metadata.setdefault("html_outputs", []).append(
                {"content": html_content, "timestamp": datetime.now().isoformat()}
            )
            self._append_stdout("[HTML output generated]\n")

        # Handle JavaScript output
        elif "application/javascript" in data:
            js_content = data["application/javascript"]
            result.metadata.setdefault("javascript_outputs", []).append(
                {"content": js_content, "timestamp": datetime.now().isoformat()}
            )
            self._append_stdout("[JavaScript output generated]\n")

        # Handle plain text output
        elif "text/plain" in data:
            plain_content = data["text/plain"]
            self._append_stdout(plain_content + "\n")

    def _wait_for_execution_completion(self):
        """
        Wait for execution to complete with timeout handling
        """
        timeout = 300  # 5 minute timeout
        start_time = time.time()

        while not self.finish_flag and time.time() - start_time < timeout:
            time.sleep(0.1)

            # Check for stop events
            if (
                hasattr(self.computer, "interpreter")
                and hasattr(self.computer.interpreter, "stop_event")
                and self.computer.interpreter.stop_event.is_set()
            ):
                self.finish_flag = True
                break

        if not self.finish_flag:
            self.logger.warning("Execution did not complete within timeout")
            self.finish_flag = True

    def _process_remaining_messages(self, result: StructuredExecutionResult):
        """
        Process any remaining messages in the queue

        Args:
            result: StructuredExecutionResult to update
        """
        # Give a short time for any final messages
        time.sleep(0.2)

        # Process remaining messages
        remaining_count = 0
        while remaining_count < 10:  # Limit to prevent infinite loop
            try:
                msg = self.kc.iopub_channel.get_msg(timeout=0.05)
                self._process_jupyter_message(msg, result)
                remaining_count += 1
            except queue.Empty:
                break
            except Exception:
                break

    def _capture_final_execution_state(self, result: StructuredExecutionResult):
        """
        Capture final execution state and environment information

        Args:
            result: StructuredExecutionResult to update
        """
        try:
            # Capture environment variables and system info
            state_query = """
import sys
import os
import psutil

# Get basic system info
print(f"Python version: {sys.version}")
print(f"Platform: {sys.platform}")
print(f"Current working directory: {os.getcwd()}")

# Get memory usage
process = psutil.Process()
memory_info = process.memory_info()
print(f"Memory usage: {memory_info.rss / 1024 / 1024:.2f} MB")

# List imported modules
imported_modules = sorted([name for name in sys.modules.keys() if not name.startswith('_')])
print(f"Imported modules count: {len(imported_modules)}")
            """.strip()

            # Execute state query silently
            self.kc.execute(state_query, silent=True)

        except Exception as e:
            self.logger.warning(f"Could not capture final execution state: {e}")

    def _fallback_subprocess_execution(
        self, code: str, result: StructuredExecutionResult
    ):
        """
        Fallback execution using subprocess when Jupyter is not available

        Args:
            code: Python code to execute
            result: StructuredExecutionResult to populate
        """
        try:
            # Write code to temporary file
            temp_file = Path(f"/tmp/python_exec_{uuid.uuid4().hex}.py")
            temp_file.write_text(code)

            # Execute with subprocess
            process = subprocess.run(
                [sys.executable, str(temp_file)],
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=result.working_directory,
            )

            result.stdout = process.stdout
            result.stderr = process.stderr
            result.exit_code = process.returncode

            # Clean up
            temp_file.unlink()

        except subprocess.TimeoutExpired:
            result.error = "Execution timed out"
            result.exit_code = 124
        except Exception as e:
            result.error = str(e)
            result.exit_code = 1

    def stop(self):
        """
        Stop current execution
        """
        self.finish_flag = True

        if self.kc:
            try:
                self.km.interrupt_kernel()
            except Exception:
                pass

    def terminate(self):
        """
        Terminate kernel and cleanup resources
        """
        self.finish_flag = True

        if self.kc:
            try:
                self.kc.stop_channels()
            except Exception:
                pass

        if self.km:
            try:
                self.km.shutdown_kernel()
            except Exception:
                pass

        self.kernel_ready = False

    def run(self, code):
        """
        Legacy run method for backward compatibility

        This method maintains compatibility with the existing interface while
        providing basic structured output when possible.
        """
        if self._structured_mode and self._current_execution:
            # We're already in structured mode, just execute
            self._execute_with_capture(code, self._current_execution)
            return []
        else:
            # Legacy mode - use basic Jupyter execution
            return self._run_legacy_mode(code)

    def _run_legacy_mode(self, code):
        """
        Run in legacy mode for backward compatibility

        Args:
            code: Python code to execute

        Returns:
            List of output messages in LMC format
        """
        if not self.kernel_ready or not self.kc:
            return [
                {
                    "type": "console",
                    "format": "output",
                    "content": "Python kernel not available",
                }
            ]

        try:
            # Execute code
            processed_code = self._preprocess_python_code(code)
            self.finish_flag = False

            output_messages = []

            # Setup message capture for legacy mode
            message_queue = queue.Queue()

            def legacy_message_listener():
                while not self.finish_flag:
                    try:
                        msg = self.kc.iopub_channel.get_msg(timeout=0.1)
                        message_queue.put(msg)
                    except queue.Empty:
                        continue
                    except Exception:
                        break

            # Start listener
            listener_thread = threading.Thread(
                target=legacy_message_listener, daemon=True
            )
            listener_thread.start()

            # Execute code
            self.kc.execute(processed_code)

            # Process messages
            timeout = time.time() + 30  # 30 second timeout
            while not self.finish_flag and time.time() < timeout:
                try:
                    msg = message_queue.get(timeout=0.1)
                    legacy_output = self._process_legacy_message(msg)
                    if legacy_output:
                        output_messages.extend(legacy_output)
                except queue.Empty:
                    continue

            return output_messages

        except Exception as e:
            return [
                {"type": "console", "format": "output", "content": f"Error: {str(e)}"}
            ]

    def _process_legacy_message(self, msg: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process Jupyter message for legacy output format

        Args:
            msg: Jupyter message

        Returns:
            List of output messages in LMC format
        """
        msg_type = msg["msg_type"]
        content = msg["content"]
        output = []

        if msg_type == "status" and content["execution_state"] == "idle":
            self.finish_flag = True

        elif msg_type == "stream":
            stream_content = content["text"]

            # Handle active line markers
            if "##active_line" in stream_content:
                line_number = self._extract_active_line_number(stream_content)
                if line_number:
                    output.append(
                        {
                            "type": "console",
                            "format": "active_line",
                            "content": line_number,
                        }
                    )
                stream_content = re.sub(r"##active_line\d+##\n?", "", stream_content)

            # Handle end of execution
            if "##end_of_execution##" in stream_content:
                stream_content = stream_content.replace(
                    "##end_of_execution##", ""
                ).strip()
                self.finish_flag = True

            if stream_content:
                output.append(
                    {"type": "console", "format": "output", "content": stream_content}
                )

        elif msg_type == "error":
            error_content = "\n".join(content["traceback"])
            error_content = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", error_content)
            output.append(
                {"type": "console", "format": "output", "content": error_content}
            )

        elif msg_type in ["display_data", "execute_result"]:
            data = content["data"]

            if "image/png" in data:
                output.append(
                    {
                        "type": "image",
                        "format": "base64.png",
                        "content": data["image/png"],
                    }
                )
            elif "image/jpeg" in data:
                output.append(
                    {
                        "type": "image",
                        "format": "base64.jpeg",
                        "content": data["image/jpeg"],
                    }
                )
            elif "text/html" in data:
                output.append(
                    {"type": "code", "format": "html", "content": data["text/html"]}
                )
            elif "text/plain" in data:
                output.append(
                    {
                        "type": "console",
                        "format": "output",
                        "content": data["text/plain"],
                    }
                )
            elif "application/javascript" in data:
                output.append(
                    {
                        "type": "code",
                        "format": "javascript",
                        "content": data["application/javascript"],
                    }
                )

        return output


class ActiveLinePrintTransformer(ast.NodeTransformer):
    """
    AST transformer to insert print statements for active line tracking

    This transformer intelligently inserts active line markers before executable
    statements while preserving the code structure and avoiding syntax errors.
    """

    def insert_print_statement(self, line_number: int) -> ast.Expr:
        """
        Create a print statement for active line tracking

        Args:
            line_number: Line number to mark as active

        Returns:
            AST expression node for the print statement
        """
        return ast.Expr(
            value=ast.Call(
                func=ast.Name(id="print", ctx=ast.Load()),
                args=[ast.Constant(value=f"##active_line{line_number}##")],
                keywords=[],
            )
        )

    def process_body(self, body: List[ast.stmt]) -> List[ast.stmt]:
        """
        Process a block of statements, adding print calls

        Args:
            body: List of AST statement nodes

        Returns:
            Modified list with active line markers
        """
        new_body = []

        for stmt in body:
            if hasattr(stmt, "lineno"):
                # Insert active line marker before executable statements
                if self._should_add_marker(stmt):
                    new_body.append(self.insert_print_statement(stmt.lineno))
            new_body.append(stmt)

        return new_body

    def _should_add_marker(self, stmt: ast.stmt) -> bool:
        """
        Determine if active line marker should be added for this statement

        Args:
            stmt: AST statement node

        Returns:
            True if marker should be added
        """
        # Don't add markers for certain statement types
        skip_types = (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)
        return not isinstance(stmt, skip_types)

    def visit(self, node: ast.AST) -> ast.AST:
        """
        Visit AST node and transform if needed

        Args:
            node: AST node to visit

        Returns:
            Transformed AST node
        """
        new_node = super().visit(node)

        # Process nodes with body attributes
        if hasattr(new_node, "body") and isinstance(new_node.body, list):
            new_node.body = self.process_body(new_node.body)

        # Process orelse blocks (for if/while/for statements)
        if hasattr(new_node, "orelse") and new_node.orelse:
            new_node.orelse = self.process_body(new_node.orelse)

        # Special handling for try statements
        if isinstance(new_node, ast.Try):
            # Process exception handlers
            for handler in new_node.handlers:
                if hasattr(handler, "body"):
                    handler.body = self.process_body(handler.body)
            # Process finally block
            if new_node.finalbody:
                new_node.finalbody = self.process_body(new_node.finalbody)

        return new_node


# Legacy compatibility - maintain original Python class behavior
class Python(EnhancedPython):
    """
    Legacy Python class that extends EnhancedPython

    This maintains backward compatibility with existing code while providing
    access to enhanced structured output capabilities.
    """

    pass
