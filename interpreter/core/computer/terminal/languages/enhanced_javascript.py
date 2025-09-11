"""
Enhanced JavaScript Language Implementation with Structured JSON Output Support

This module provides a comprehensive JavaScript/Node.js code execution environment
with structured JSON output capture, designed for seamless integration with
Node.js REPL and supporting advanced features like npm package management,
file system monitoring, and execution context management.

Key Features:
- Node.js REPL integration with structured output capture
- JavaScript-specific error parsing and exception handling
- NPM package import tracking and dependency management
- File system monitoring for JavaScript-generated files
- Interactive execution with active line tracking
- Performance profiling and memory usage monitoring
- ES6+ syntax support and modern JavaScript features

Author: Language-Specific Subclasses Specialist
Date: 2025-09-09
"""

import re
import subprocess
import time
from typing import List, Optional

from .enhanced_base_language import (
    EnhancedSubprocessLanguage,
    StructuredExecutionResult,
)


class EnhancedJavaScript(EnhancedSubprocessLanguage):
    """
    Enhanced JavaScript language implementation with structured JSON output

    This class provides comprehensive JavaScript code execution with Node.js REPL
    integration, structured output capture, and advanced monitoring capabilities.

    Features:
    - Node.js REPL management and execution
    - Structured output capture with JSON formatting
    - JavaScript-specific error parsing and exception tracking
    - Interactive execution with active line markers
    - NPM dependency tracking and package management
    - Performance profiling and resource usage tracking
    - ES6+ syntax support and modern JavaScript features
    """

    file_extension = "js"
    name = "JavaScript"
    aliases = ["js", "node", "nodejs", "javascript"]

    def __init__(self, computer=None):
        super().__init__(computer)

        # JavaScript-specific tracking
        self.imported_packages = set()
        self.node_version = None
        self.npm_packages = set()

        # REPL configuration
        self.repl_ready = False
        self._detect_node_version()

    def _detect_node_version(self):
        """
        Detect Node.js version and validate availability
        """
        try:
            result = subprocess.run(
                ["node", "--version"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                self.node_version = result.stdout.strip()
                self.logger.info(f"Node.js version detected: {self.node_version}")
                self.repl_ready = True
            else:
                self.logger.error("Node.js not available or not working")

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error(f"Failed to detect Node.js: {e}")

    def get_start_command(self) -> List[str]:
        """
        Get the command to start the Node.js REPL

        Returns:
            List of command arguments for Node.js REPL
        """
        return ["node", "-i"]

    def _get_language_version(self) -> Optional[str]:
        """
        Get Node.js version information

        Returns:
            Node.js version string
        """
        return self.node_version

    def _detect_language_specific_errors(self, output: str) -> Optional[str]:
        """
        Parse JavaScript-specific error patterns from output

        Args:
            output: Output text to analyze

        Returns:
            Parsed error message, or None if no error detected
        """
        # Common JavaScript error patterns
        error_patterns = [
            r"(\w+Error): (.+)",
            r"(\w+Exception): (.+)",
            r"ReferenceError: (.+)",
            r"TypeError: (.+)",
            r"SyntaxError: (.+)",
            r"RangeError: (.+)",
            r"Error: (.+)",
            r"Uncaught (.+)",
            r"at (.+\.js:\d+:\d+)",  # Stack trace lines
        ]

        for pattern in error_patterns:
            match = re.search(pattern, output)
            if match:
                if len(match.groups()) >= 2:
                    return f"{match.group(1)}: {match.group(2)}"
                else:
                    return match.group(0)

        return None

    def preprocess_code_structured(self, code: str) -> str:
        """
        Preprocess JavaScript code for structured execution

        Args:
            code: Original JavaScript code

        Returns:
            Preprocessed code with markers and error handling
        """
        try:
            # Detect if code has multiline constructs
            has_multiline = self._detect_multiline_constructs(code)

            if not has_multiline:
                # Add active line markers for simple code
                code = self._add_active_line_markers(code)

            # Wrap in try-catch and add completion marker
            code = self._wrap_with_error_handling(code)

            return code

        except Exception as e:
            self.logger.warning(f"JavaScript code preprocessing failed: {e}")
            return self._wrap_with_error_handling(code)

    def _detect_multiline_constructs(self, code: str) -> bool:
        """
        Detect if JavaScript code contains multiline constructs

        Args:
            code: JavaScript code to analyze

        Returns:
            True if code contains multiline constructs
        """
        multiline_indicators = [
            "{",
            "}",
            "[",
            "]",
            "function",
            "=>",
            "if",
            "for",
            "while",
            "switch",
            "try",
        ]
        return any(indicator in code for indicator in multiline_indicators)

    def _add_active_line_markers(self, code: str) -> str:
        """
        Add console.log statements for active line tracking

        Args:
            code: Original JavaScript code

        Returns:
            Code with active line markers
        """
        lines = code.split("\n")
        processed_lines = []

        for i, line in enumerate(lines, 1):
            # Skip empty lines and comments
            if line.strip() and not line.strip().startswith("//"):
                processed_lines.append(f'console.log("##active_line{i}##");')
            processed_lines.append(line)

        return "\n".join(processed_lines)

    def _wrap_with_error_handling(self, code: str) -> str:
        """
        Wrap JavaScript code with try-catch and completion marker

        Args:
            code: JavaScript code to wrap

        Returns:
            Wrapped code with error handling
        """
        return f"""
try {{
{code}
}} catch (e) {{
    console.error(e);
}}
console.log("##end_of_execution##");
"""

    def line_postprocessor(self, line: str) -> Optional[str]:
        """
        Post-process Node.js REPL output lines

        Args:
            line: Raw output line from Node.js REPL

        Returns:
            Processed line, or None to discard
        """
        # Clean up Node.js REPL artifacts
        if "Welcome to Node.js" in line:
            return None
        if line.strip() in ["undefined", 'Type ".help" for more information.']:
            return None

        # Remove REPL prompt characters
        line = line.strip(". \n")
        line = re.sub(r"^\s*(>\s*)+", "", line)

        return line.rstrip()

    def _clean_execution_markers(self, line: str) -> str:
        """
        Remove JavaScript-specific execution end markers from line

        Args:
            line: Line to clean

        Returns:
            Cleaned line
        """
        return line.replace("##end_of_execution##", "").strip()

    def _extract_package_imports(self, code: str):
        """
        Extract and track package imports from JavaScript code

        Args:
            code: JavaScript code to analyze
        """
        # Track require() statements
        require_pattern = r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"
        requires = re.findall(require_pattern, code)
        self.imported_packages.update(requires)

        # Track ES6 import statements
        import_pattern = r"import\s+.*?\s+from\s+['\"]([^'\"]+)['\"]"
        imports = re.findall(import_pattern, code)
        self.imported_packages.update(imports)

        # Log new packages
        if requires or imports:
            new_packages = (set(requires) | set(imports)) - self.npm_packages
            if new_packages:
                self.logger.info(f"New JavaScript packages detected: {new_packages}")
                self.npm_packages.update(new_packages)

    def _execute_with_capture(self, code: str, result: StructuredExecutionResult):
        """
        Execute JavaScript code with comprehensive output capture

        Args:
            code: JavaScript code to execute
            result: StructuredExecutionResult to populate
        """
        # Track package imports
        self._extract_package_imports(code)

        # Add JavaScript-specific metadata
        result.metadata.update(
            {
                "node_version": self.node_version,
                "imported_packages": list(self.imported_packages),
                "npm_packages": list(self.npm_packages),
            }
        )

        # Use parent implementation for subprocess execution
        super()._execute_with_capture(code, result)

        # Add post-execution analysis
        self._analyze_execution_context(result)

    def _analyze_execution_context(self, result: StructuredExecutionResult):
        """
        Analyze JavaScript execution context and add metadata

        Args:
            result: StructuredExecutionResult to enhance
        """
        try:
            # Analyze output for JavaScript-specific patterns
            analysis = {
                "async_operations_detected": "Promise" in result.stdout
                or "async" in result.stdout,
                "console_outputs": result.stdout.count("console.log"),
                "error_count": result.stderr.count("Error"),
                "package_usage": len(self.imported_packages),
            }

            result.metadata["javascript_analysis"] = analysis

        except Exception as e:
            self.logger.warning(f"JavaScript context analysis failed: {e}")

    def detect_end_of_execution(self, line: str) -> bool:
        """
        Detect JavaScript-specific end-of-execution markers

        Args:
            line: Output line to check

        Returns:
            True if end of execution detected
        """
        return "##end_of_execution##" in line

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
            # Legacy mode - use parent implementation
            return self._run_legacy_mode(code)

    def _run_legacy_mode(self, code):
        """
        Run in legacy mode for backward compatibility

        Args:
            code: JavaScript code to execute

        Returns:
            List of output messages in LMC format
        """
        if not self.repl_ready:
            return [
                {
                    "type": "console",
                    "format": "output",
                    "content": "Node.js not available",
                }
            ]

        try:
            # Use the existing subprocess language implementation
            # but return results in legacy format
            output_messages = []

            # Preprocess code
            processed_code = self.preprocess_code_structured(code)

            # Start subprocess if needed
            if not self.process or self.process.poll() is not None:
                self._start_subprocess()

            # Send code and capture output
            self.process.stdin.write(processed_code + "\n")
            self.process.stdin.flush()

            # Simple output capture for legacy mode
            timeout = time.time() + 30  # 30 second timeout
            current_output = ""

            while time.time() < timeout:
                try:
                    # Read available output
                    import select

                    ready, _, _ = select.select([self.process.stdout], [], [], 0.1)

                    if ready:
                        chunk = self.process.stdout.read(1024)
                        if chunk:
                            current_output += chunk

                            # Check for completion marker
                            if "##end_of_execution##" in current_output:
                                break
                    else:
                        time.sleep(0.1)

                except Exception:
                    break

            # Process output into legacy format
            if current_output:
                # Clean up output
                cleaned_output = current_output.replace("##end_of_execution##", "")
                cleaned_output = re.sub(r"##active_line\d+##\n?", "", cleaned_output)

                if cleaned_output.strip():
                    output_messages.append(
                        {
                            "type": "console",
                            "format": "output",
                            "content": cleaned_output.strip(),
                        }
                    )

            return output_messages

        except Exception as e:
            return [
                {"type": "console", "format": "output", "content": f"Error: {str(e)}"}
            ]


# Legacy compatibility - maintain original JavaScript class behavior
class JavaScript(EnhancedJavaScript):
    """
    Legacy JavaScript class that extends EnhancedJavaScript

    This maintains backward compatibility with existing code while providing
    access to enhanced structured output capabilities.
    """

    pass
