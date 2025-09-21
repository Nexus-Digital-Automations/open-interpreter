import asyncio
import inspect
import json
import logging

from .ai.ai import Ai
from .browser.browser import Browser
from .calendar.calendar import Calendar
from .clipboard.clipboard import Clipboard
from .contacts.contacts import Contacts
from .display.display import Display
from .docs.docs import Docs
from .files.files import Files
from .keyboard.keyboard import Keyboard
from .mail.mail import Mail
from .mouse.mouse import Mouse
from .os.os import Os
from .skills.skills import Skills
from .sms.sms import SMS
from .terminal.terminal import Terminal
from .vision.vision import Vision


def get_parlant_service():
    """Import Parlant service with error handling"""
    try:
        from ..parlant_integration import get_parlant_service as _get_parlant_service

        return _get_parlant_service()
    except ImportError:
        return None


class Computer:
    def __init__(self, interpreter):
        self.interpreter = interpreter

        self.terminal = Terminal(self)

        # Parlant Integration for Computer Operations
        self.parlant_service = get_parlant_service()
        self.parlant_enabled = (
            self.parlant_service.PARLANT_ENABLED if self.parlant_service else False
        )
        self.logger = logging.getLogger("ParlantValidatedComputer")

        self.offline = False
        self.verbose = False
        self.debug = False

        self.mouse = Mouse(self)
        self.keyboard = Keyboard(self)
        self.display = Display(self)
        self.clipboard = Clipboard(self)
        self.mail = Mail(self)
        self.sms = SMS(self)
        self.calendar = Calendar(self)
        self.contacts = Contacts(self)
        self.browser = Browser(self)
        self.os = Os(self)
        self.vision = Vision(self)
        self.skills = Skills(self)
        self.docs = Docs(self)
        self.ai = Ai(self)
        self.files = Files(self)

        self.emit_images = True
        self.api_base = "https://api.openinterpreter.com/v0"
        self.save_skills = True

        self.import_computer_api = False  # Defaults to false
        self._has_imported_computer_api = False  # Because we only want to do this once

        self.import_skills = False
        self._has_imported_skills = False
        self.max_output = (
            self.interpreter.max_output
        )  # Should mirror interpreter.max_output

        computer_tools = "\n".join(
            self._get_all_computer_tools_signature_and_description()
        )

        self.system_message = f"""

# THE COMPUTER API

A python `computer` module is ALREADY IMPORTED, and can be used for many tasks:

```python
{computer_tools}
```

Do not import the computer module, or any of its sub-modules. They are already imported.

    """.strip()

    # Shortcut for computer.terminal.languages
    @property
    def languages(self):
        return self.terminal.languages

    @languages.setter
    def languages(self, value):
        self.terminal.languages = value

    def _get_all_computer_tools_list(self):
        return [
            self.mouse,
            self.keyboard,
            self.display,
            self.clipboard,
            self.mail,
            self.sms,
            self.calendar,
            self.contacts,
            self.browser,
            self.os,
            self.vision,
            self.skills,
            self.docs,
            self.ai,
            self.files,
        ]

    def _get_all_computer_tools_signature_and_description(self):
        """
        This function returns a list of all the computer tools that are available with their signature and description from the function docstrings.
        for example:
        computer.browser.search(query) # Searches the web for the specified query and returns the results.
        computer.calendar.create_event(title: str, start_date: datetime.datetime, end_date: datetime.datetime, location: str = "", notes: str = "", calendar: str = None) -> str # Creates a new calendar event in the default calendar with the given parameters using AppleScript.
        """
        tools = self._get_all_computer_tools_list()
        tools_signature_and_description = []
        for tool in tools:
            tool_info = self._extract_tool_info(tool)
            for method in tool_info["methods"]:
                # Format as tool_signature # tool_description
                formatted_info = f"{method['signature']} # {method['description']}"
                tools_signature_and_description.append(formatted_info)
        return tools_signature_and_description

    def _extract_tool_info(self, tool):
        """
        Helper function to extract the signature and description of a tool's methods.
        """
        tool_info = {"signature": tool.__class__.__name__, "methods": []}
        if tool.__class__.__name__ == "Browser":
            # Note: For future method filtering logic, prepare methods list here
            for name in dir(tool):
                if "driver" in name:
                    continue  # Skip methods containing 'driver' in their name
                attr = getattr(tool, name)
                if (
                    callable(attr)
                    and not name.startswith("_")
                    and not hasattr(attr, "__wrapped__")
                    and not isinstance(attr, property)
                ):
                    # Construct the method signature manually
                    param_str = ", ".join(
                        param
                        for param in attr.__code__.co_varnames[
                            : attr.__code__.co_argcount
                        ]
                    )
                    full_signature = f"computer.{tool.__class__.__name__.lower()}.{name}({param_str})"
                    # Get the method description
                    method_description = attr.__doc__ or ""
                    # Append the method details
                    tool_info["methods"].append(
                        {
                            "signature": full_signature,
                            "description": method_description.strip(),
                        }
                    )
            return tool_info

        for name, method in inspect.getmembers(tool, predicate=inspect.ismethod):
            # Check if the method should be ignored based on its decorator
            if not name.startswith("_") and not hasattr(method, "__wrapped__"):
                # Get the method signature
                method_signature = inspect.signature(method)
                # Construct the signature string without *args and **kwargs
                param_str = ", ".join(
                    (
                        f"{param.name}"
                        if param.default == param.empty
                        else f"{param.name}={param.default!r}"
                    )
                    for param in method_signature.parameters.values()
                    if param.kind not in (param.VAR_POSITIONAL, param.VAR_KEYWORD)
                )
                full_signature = (
                    f"computer.{tool.__class__.__name__.lower()}.{name}({param_str})"
                )
                # Get the method description
                method_description = method.__doc__ or ""
                # Append the method details
                tool_info["methods"].append(
                    {
                        "signature": full_signature,
                        "description": method_description.strip(),
                    }
                )
        return tool_info

    def run(self, *args, **kwargs):
        """
        Parlant-validated shortcut for computer.terminal.run

        Validates computer automation commands before execution through
        conversational AI to ensure safety and intent alignment.
        """
        if self.parlant_enabled and self.parlant_service:
            # Extract command information
            command_type = args[0] if args else "unknown"

            operation_id = f"computer_run_{id(self)}_{int(__import__('time').time())}"

            self.logger.info(
                f"[{operation_id}] Validating computer run command",
                extra={
                    "command_type": command_type,
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                },
            )

            try:
                # Async validation in sync context
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            validation_result = loop.run_until_complete(
                self.parlant_service.validate_computer_automation(
                    command_type=str(command_type),
                    parameters={
                        "args": [str(arg)[:200] for arg in args],
                        "kwargs": {k: str(v)[:200] for k, v in kwargs.items()},
                        "interpreter_safe_mode": getattr(
                            self.interpreter, "safe_mode", "off"
                        ),
                        "interpreter_auto_run": getattr(
                            self.interpreter, "auto_run", False
                        ),
                    },
                )
            )

            if not validation_result["approved"]:
                error_msg = f"Computer run blocked by Parlant validation: {validation_result['reasoning']}"
                self.logger.error(
                    f"[{operation_id}] {error_msg}",
                    extra={
                        "confidence": validation_result["confidence"],
                        "risk_level": validation_result["risk_level"],
                        "command_type": command_type,
                    },
                )
                raise PermissionError(error_msg)

            self.logger.info(
                f"[{operation_id}] Computer run validation approved",
                extra={
                    "confidence": validation_result["confidence"],
                    "risk_level": validation_result["risk_level"],
                },
            )

        # Execute original terminal.run
        return self.terminal.run(*args, **kwargs)

    def exec(self, code):
        """
        Parlant-validated shortcut for computer.terminal.run("shell", code)

        Validates code execution before running through conversational AI
        to ensure maximum safety and intent verification. This is the most
        critical security function in Open-Interpreter.
        """
        if self.parlant_enabled and self.parlant_service:
            operation_id = f"computer_exec_{id(self)}_{int(__import__('time').time())}"

            self.logger.info(
                f"[{operation_id}] Validating code execution",
                extra={
                    "code_length": len(code),
                    "contains_imports": "import " in code,
                    "contains_system_calls": any(
                        keyword in code.lower()
                        for keyword in [
                            "os.",
                            "subprocess",
                            "system",
                            "exec",
                            "eval",
                            "open(",
                        ]
                    ),
                },
            )

            try:
                # Async validation in sync context
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            validation_result = loop.run_until_complete(
                self.parlant_service.validate_code_execution(
                    code=code,
                    language="shell",
                    execution_context={
                        "execution_method": "computer.exec",
                        "interpreter_safe_mode": getattr(
                            self.interpreter, "safe_mode", "off"
                        ),
                        "interpreter_auto_run": getattr(
                            self.interpreter, "auto_run", False
                        ),
                        "interpreter_offline": getattr(
                            self.interpreter, "offline", False
                        ),
                    },
                )
            )

            if not validation_result["approved"]:
                error_msg = f"Code execution blocked by Parlant validation: {validation_result['reasoning']}"
                self.logger.error(
                    f"[{operation_id}] {error_msg}",
                    extra={
                        "confidence": validation_result["confidence"],
                        "risk_level": validation_result["risk_level"],
                        "code_preview": code[:200],
                    },
                )
                raise PermissionError(error_msg)

            self.logger.info(
                f"[{operation_id}] Code execution validation approved",
                extra={
                    "confidence": validation_result["confidence"],
                    "risk_level": validation_result["risk_level"],
                },
            )

        # Execute original terminal.run with shell
        return self.terminal.run("shell", code)

    def stop(self):
        """
        Shortcut for computer.terminal.stop
        """
        return self.terminal.stop()

    def terminate(self):
        """
        Shortcut for computer.terminal.terminate
        """
        return self.terminal.terminate()

    def screenshot(self, *args, **kwargs):
        """
        Shortcut for computer.display.screenshot
        """
        return self.display.screenshot(*args, **kwargs)

    def view(self, *args, **kwargs):
        """
        Shortcut for computer.display.screenshot
        """
        return self.display.screenshot(*args, **kwargs)

    def to_dict(self):
        def json_serializable(obj):
            try:
                json.dumps(obj)
                return True
            except (TypeError, ValueError):
                return False

        return {k: v for k, v in self.__dict__.items() if json_serializable(v)}

    def load_dict(self, data_dict):
        for key, value in data_dict.items():
            if hasattr(self, key):
                setattr(self, key, value)
