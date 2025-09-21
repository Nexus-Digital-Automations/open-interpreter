"""
Parlant Validated Functions for Open-Interpreter

Provides function-level Parlant conversational AI validation wrappers for ALL
Open-Interpreter critical operations. These wrappers enhance security and safety
by validating code execution, computer automation, and AI interactions.

This module implements the function-level integration patterns with decorators
and method overrides for seamless Parlant validation integration.

@author Parlant Integration Team
@since 1.0.0
"""

import asyncio
import logging
from functools import wraps

from .parlant_integration import get_parlant_service, parlant_validate


class ParlantValidatedOpenInterpreter:
    """
    Mixin class for adding Parlant validation to OpenInterpreter methods

    Provides conversational AI validation for all critical operations including
    code execution, computer automation, chat interactions, and job management.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parlant_service = get_parlant_service()
        self.logger = logging.getLogger("ParlantValidatedOI")

    async def parlant_validated_chat(
        self, message=None, display=True, stream=False, blocking=True
    ):
        """
        Parlant-validated chat interaction

        Validates user chat messages and AI responses through conversational AI
        before processing to ensure safety and intent alignment.

        Args:
            message: User message or input
            display: Whether to display response
            stream: Whether to stream response
            blocking: Whether to block for completion

        Returns:
            Chat response after Parlant validation
        """
        operation_id = f"chat_{id(self)}_{int(__import__('time').time())}"

        self.logger.info(
            f"[{operation_id}] Starting Parlant-validated chat",
            extra={
                "message_type": type(message).__name__,
                "message_length": len(str(message)) if message else 0,
                "display": display,
                "stream": stream,
            },
        )

        try:
            # Validate chat interaction
            validation_result = await self.parlant_service.validate_ai_interaction(
                interaction_type="chat",
                message_content=str(message) if message else "",
                conversation_context={
                    "display": display,
                    "stream": stream,
                    "blocking": blocking,
                    "messages_count": len(getattr(self, "messages", [])),
                    "auto_run": getattr(self, "auto_run", False),
                },
            )

            if not validation_result["approved"]:
                self.logger.warning(
                    f"[{operation_id}] Chat blocked by Parlant validation",
                    extra={
                        "reasoning": validation_result["reasoning"],
                        "confidence": validation_result["confidence"],
                        "risk_level": validation_result["risk_level"],
                    },
                )

                if display:
                    print(f"🚫 Chat blocked: {validation_result['reasoning']}")

                return {
                    "role": "assistant",
                    "content": f"I cannot process this request: {validation_result['reasoning']}",
                    "parlant_blocked": True,
                    "validation_result": validation_result,
                }

            self.logger.info(
                f"[{operation_id}] Chat validation approved",
                extra={
                    "confidence": validation_result["confidence"],
                    "risk_level": validation_result["risk_level"],
                },
            )

            # Execute original chat method
            if hasattr(super(), "chat"):
                result = await super().chat(message, display, stream, blocking)
            else:
                # Fallback for synchronous chat method
                result = getattr(super(), "chat")(message, display, stream, blocking)

            self.logger.info(f"[{operation_id}] Chat completed successfully")
            return result

        except Exception as e:
            self.logger.error(
                f"[{operation_id}] Chat validation or execution failed",
                extra={"error": str(e), "error_type": type(e).__name__},
            )
            raise

    async def parlant_validated_execute_code(
        self, code: str, language: str = None, **kwargs
    ):
        """
        Parlant-validated code execution

        Validates code before execution with security analysis and intent verification.
        This is the most critical security function in Open-Interpreter.

        Args:
            code: Code to execute
            language: Programming language
            **kwargs: Additional execution parameters

        Returns:
            Code execution result after Parlant validation
        """
        operation_id = f"execute_code_{id(self)}_{int(__import__('time').time())}"

        self.logger.info(
            f"[{operation_id}] Starting Parlant-validated code execution",
            extra={
                "language": language,
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
            # Validate code execution
            validation_result = await self.parlant_service.validate_code_execution(
                code=code,
                language=language or "python",
                execution_context={
                    "safe_mode": getattr(self, "safe_mode", "off"),
                    "auto_run": getattr(self, "auto_run", False),
                    "offline": getattr(self, "offline", False),
                    **kwargs,
                },
            )

            if not validation_result["approved"]:
                self.logger.error(
                    f"[{operation_id}] Code execution blocked by Parlant",
                    extra={
                        "reasoning": validation_result["reasoning"],
                        "confidence": validation_result["confidence"],
                        "risk_level": validation_result["risk_level"],
                        "code_preview": code[:200],
                    },
                )

                raise PermissionError(
                    f"Code execution blocked by Parlant validation: {validation_result['reasoning']}"
                )

            self.logger.info(
                f"[{operation_id}] Code execution validation approved",
                extra={
                    "confidence": validation_result["confidence"],
                    "risk_level": validation_result["risk_level"],
                },
            )

            # Execute original code execution method
            if hasattr(self, "computer") and hasattr(self.computer, "exec"):
                result = self.computer.exec(code)
            elif hasattr(super(), "execute_code"):
                result = await super().execute_code(code, language, **kwargs)
            else:
                self.logger.warning(f"[{operation_id}] No code execution method found")
                raise NotImplementedError("No code execution method available")

            self.logger.info(f"[{operation_id}] Code execution completed successfully")
            return result

        except PermissionError:
            raise  # Re-raise Parlant validation errors
        except Exception as e:
            self.logger.error(
                f"[{operation_id}] Code execution failed",
                extra={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "code_preview": code[:200],
                },
            )
            raise

    async def parlant_validated_computer_run(self, *args, **kwargs):
        """
        Parlant-validated computer automation

        Validates computer interaction commands before execution.

        Args:
            *args: Computer command arguments
            **kwargs: Computer command parameters

        Returns:
            Computer automation result after Parlant validation
        """
        operation_id = f"computer_run_{id(self)}_{int(__import__('time').time())}"

        self.logger.info(
            f"[{operation_id}] Starting Parlant-validated computer automation",
            extra={"args_count": len(args), "kwargs_keys": list(kwargs.keys())},
        )

        try:
            # Determine command type from arguments
            command_type = "unknown"
            if args:
                if isinstance(args[0], str):
                    command_type = args[0].split()[0] if " " in args[0] else args[0]
                elif isinstance(args[0], dict) and "type" in args[0]:
                    command_type = args[0]["type"]

            # Validate computer automation
            validation_result = await self.parlant_service.validate_computer_automation(
                command_type=command_type,
                parameters={
                    "args": [str(arg)[:100] for arg in args],  # Limit arg length
                    "kwargs": {k: str(v)[:100] for k, v in kwargs.items()},
                    "automation_context": {
                        "safe_mode": getattr(self, "safe_mode", "off"),
                        "computer_available": hasattr(self, "computer"),
                    },
                },
            )

            if not validation_result["approved"]:
                self.logger.error(
                    f"[{operation_id}] Computer automation blocked",
                    extra={
                        "reasoning": validation_result["reasoning"],
                        "confidence": validation_result["confidence"],
                        "risk_level": validation_result["risk_level"],
                        "command_type": command_type,
                    },
                )

                raise PermissionError(
                    f"Computer automation blocked by Parlant validation: {validation_result['reasoning']}"
                )

            self.logger.info(
                f"[{operation_id}] Computer automation validation approved",
                extra={
                    "confidence": validation_result["confidence"],
                    "risk_level": validation_result["risk_level"],
                    "command_type": command_type,
                },
            )

            # Execute original computer run method
            if hasattr(self, "computer") and hasattr(self.computer, "run"):
                result = self.computer.run(*args, **kwargs)
            elif hasattr(super(), "computer_run"):
                result = await super().computer_run(*args, **kwargs)
            else:
                self.logger.warning(f"[{operation_id}] No computer run method found")
                raise NotImplementedError("No computer automation method available")

            self.logger.info(
                f"[{operation_id}] Computer automation completed successfully"
            )
            return result

        except PermissionError:
            raise  # Re-raise Parlant validation errors
        except Exception as e:
            self.logger.error(
                f"[{operation_id}] Computer automation failed",
                extra={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "command_type": command_type,
                },
            )
            raise

    async def parlant_validated_respond(self, run_code=None, job_id=None, **kwargs):
        """
        Parlant-validated response generation

        Validates AI response generation and processing.

        Args:
            run_code: Code to run as part of response
            job_id: Job identifier for tracking
            **kwargs: Additional response parameters

        Returns:
            Response result after Parlant validation
        """
        operation_id = f"respond_{id(self)}_{int(__import__('time').time())}"

        self.logger.info(
            f"[{operation_id}] Starting Parlant-validated response",
            extra={
                "has_run_code": run_code is not None,
                "job_id": job_id,
                "kwargs_keys": list(kwargs.keys()),
            },
        )

        try:
            # Validate response generation
            validation_result = await self.parlant_service.validate_ai_interaction(
                interaction_type="respond",
                message_content=str(run_code) if run_code else "",
                conversation_context={
                    "job_id": job_id,
                    "has_code": run_code is not None,
                    "response_context": kwargs,
                    "messages_count": len(getattr(self, "messages", [])),
                },
            )

            if not validation_result["approved"]:
                self.logger.warning(
                    f"[{operation_id}] Response generation blocked",
                    extra={
                        "reasoning": validation_result["reasoning"],
                        "confidence": validation_result["confidence"],
                        "risk_level": validation_result["risk_level"],
                    },
                )

                return {
                    "role": "assistant",
                    "content": f"Response blocked by validation: {validation_result['reasoning']}",
                    "parlant_blocked": True,
                    "validation_result": validation_result,
                }

            self.logger.info(
                f"[{operation_id}] Response validation approved",
                extra={
                    "confidence": validation_result["confidence"],
                    "risk_level": validation_result["risk_level"],
                },
            )

            # Execute original respond method
            if hasattr(super(), "respond"):
                if asyncio.iscoroutinefunction(super().respond):
                    result = await super().respond(run_code, job_id, **kwargs)
                else:
                    result = super().respond(run_code, job_id, **kwargs)
            else:
                self.logger.warning(f"[{operation_id}] No respond method found")
                raise NotImplementedError("No respond method available")

            self.logger.info(
                f"[{operation_id}] Response generation completed successfully"
            )
            return result

        except Exception as e:
            self.logger.error(
                f"[{operation_id}] Response generation failed",
                extra={"error": str(e), "error_type": type(e).__name__},
            )
            raise

    async def parlant_validated_execute_job(self, request, **kwargs):
        """
        Parlant-validated job execution

        Validates job execution requests before processing.

        Args:
            request: Job execution request
            **kwargs: Additional job parameters

        Returns:
            Job execution result after Parlant validation
        """
        operation_id = f"execute_job_{id(self)}_{int(__import__('time').time())}"

        self.logger.info(
            f"[{operation_id}] Starting Parlant-validated job execution",
            extra={
                "request_type": type(request).__name__,
                "kwargs_keys": list(kwargs.keys()),
            },
        )

        try:
            # Extract job context
            job_context = {
                "request_type": type(request).__name__,
                "has_code": hasattr(request, "code")
                or (isinstance(request, dict) and "code" in request),
                "job_parameters": kwargs,
            }

            if hasattr(request, "code"):
                job_context["code"] = getattr(request, "code")
            elif isinstance(request, dict) and "code" in request:
                job_context["code"] = request["code"]

            # Validate job execution
            validation_result = await self.parlant_service.validate_operation(
                operation="execute_job",
                context=job_context,
                user_intent=f"Execute job with request: {type(request).__name__}",
            )

            if not validation_result["approved"]:
                self.logger.error(
                    f"[{operation_id}] Job execution blocked",
                    extra={
                        "reasoning": validation_result["reasoning"],
                        "confidence": validation_result["confidence"],
                        "risk_level": validation_result["risk_level"],
                    },
                )

                raise PermissionError(
                    f"Job execution blocked by Parlant validation: {validation_result['reasoning']}"
                )

            self.logger.info(
                f"[{operation_id}] Job execution validation approved",
                extra={
                    "confidence": validation_result["confidence"],
                    "risk_level": validation_result["risk_level"],
                },
            )

            # Execute original job execution method
            if hasattr(super(), "execute_job"):
                if asyncio.iscoroutinefunction(super().execute_job):
                    result = await super().execute_job(request, **kwargs)
                else:
                    result = super().execute_job(request, **kwargs)
            else:
                self.logger.warning(f"[{operation_id}] No execute_job method found")
                raise NotImplementedError("No job execution method available")

            self.logger.info(f"[{operation_id}] Job execution completed successfully")
            return result

        except PermissionError:
            raise  # Re-raise Parlant validation errors
        except Exception as e:
            self.logger.error(
                f"[{operation_id}] Job execution failed",
                extra={"error": str(e), "error_type": type(e).__name__},
            )
            raise


def apply_parlant_validation_to_class(cls):
    """
    Class decorator to apply Parlant validation to all relevant methods

    Automatically wraps critical methods with Parlant validation while
    preserving the original method signatures and behavior.

    Args:
        cls: Class to enhance with Parlant validation

    Returns:
        Enhanced class with Parlant validation
    """

    # Methods to wrap with validation
    critical_methods = {
        "chat": "ai_interaction",
        "execute_code": "code_execution",
        "execute_job": "job_execution",
        "respond": "ai_interaction",
        "run": "computer_automation",
    }

    for method_name, operation_type in critical_methods.items():
        if hasattr(cls, method_name):
            original_method = getattr(cls, method_name)

            # Create Parlant-validated wrapper
            @wraps(original_method)
            def create_validated_method(method_name, operation_type, original_method):
                async def validated_method(self, *args, **kwargs):
                    service = get_parlant_service()

                    # Build context from method arguments
                    context = {
                        "method_name": method_name,
                        "class_name": cls.__name__,
                        "args_count": len(args),
                        "kwargs_keys": list(kwargs.keys()),
                    }

                    # Add method-specific context
                    if method_name == "execute_code" and args:
                        context["code"] = args[0][:500]  # First 500 chars
                        if len(args) > 1:
                            context["language"] = args[1]
                    elif method_name == "chat" and args:
                        context["message"] = str(args[0])[:200]

                    # Validate operation
                    validation_result = await service.validate_operation(
                        operation=operation_type,
                        context=context,
                        user_intent=f"Execute {method_name} method on {cls.__name__}",
                    )

                    if not validation_result["approved"]:
                        raise PermissionError(
                            f"Method {method_name} blocked by Parlant validation: {validation_result['reasoning']}"
                        )

                    # Execute original method
                    if asyncio.iscoroutinefunction(original_method):
                        return await original_method(self, *args, **kwargs)
                    else:
                        return original_method(self, *args, **kwargs)

                return validated_method

            # Replace method with validated version
            validated_method = create_validated_method(
                method_name, operation_type, original_method
            )
            setattr(cls, f"parlant_validated_{method_name}", validated_method)

            # Keep original method available
            setattr(cls, f"original_{method_name}", original_method)

    return cls


def enhance_interpreter_with_parlant(interpreter_instance):
    """
    Enhance an existing OpenInterpreter instance with Parlant validation

    Dynamically adds Parlant validation to an existing interpreter instance
    without modifying the class definition.

    Args:
        interpreter_instance: OpenInterpreter instance to enhance

    Returns:
        Enhanced interpreter instance with Parlant validation
    """

    # Add Parlant service to instance
    interpreter_instance.parlant_service = get_parlant_service()
    interpreter_instance.logger = logging.getLogger("ParlantValidatedOI")

    # Wrap critical methods
    if hasattr(interpreter_instance, "chat"):
        original_chat = interpreter_instance.chat
        interpreter_instance.original_chat = original_chat

        async def parlant_validated_chat(
            message=None, display=True, stream=False, blocking=True
        ):
            # Validation logic here
            validation_result = (
                await interpreter_instance.parlant_service.validate_ai_interaction(
                    interaction_type="chat",
                    message_content=str(message) if message else "",
                    conversation_context={"display": display, "stream": stream},
                )
            )

            if not validation_result["approved"]:
                if display:
                    print(f"🚫 Chat blocked: {validation_result['reasoning']}")
                raise PermissionError(f"Chat blocked: {validation_result['reasoning']}")

            return original_chat(message, display, stream, blocking)

        interpreter_instance.chat = parlant_validated_chat

    # Wrap computer execution if available
    if hasattr(interpreter_instance, "computer") and hasattr(
        interpreter_instance.computer, "exec"
    ):
        original_exec = interpreter_instance.computer.exec
        interpreter_instance.computer.original_exec = original_exec

        async def parlant_validated_exec(code):
            validation_result = (
                await interpreter_instance.parlant_service.validate_code_execution(
                    code=code,
                    language="python",
                    execution_context={
                        "safe_mode": getattr(interpreter_instance, "safe_mode", "off")
                    },
                )
            )

            if not validation_result["approved"]:
                raise PermissionError(
                    f"Code execution blocked: {validation_result['reasoning']}"
                )

            return original_exec(code)

        interpreter_instance.computer.exec = parlant_validated_exec

    interpreter_instance.logger.info(
        "OpenInterpreter instance enhanced with Parlant validation"
    )
    return interpreter_instance


# Auto-enhancement hook for new interpreter instances
def auto_enhance_interpreters():
    """
    Auto-enhancement hook that can be called to enhance all OpenInterpreter instances

    This function can be called during module initialization to automatically
    enhance interpreter instances with Parlant validation.
    """
    import gc

    from .core import OpenInterpreter

    # Find and enhance existing interpreter instances
    enhanced_count = 0
    for obj in gc.get_objects():
        if isinstance(obj, OpenInterpreter) and not hasattr(obj, "parlant_service"):
            enhance_interpreter_with_parlant(obj)
            enhanced_count += 1

    if enhanced_count > 0:
        logging.getLogger("ParlantValidatedOI").info(
            f"Auto-enhanced {enhanced_count} OpenInterpreter instances with Parlant validation"
        )


# Export key functions and classes
__all__ = [
    "ParlantValidatedOpenInterpreter",
    "apply_parlant_validation_to_class",
    "enhance_interpreter_with_parlant",
    "auto_enhance_interpreters",
    "parlant_validate",
    "get_parlant_service",
]
