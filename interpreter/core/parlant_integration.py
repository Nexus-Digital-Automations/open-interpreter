"""
Parlant Integration Service for Open-Interpreter

Provides conversational AI validation for ALL Open-Interpreter code execution,
interpretation, and computer automation functions. Implements function-level
Parlant integration to ensure AI execution precision and safety guardrails.

This module wraps every code execution and computer automation function with
Parlant's conversational AI validation system for maximum control and safety.

@author Parlant Integration Team
@since 1.0.0
"""

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import wraps
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ParlantIntegrationService:
    """
    Parlant Integration Service for Open-Interpreter

    Provides conversational AI validation for all code execution, interpretation,
    and computer automation functions. Ensures safety guardrails and intent
    verification for every system operation.

    Example:
        service = ParlantIntegrationService()
        result = await service.validate_operation(
            operation="execute_code",
            context={"code": "print('hello')", "language": "python"},
            user_intent="Execute simple print statement for testing"
        )
    """

    # Parlant Configuration Constants
    PARLANT_API_BASE_URL = os.getenv("PARLANT_API_BASE_URL", "http://localhost:8000")
    PARLANT_API_TIMEOUT = float(os.getenv("PARLANT_API_TIMEOUT_MS", "10000")) / 1000.0
    PARLANT_ENABLED = os.getenv("PARLANT_ENABLED", "true").lower() == "true"
    PARLANT_CACHE_ENABLED = os.getenv("PARLANT_CACHE_ENABLED", "true").lower() == "true"
    PARLANT_CACHE_MAX_AGE = (
        float(os.getenv("PARLANT_CACHE_MAX_AGE_MS", "300000")) / 1000.0
    )

    # Risk Level Definitions for Open-Interpreter Operations
    RISK_LEVELS = {
        "low": [
            "status_check",
            "health_check",
            "info_query",
            "read_file",
            "list_directory",
            "get_metadata",
            "check_permissions",
        ],
        "medium": [
            "chat_interaction",
            "process_message",
            "format_response",
            "validate_input",
            "search_content",
            "analyze_data",
        ],
        "high": [
            "execute_code",
            "run_command",
            "computer_interaction",
            "file_modification",
            "network_request",
            "system_call",
        ],
        "critical": [
            "system_admin",
            "delete_files",
            "install_packages",
            "modify_system",
            "access_credentials",
            "execute_arbitrary",
        ],
    }

    # Operation Categories for Open-Interpreter
    OPERATION_CATEGORIES = {
        "code_execution": [
            "execute_code",
            "run_code",
            "exec_command",
            "interpret_code",
            "compile_code",
            "run_script",
            "execute_function",
        ],
        "computer_automation": [
            "computer_run",
            "computer_exec",
            "system_command",
            "mouse_click",
            "keyboard_input",
            "screen_capture",
            "file_operation",
        ],
        "ai_interaction": [
            "chat",
            "respond",
            "process_llm",
            "generate_response",
            "analyze_intent",
            "conversation_flow",
        ],
        "job_management": [
            "execute_job",
            "manage_job",
            "schedule_task",
            "monitor_execution",
            "handle_result",
            "cleanup_job",
        ],
        "terminal_interface": [
            "terminal_command",
            "shell_execution",
            "environment_setup",
            "path_navigation",
            "process_control",
        ],
    }

    def __init__(self):
        """Initialize Parlant Integration Service for Open-Interpreter"""
        self.logger = self._setup_logging()
        self.cache = {}
        self.metrics = self._initialize_metrics()
        self.operation_counter = 0
        self.conversation_context = {}
        self.session = self._setup_http_session()
        self._thread_pool = ThreadPoolExecutor(max_workers=5)

        self._log_service_initialization()

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging for Parlant operations"""
        logger = logging.getLogger("ParlantIntegration")
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(
                getattr(logging, os.getenv("PARLANT_LOG_LEVEL", "INFO").upper())
            )
        return logger

    def _setup_http_session(self) -> requests.Session:
        """Setup HTTP session with retry strategy and timeouts"""
        session = requests.Session()

        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Default headers
        session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "OpenInterpreter-Parlant-Integration/1.0.0",
            }
        )

        if os.getenv("PARLANT_API_KEY"):
            session.headers["Authorization"] = f"Bearer {os.getenv('PARLANT_API_KEY')}"

        return session

    def _initialize_metrics(self) -> Dict[str, Any]:
        """Initialize performance metrics tracking"""
        return {
            "total_validations": 0,
            "successful_validations": 0,
            "failed_validations": 0,
            "average_response_time": 0.0,
            "cache_hits": 0,
            "cache_misses": 0,
            "high_risk_operations": 0,
            "blocked_operations": 0,
        }

    async def validate_operation(
        self,
        operation: str,
        context: Dict[str, Any] = None,
        user_intent: str = None,
        risk_assessment: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Core validation method for Open-Interpreter operations

        Validates code execution, computer automation, and AI interactions
        through Parlant's conversational AI engine with safety guardrails.

        Args:
            operation: The operation being performed
            context: Operation context (code, commands, parameters)
            user_intent: Natural language description of user intent
            risk_assessment: Optional custom risk assessment

        Returns:
            Dict containing validation result with approval status and metadata

        Example:
            result = await validate_operation(
                operation="execute_code",
                context={
                    "code": "import os; os.listdir('/')",
                    "language": "python",
                    "execution_context": "user_request"
                },
                user_intent="List files in root directory for exploration"
            )
        """
        operation_id = self._generate_operation_id()
        start_time = time.time()

        self._log_validation_start(operation_id, operation, context, user_intent)

        if not self.PARLANT_ENABLED:
            return self._bypass_result(operation_id, "Parlant disabled")

        try:
            # Check cache for performance optimization
            cache_key = self._generate_cache_key(operation, context, user_intent)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                return self._add_operation_metadata(
                    cached_result, operation_id, start_time
                )

            # Perform risk assessment
            risk_level = risk_assessment or self._assess_operation_risk(
                operation, context
            )

            # Build validation request
            validation_request = self._build_validation_request(
                operation, context, user_intent, risk_level, operation_id
            )

            # Execute conversational validation
            validation_result = await self._execute_parlant_validation(
                validation_request, operation_id
            )

            # Process and enhance result
            enhanced_result = self._process_validation_result(
                validation_result, risk_level, operation_id
            )

            # Cache successful validations
            if enhanced_result["approved"]:
                self._cache_validation_result(cache_key, enhanced_result)

            # Update metrics
            self._record_validation_metrics(
                operation_id, enhanced_result, time.time() - start_time
            )

            self._log_validation_completion(operation_id, enhanced_result)
            return self._add_operation_metadata(
                enhanced_result, operation_id, start_time
            )

        except Exception as e:
            return self._handle_validation_error(e, operation_id, operation, context)

    async def validate_code_execution(
        self, code: str, language: str, execution_context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Specialized validation for code execution operations

        Validates code before execution with security analysis and intent verification.

        Args:
            code: Code to be executed
            language: Programming language
            execution_context: Execution environment context

        Returns:
            Validation result for code execution
        """
        context = {
            "code": code,
            "language": language,
            "code_length": len(code),
            "contains_imports": "import " in code,
            "contains_system_calls": any(
                keyword in code.lower()
                for keyword in ["os.", "subprocess", "system", "exec", "eval"]
            ),
            "execution_context": execution_context or {},
        }

        return await self.validate_operation(
            operation="execute_code",
            context=context,
            user_intent=f"Execute {language} code: {code[:100]}{'...' if len(code) > 100 else ''}",
        )

    async def validate_computer_automation(
        self, command_type: str, parameters: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Specialized validation for computer automation operations

        Validates computer interaction commands before execution.

        Args:
            command_type: Type of computer command (click, type, run, etc.)
            parameters: Command parameters and context

        Returns:
            Validation result for computer automation
        """
        context = {
            "command_type": command_type,
            "parameters": parameters or {},
            "automation_scope": "computer_interaction",
            "requires_system_access": command_type in ["run", "exec", "admin"],
        }

        return await self.validate_operation(
            operation="computer_automation",
            context=context,
            user_intent=f"Execute computer automation: {command_type}",
        )

    async def validate_ai_interaction(
        self,
        interaction_type: str,
        message_content: str,
        conversation_context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Specialized validation for AI interactions and responses

        Validates AI conversation flows and response generation.

        Args:
            interaction_type: Type of AI interaction (chat, respond, analyze)
            message_content: Content of the interaction
            conversation_context: Conversation history and context

        Returns:
            Validation result for AI interaction
        """
        context = {
            "interaction_type": interaction_type,
            "message_length": len(message_content),
            "contains_code_request": any(
                keyword in message_content.lower()
                for keyword in ["execute", "run", "code", "script", "command"]
            ),
            "conversation_context": conversation_context or {},
        }

        return await self.validate_operation(
            operation="ai_interaction",
            context=context,
            user_intent=f"AI {interaction_type}: {message_content[:100]}{'...' if len(message_content) > 100 else ''}",
        )

    def get_health_status(self) -> Dict[str, Any]:
        """
        Get comprehensive health status of Parlant integration

        Returns:
            Health status including API connectivity, performance metrics
        """
        return {
            "parlant_enabled": self.PARLANT_ENABLED,
            "api_connectivity": self._check_api_connectivity(),
            "cache_status": self._check_cache_status(),
            "performance_metrics": self._get_performance_metrics(),
            "recent_validations": self._get_recent_validation_stats(),
            "service_uptime": time.time(),
            "timestamp": datetime.now().isoformat(),
        }

    def _assess_operation_risk(
        self, operation: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess risk level of Open-Interpreter operation"""
        base_risk = self._determine_base_risk_level(operation)
        risk_factors = self._analyze_risk_factors(operation, context)

        # Adjust risk based on context
        if context and context.get("code"):
            code = context["code"]
            if any(
                dangerous in code.lower()
                for dangerous in [
                    "rm -rf",
                    "del /s",
                    "format",
                    "sudo",
                    "admin",
                    "password",
                ]
            ):
                base_risk = "critical"
            elif any(
                system_call in code.lower()
                for system_call in ["subprocess", "os.system", "exec", "eval"]
            ):
                base_risk = "high" if base_risk in ["low", "medium"] else base_risk

        return {
            "level": base_risk,
            "factors": risk_factors,
            "requires_approval": base_risk in ["high", "critical"],
            "assessment_time": datetime.now().isoformat(),
        }

    def _determine_base_risk_level(self, operation: str) -> str:
        """Map operations to base risk levels"""
        for level, operations in self.RISK_LEVELS.items():
            if operation in operations:
                return level

        # Check operation patterns
        if any(keyword in operation.lower() for keyword in ["execute", "run", "exec"]):
            return "high"
        elif any(
            keyword in operation.lower() for keyword in ["system", "admin", "delete"]
        ):
            return "critical"
        elif any(
            keyword in operation.lower() for keyword in ["chat", "respond", "message"]
        ):
            return "medium"

        return "medium"  # Default for unmapped operations

    def _analyze_risk_factors(
        self, operation: str, context: Dict[str, Any]
    ) -> List[str]:
        """Identify specific risk factors based on operation context"""
        factors = []

        if context:
            # Code-specific factors
            if context.get("code"):
                code = context["code"]
                if len(code) > 1000:
                    factors.append("large_code_block")
                if "import " in code:
                    factors.append("external_imports")
                if any(
                    net in code.lower()
                    for net in ["http", "request", "urllib", "socket"]
                ):
                    factors.append("network_operations")
                if any(
                    file_op in code.lower()
                    for file_op in ["open(", "write", "delete", "remove"]
                ):
                    factors.append("file_operations")

            # System interaction factors
            if context.get("requires_system_access"):
                factors.append("system_access_required")
            if context.get("automation_scope") == "computer_interaction":
                factors.append("computer_automation")
            if context.get("contains_system_calls"):
                factors.append("system_calls_detected")

        # Operation-specific factors
        if "execute" in operation.lower():
            factors.append("code_execution")
        if "computer" in operation.lower():
            factors.append("computer_control")
        if "admin" in operation.lower():
            factors.append("administrative_operation")

        return factors

    def _build_validation_request(
        self,
        operation: str,
        context: Dict[str, Any],
        user_intent: str,
        risk_assessment: Dict[str, Any],
        operation_id: str,
    ) -> Dict[str, Any]:
        """Build validation request payload for Parlant API"""
        return {
            "operation_id": operation_id,
            "operation": operation,
            "context": self._sanitize_context(context),
            "user_intent": user_intent or f"Perform {operation} operation",
            "risk_assessment": risk_assessment,
            "system_info": {
                "service": "open-interpreter",
                "version": "1.0.0",
                "environment": os.getenv("ENVIRONMENT", "development"),
                "timestamp": datetime.now().isoformat(),
                "python_version": f"{__import__('sys').version_info.major}.{__import__('sys').version_info.minor}",
            },
            "validation_settings": {
                "require_approval": risk_assessment["requires_approval"],
                "timeout_ms": int(self.PARLANT_API_TIMEOUT * 1000),
                "cache_enabled": self.PARLANT_CACHE_ENABLED,
            },
        }

    async def _execute_parlant_validation(
        self, request_payload: Dict[str, Any], operation_id: str
    ) -> Dict[str, Any]:
        """Execute validation request to Parlant API"""
        self.logger.debug(
            f"[{operation_id}] Executing Parlant validation",
            extra={
                "operation": request_payload["operation"],
                "risk_level": request_payload["risk_assessment"]["level"],
            },
        )

        # Use thread pool for synchronous HTTP request in async context
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            self._thread_pool,
            self._make_validation_request,
            request_payload,
            operation_id,
        )

        return response

    def _make_validation_request(
        self, request_payload: Dict[str, Any], operation_id: str
    ) -> Dict[str, Any]:
        """Make synchronous HTTP request to Parlant API"""
        try:
            response = self.session.post(
                f"{self.PARLANT_API_BASE_URL}/api/v1/validate",
                json=request_payload,
                timeout=self.PARLANT_API_TIMEOUT,
                headers={"X-Operation-ID": operation_id},
            )

            response.raise_for_status()
            return response.json()

        except requests.exceptions.RequestException as e:
            self.logger.error(f"[{operation_id}] Parlant API request failed: {e}")
            raise

    def _process_validation_result(
        self,
        validation_result: Dict[str, Any],
        risk_assessment: Dict[str, Any],
        operation_id: str,
    ) -> Dict[str, Any]:
        """Process and enhance validation results from Parlant API"""
        return {
            "approved": validation_result.get("approved", False),
            "confidence": validation_result.get("confidence", 0.0),
            "reasoning": validation_result.get("reasoning", "No reasoning provided"),
            "risk_level": risk_assessment["level"],
            "operation_id": operation_id,
            "validation_metadata": {
                "parlant_session_id": validation_result.get("session_id"),
                "response_time_ms": validation_result.get("response_time_ms"),
                "model_version": validation_result.get("model_version"),
                "validation_timestamp": datetime.now().isoformat(),
            },
            "recommendations": validation_result.get("recommendations", []),
            "warnings": validation_result.get("warnings", []),
        }

    def _sanitize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from context for API transmission"""
        if not context:
            return {}

        sanitized = context.copy()

        # Remove sensitive fields
        sensitive_keys = [
            "password",
            "secret",
            "token",
            "api_key",
            "credential",
            "private_key",
        ]
        for key in sensitive_keys:
            sanitized.pop(key, None)

        # Truncate large code blocks
        if sanitized.get("code") and len(sanitized["code"]) > 2000:
            sanitized["code"] = sanitized["code"][:1997] + "..."

        return sanitized

    def _generate_cache_key(
        self, operation: str, context: Dict[str, Any], user_intent: str
    ) -> str:
        """Generate deterministic cache key"""
        key_data = {
            "operation": operation,
            "context_hash": hashlib.sha256(
                json.dumps(context or {}, sort_keys=True).encode()
            ).hexdigest(),
            "intent_hash": hashlib.sha256((user_intent or "").encode()).hexdigest(),
        }
        return hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()

    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached validation result if available and valid"""
        if not self.PARLANT_CACHE_ENABLED or cache_key not in self.cache:
            self.metrics["cache_misses"] += 1
            return None

        cached_item = self.cache[cache_key]
        if time.time() - cached_item["timestamp"] > self.PARLANT_CACHE_MAX_AGE:
            del self.cache[cache_key]
            self.metrics["cache_misses"] += 1
            return None

        self.metrics["cache_hits"] += 1
        self.logger.debug(f"Cache hit for key: {cache_key[:16]}...")
        return cached_item["result"]

    def _cache_validation_result(self, cache_key: str, result: Dict[str, Any]) -> None:
        """Store validation result in cache"""
        if not self.PARLANT_CACHE_ENABLED:
            return

        self.cache[cache_key] = {"result": result, "timestamp": time.time()}

        # Simple cache cleanup
        if len(self.cache) > 1000:
            oldest_key = min(
                self.cache.keys(), key=lambda k: self.cache[k]["timestamp"]
            )
            del self.cache[oldest_key]

    def _generate_operation_id(self) -> str:
        """Generate unique operation identifier"""
        self.operation_counter += 1
        return f"oi_parlant_{int(time.time())}_{self.operation_counter}_{threading.current_thread().ident}"

    def _bypass_result(self, operation_id: str, reason: str) -> Dict[str, Any]:
        """Return approval result when Parlant is disabled"""
        return {
            "approved": True,
            "bypassed": True,
            "bypass_reason": reason,
            "operation_id": operation_id,
            "confidence": 1.0,
            "reasoning": f"Parlant validation bypassed: {reason}",
            "validation_metadata": {"bypass_timestamp": datetime.now().isoformat()},
        }

    def _add_operation_metadata(
        self, result: Dict[str, Any], operation_id: str, start_time: float
    ) -> Dict[str, Any]:
        """Add timing and operation metadata to validation results"""
        result.update(
            {
                "operation_id": operation_id,
                "total_duration_ms": round((time.time() - start_time) * 1000, 2),
                "processed_at": datetime.now().isoformat(),
            }
        )
        return result

    def _handle_validation_error(
        self,
        error: Exception,
        operation_id: str,
        operation: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Handle errors during validation process"""
        self.logger.error(
            f"[{operation_id}] Validation failed: {error}",
            extra={
                "operation": operation,
                "context_keys": list(context.keys()) if context else [],
                "error_type": type(error).__name__,
            },
        )

        self.metrics["failed_validations"] += 1

        # Safe default based on risk level
        risk_level = self._determine_base_risk_level(operation)
        safe_default = risk_level not in ["high", "critical"]

        return {
            "approved": safe_default,
            "error": True,
            "error_message": str(error),
            "operation_id": operation_id,
            "confidence": 0.0,
            "reasoning": f"Validation failed due to error: {error}",
            "validation_metadata": {
                "error_timestamp": datetime.now().isoformat(),
                "error_class": type(error).__name__,
            },
        }

    def _record_validation_metrics(
        self, operation_id: str, result: Dict[str, Any], duration: float
    ) -> None:
        """Update performance metrics after validation completion"""
        self.metrics["total_validations"] += 1

        if result["approved"]:
            self.metrics["successful_validations"] += 1
        else:
            self.metrics["failed_validations"] += 1
            if result.get("risk_level") in ["high", "critical"]:
                self.metrics["blocked_operations"] += 1

        if result.get("risk_level") in ["high", "critical"]:
            self.metrics["high_risk_operations"] += 1

        # Update average response time
        current_avg = self.metrics["average_response_time"]
        total_count = self.metrics["total_validations"]
        self.metrics["average_response_time"] = (
            (current_avg * (total_count - 1)) + duration
        ) / total_count

    def _check_api_connectivity(self) -> Dict[str, Any]:
        """Test connection to Parlant API"""
        try:
            response = self.session.get(
                f"{self.PARLANT_API_BASE_URL}/api/v1/health", timeout=5
            )
            return {
                "connected": response.status_code == 200,
                "response_time_ms": response.elapsed.total_seconds() * 1000,
                "last_check": datetime.now().isoformat(),
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e),
                "last_check": datetime.now().isoformat(),
            }

    def _check_cache_status(self) -> Dict[str, Any]:
        """Check cache functionality and performance"""
        if not self.PARLANT_CACHE_ENABLED:
            return {"enabled": False}

        hit_rate = 0.0
        total_requests = self.metrics["cache_hits"] + self.metrics["cache_misses"]
        if total_requests > 0:
            hit_rate = (self.metrics["cache_hits"] / total_requests) * 100

        return {
            "enabled": True,
            "entries": len(self.cache),
            "hits": self.metrics["cache_hits"],
            "misses": self.metrics["cache_misses"],
            "hit_rate_percent": round(hit_rate, 2),
        }

    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        success_rate = 0.0
        if self.metrics["total_validations"] > 0:
            success_rate = (
                self.metrics["successful_validations"]
                / self.metrics["total_validations"]
            ) * 100

        return {
            **self.metrics,
            "success_rate_percent": round(success_rate, 2),
            "cache_hit_rate_percent": round(
                (
                    self.metrics["cache_hits"]
                    / max(1, self.metrics["cache_hits"] + self.metrics["cache_misses"])
                )
                * 100,
                2,
            ),
        }

    def _get_recent_validation_stats(self) -> Dict[str, Any]:
        """Get recent validation statistics"""
        return {
            "recent_validations": self.metrics["total_validations"],
            "recent_success_rate": round(
                (
                    self.metrics["successful_validations"]
                    / max(1, self.metrics["total_validations"])
                )
                * 100,
                2,
            ),
            "average_response_time_ms": round(
                self.metrics["average_response_time"] * 1000, 2
            ),
            "high_risk_operations": self.metrics["high_risk_operations"],
            "blocked_operations": self.metrics["blocked_operations"],
        }

    def _log_service_initialization(self) -> None:
        """Log service startup information"""
        self.logger.info(
            "Parlant Integration Service initialized",
            extra={
                "parlant_enabled": self.PARLANT_ENABLED,
                "api_base_url": self.PARLANT_API_BASE_URL,
                "cache_enabled": self.PARLANT_CACHE_ENABLED,
                "timeout_seconds": self.PARLANT_API_TIMEOUT,
                "service": "open-interpreter",
            },
        )

    def _log_validation_start(
        self,
        operation_id: str,
        operation: str,
        context: Dict[str, Any],
        user_intent: str,
    ) -> None:
        """Log validation operation start"""
        self.logger.info(
            f"[{operation_id}] Validation started",
            extra={
                "operation": operation,
                "context_keys": list(context.keys()) if context else [],
                "user_intent": user_intent,
                "timestamp": datetime.now().isoformat(),
            },
        )

    def _log_validation_completion(
        self, operation_id: str, result: Dict[str, Any]
    ) -> None:
        """Log validation operation completion"""
        self.logger.info(
            f"[{operation_id}] Validation completed",
            extra={
                "approved": result["approved"],
                "confidence": result["confidence"],
                "risk_level": result["risk_level"],
                "bypassed": result.get("bypassed", False),
                "timestamp": datetime.now().isoformat(),
            },
        )


# Global service instance
_parlant_service: Optional[ParlantIntegrationService] = None


def get_parlant_service() -> ParlantIntegrationService:
    """Get global Parlant service instance (singleton pattern)"""
    global _parlant_service
    if _parlant_service is None:
        _parlant_service = ParlantIntegrationService()
    return _parlant_service


def parlant_validate(operation_type: str = None):
    """
    Decorator for function-level Parlant validation

    Wraps Open-Interpreter functions with conversational AI validation.

    Args:
        operation_type: Type of operation for risk assessment

    Example:
        @parlant_validate("code_execution")
        async def execute_code(code, language):
            # Function implementation
            pass
    """

    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            service = get_parlant_service()

            # Extract context from function arguments
            context = {
                "function_name": func.__name__,
                "args_count": len(args),
                "kwargs_keys": list(kwargs.keys()) if kwargs else [],
                "module": func.__module__,
            }

            # Add specific context based on function signature
            if "code" in kwargs:
                context["code"] = kwargs["code"]
            if "language" in kwargs:
                context["language"] = kwargs["language"]
            if len(args) > 0 and isinstance(args[0], str):
                context["primary_input"] = args[0][:200]  # First 200 chars

            # Perform validation
            validation_result = await service.validate_operation(
                operation=operation_type or func.__name__,
                context=context,
                user_intent=f"Execute {func.__name__} function",
            )

            if not validation_result["approved"]:
                raise PermissionError(
                    f"Parlant validation blocked {func.__name__}: {validation_result['reasoning']}"
                )

            # Execute original function
            if asyncio.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For synchronous functions, run validation in event loop
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            return loop.run_until_complete(async_wrapper(*args, **kwargs))

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator
