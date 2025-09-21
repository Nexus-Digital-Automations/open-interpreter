"""
PARLANT Conversational Validation Middleware for Open-Interpreter FastAPI

Implements comprehensive conversational validation middleware for Open-Interpreter's
Python-based code execution and security API layers with sub-500ms performance
requirements and enterprise-grade security validation.

This middleware provides:
- Code execution safety validation through conversational approval
- File system operation validation with risk classification
- Terminal command approval system with security validation
- LLM interaction validation and audit trail system
- Real-time risk assessment and approval workflows

@author PARLANT Integration Specialist
@since 1.0.0
@performance_target <500ms validation for interactive operations
"""

import hashlib
import json
import logging
import time
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from fastapi import FastAPI, Request, Response
from fastapi.middleware.base import BaseHTTPMiddleware
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import JSONResponse

from .enterprise_security_integration import EnterpriseSecurityOrchestrator
from .parlant_integration import ParlantIntegrationService
from .ultra_secure_code_execution import (
    ApprovalLevel,
    RiskAssessment,
    RiskLevel,
    SecurityLevel,
)


class OperationType(Enum):
    """Types of operations requiring PARLANT validation"""

    CODE_EXECUTION = "code_execution"
    FILE_OPERATION = "file_operation"
    TERMINAL_COMMAND = "terminal_command"
    LLM_INTERACTION = "llm_interaction"
    SECURITY_OPERATION = "security_operation"
    SYSTEM_ADMINISTRATION = "system_administration"


class ValidationResult(Enum):
    """PARLANT validation results"""

    APPROVED = "approved"
    REJECTED = "rejected"
    REQUIRES_CONFIRMATION = "requires_confirmation"
    ESCALATION_REQUIRED = "escalation_required"
    SECURITY_VIOLATION = "security_violation"


class ParlantValidationMiddleware(BaseHTTPMiddleware):
    """
    PARLANT Conversational Validation Middleware

    Provides comprehensive conversational validation for all Open-Interpreter
    API operations with real-time risk assessment, approval workflows, and
    comprehensive audit trails.

    Features:
    - Sub-500ms validation for interactive operations
    - Risk-based validation with configurable thresholds
    - Conversational approval workflows for high-risk operations
    - Comprehensive audit trail and compliance documentation
    - Integration with existing enterprise security systems
    """

    def __init__(
        self,
        app: FastAPI,
        parlant_service: Optional[ParlantIntegrationService] = None,
        security_orchestrator: Optional[EnterpriseSecurityOrchestrator] = None,
        **kwargs,
    ):
        super().__init__(app)

        # Initialize services
        self.parlant_service = parlant_service or ParlantIntegrationService()
        self.security_orchestrator = security_orchestrator

        # Configuration
        self.validation_enabled = kwargs.get("validation_enabled", True)
        self.performance_target_ms = kwargs.get("performance_target_ms", 500)
        self.bypass_endpoints = set(
            kwargs.get("bypass_endpoints", ["/health", "/docs", "/openapi.json"])
        )
        self.high_risk_threshold = kwargs.get("high_risk_threshold", 0.7)
        self.critical_risk_threshold = kwargs.get("critical_risk_threshold", 0.9)

        # Risk assessment configuration
        self.risk_classification = {
            "code_execution": {
                "base_risk": 0.6,
                "patterns": {
                    r"import\s+os|subprocess|system": 0.8,
                    r"exec\s*\(|eval\s*\(": 0.9,
                    r"__import__|getattr": 0.7,
                    r"rm\s+-rf|del\s+/": 0.95,
                    r"curl|wget|requests\.get": 0.5,
                },
            },
            "file_operations": {
                "base_risk": 0.4,
                "patterns": {
                    r"\/etc\/|\/root\/|\/sys\/": 0.9,
                    r"\.ssh\/|\.aws\/|\.config\/": 0.8,
                    r"password|secret|key|token": 0.7,
                    r"delete|remove|rm": 0.6,
                },
            },
            "terminal_commands": {
                "base_risk": 0.5,
                "patterns": {
                    r"sudo|su\s|chmod\s+777": 0.9,
                    r"dd\s+if=|mkfs|fdisk": 0.95,
                    r"iptables|ufw|firewall": 0.8,
                    r"crontab|systemctl|service": 0.7,
                },
            },
        }

        # Performance monitoring
        self.validation_metrics = {
            "total_requests": 0,
            "validated_requests": 0,
            "approved_requests": 0,
            "rejected_requests": 0,
            "average_validation_time_ms": 0.0,
            "max_validation_time_ms": 0.0,
        }

        # Logging
        self.logger = logging.getLogger("ParlantValidationMiddleware")
        self.logger.info(
            "PARLANT Validation Middleware initialized",
            extra={
                "validation_enabled": self.validation_enabled,
                "performance_target_ms": self.performance_target_ms,
                "high_risk_threshold": self.high_risk_threshold,
                "critical_risk_threshold": self.critical_risk_threshold,
            },
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """
        Main middleware dispatch with comprehensive validation

        Processes all incoming requests through PARLANT validation pipeline
        with performance monitoring and comprehensive audit trails.
        """
        start_time = time.time()
        self.validation_metrics["total_requests"] += 1

        # Skip validation for bypass endpoints
        if request.url.path in self.bypass_endpoints:
            return await call_next(request)

        # Skip if validation disabled
        if not self.validation_enabled:
            return await call_next(request)

        try:
            # Extract request context
            request_context = await self._extract_request_context(request)

            # Perform risk assessment
            risk_assessment = await self._assess_operation_risk(
                request, request_context
            )

            # Perform validation based on risk level
            validation_result = await self._perform_validation(
                request, request_context, risk_assessment
            )

            # Handle validation result
            if validation_result.result == ValidationResult.REJECTED:
                return await self._create_rejection_response(validation_result)

            elif validation_result.result == ValidationResult.REQUIRES_CONFIRMATION:
                # For high-risk operations, require conversational confirmation
                confirmation_result = await self._request_conversational_confirmation(
                    request, request_context, risk_assessment
                )

                if not confirmation_result.approved:
                    return await self._create_rejection_response(confirmation_result)

            # Execute request with comprehensive audit trail
            response = await self._execute_with_audit_trail(
                request, call_next, request_context, risk_assessment
            )

            # Update metrics
            validation_time_ms = (time.time() - start_time) * 1000
            await self._update_performance_metrics(validation_time_ms, approved=True)

            return response

        except Exception as e:
            self.logger.error(
                f"Validation middleware error: {str(e)}",
                extra={
                    "request_path": request.url.path,
                    "request_method": request.method,
                    "error_type": type(e).__name__,
                },
            )

            # In case of middleware failure, allow request but log incident
            response = await call_next(request)
            await self._log_validation_failure(request, e)

            return response

    async def _extract_request_context(self, request: Request) -> Dict[str, Any]:
        """Extract comprehensive context from request"""

        # Read request body if present
        body = b""
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()

        # Parse JSON body if possible
        json_body = {}
        if body:
            try:
                json_body = json.loads(body.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        # Extract user context from headers/auth
        user_context = await self._extract_user_context(request)

        return {
            "path": request.url.path,
            "method": request.method,
            "query_params": dict(request.query_params),
            "headers": dict(request.headers),
            "body": json_body,
            "user_context": user_context,
            "timestamp": datetime.now().isoformat(),
            "request_id": str(uuid.uuid4()),
        }

    async def _extract_user_context(self, request: Request) -> Dict[str, Any]:
        """Extract user context from request headers and authentication"""

        # Extract from Authorization header (JWT or API key)
        auth_header = request.headers.get("authorization", "")
        user_id = "anonymous"
        roles = ["user"]
        permissions = []

        # Extract user ID from custom headers
        if "x-user-id" in request.headers:
            user_id = request.headers["x-user-id"]

        # Extract roles from custom headers
        if "x-user-roles" in request.headers:
            roles = request.headers["x-user-roles"].split(",")

        # Extract session information
        session_id = request.headers.get("x-session-id", str(uuid.uuid4()))

        return {
            "user_id": user_id,
            "session_id": session_id,
            "roles": roles,
            "permissions": permissions,
            "security_clearance": SecurityLevel.INTERNAL.value,
            "auth_method": "header" if auth_header else "anonymous",
        }

    async def _assess_operation_risk(
        self, request: Request, context: Dict[str, Any]
    ) -> RiskAssessment:
        """
        Comprehensive risk assessment for the operation

        Analyzes request path, method, body content, and user context
        to determine risk level and required validation approach.
        """

        # Determine operation type
        operation_type = self._classify_operation(request.url.path, context["body"])

        # Calculate base risk score
        base_risk = self._calculate_base_risk_score(operation_type, context)

        # Analyze content for risk patterns
        content_risk = self._analyze_content_risk(context["body"])

        # Factor in user context
        user_risk = self._assess_user_risk(context["user_context"])

        # Calculate final risk score
        final_risk_score = min(1.0, (base_risk + content_risk + user_risk) / 3.0)

        # Determine risk level
        if final_risk_score >= self.critical_risk_threshold:
            risk_level = RiskLevel.CRITICAL
            approval_level = ApprovalLevel.DUAL_APPROVAL
        elif final_risk_score >= self.high_risk_threshold:
            risk_level = RiskLevel.HIGH
            approval_level = ApprovalLevel.SINGLE_APPROVAL
        elif final_risk_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
            approval_level = ApprovalLevel.SINGLE_APPROVAL
        else:
            risk_level = RiskLevel.LOW
            approval_level = ApprovalLevel.AUTOMATIC

        # Identify specific risk factors
        risk_factors = self._identify_risk_factors(context)
        threat_indicators = self._identify_threat_indicators(context)

        return RiskAssessment(
            risk_level=risk_level,
            security_level=SecurityLevel.INTERNAL,
            approval_level=approval_level,
            risk_factors=risk_factors,
            threat_indicators=threat_indicators,
            compliance_violations=[],
            mitigation_required=[],
            estimated_damage="medium" if final_risk_score > 0.6 else "low",
            confidence_score=final_risk_score,
            assessment_timestamp=datetime.now(),
        )

    def _classify_operation(self, path: str, body: Dict[str, Any]) -> OperationType:
        """Classify the type of operation based on request path and content"""

        if "/execute" in path or body.get("code"):
            return OperationType.CODE_EXECUTION
        elif "/jobs" in path:
            return OperationType.CODE_EXECUTION
        elif "file" in path or "directory" in path:
            return OperationType.FILE_OPERATION
        elif "terminal" in path or "command" in path:
            return OperationType.TERMINAL_COMMAND
        elif "chat" in path or "llm" in path:
            return OperationType.LLM_INTERACTION
        else:
            return OperationType.SECURITY_OPERATION

    def _calculate_base_risk_score(
        self, operation_type: OperationType, context: Dict[str, Any]
    ) -> float:
        """Calculate base risk score for operation type"""

        base_scores = {
            OperationType.CODE_EXECUTION: 0.7,
            OperationType.FILE_OPERATION: 0.5,
            OperationType.TERMINAL_COMMAND: 0.6,
            OperationType.LLM_INTERACTION: 0.3,
            OperationType.SECURITY_OPERATION: 0.8,
            OperationType.SYSTEM_ADMINISTRATION: 0.9,
        }

        return base_scores.get(operation_type, 0.5)

    def _analyze_content_risk(self, body: Dict[str, Any]) -> float:
        """Analyze request content for risk patterns"""

        risk_score = 0.0
        content_str = json.dumps(body).lower()

        # Code execution patterns
        if "code" in body:
            code = str(body["code"]).lower()
            for pattern, risk in self.risk_classification["code_execution"][
                "patterns"
            ].items():
                if any(keyword in code for keyword in pattern.split("|")):
                    risk_score = max(risk_score, risk)

        # File operation patterns
        for key in ["path", "file", "directory", "filename"]:
            if key in body:
                path_str = str(body[key]).lower()
                for pattern, risk in self.risk_classification["file_operations"][
                    "patterns"
                ].items():
                    if any(keyword in path_str for keyword in pattern.split("|")):
                        risk_score = max(risk_score, risk)

        # Terminal command patterns
        for key in ["command", "cmd", "shell"]:
            if key in body:
                cmd_str = str(body[key]).lower()
                for pattern, risk in self.risk_classification["terminal_commands"][
                    "patterns"
                ].items():
                    if any(keyword in cmd_str for keyword in pattern.split("|")):
                        risk_score = max(risk_score, risk)

        return risk_score

    def _assess_user_risk(self, user_context: Dict[str, Any]) -> float:
        """Assess risk based on user context and history"""

        # Base risk for anonymous users
        if user_context["user_id"] == "anonymous":
            return 0.3

        # Lower risk for authenticated users with proper roles
        if "admin" in user_context["roles"]:
            return 0.1
        elif "developer" in user_context["roles"]:
            return 0.2
        else:
            return 0.25

    def _identify_risk_factors(self, context: Dict[str, Any]) -> List[str]:
        """Identify specific risk factors in the request"""

        risk_factors = []

        # Check for anonymous access
        if context["user_context"]["user_id"] == "anonymous":
            risk_factors.append("anonymous_user_access")

        # Check for sensitive operations
        if context["method"] in ["DELETE", "PUT"]:
            risk_factors.append("destructive_operation")

        # Check for code execution
        if "code" in context["body"]:
            risk_factors.append("code_execution_requested")

        # Check for file operations
        if any(key in context["body"] for key in ["file", "path", "directory"]):
            risk_factors.append("file_system_access")

        return risk_factors

    def _identify_threat_indicators(self, context: Dict[str, Any]) -> List[str]:
        """Identify potential threat indicators"""

        threat_indicators = []

        # Check for suspicious patterns in code
        if "code" in context["body"]:
            code = str(context["body"]["code"]).lower()
            if any(
                pattern in code for pattern in ["reverse_shell", "backdoor", "malware"]
            ):
                threat_indicators.append("suspicious_code_patterns")

        # Check for unusual request patterns
        if len(str(context["body"])) > 10000:  # Large payload
            threat_indicators.append("unusually_large_payload")

        return threat_indicators

    async def _perform_validation(
        self, request: Request, context: Dict[str, Any], risk_assessment: RiskAssessment
    ) -> "ValidationResultDetail":
        """Perform PARLANT validation based on risk assessment"""

        validation_start = time.time()

        try:
            # For low-risk operations, auto-approve
            if risk_assessment.approval_level == ApprovalLevel.AUTOMATIC:
                return ValidationResultDetail(
                    result=ValidationResult.APPROVED,
                    reason="Low risk operation - auto-approved",
                    confidence=risk_assessment.confidence_score,
                    validation_time_ms=(time.time() - validation_start) * 1000,
                )

            # For higher risk operations, use PARLANT service
            parlant_request = {
                "operation_type": self._classify_operation(
                    request.url.path, context["body"]
                ).value,
                "risk_assessment": {
                    "risk_level": risk_assessment.risk_level.value,
                    "risk_factors": risk_assessment.risk_factors,
                    "threat_indicators": risk_assessment.threat_indicators,
                    "confidence_score": risk_assessment.confidence_score,
                },
                "user_context": context["user_context"],
                "request_context": {
                    "path": context["path"],
                    "method": context["method"],
                    "body_summary": self._create_body_summary(context["body"]),
                },
                "security_context": {
                    "requires_approval": risk_assessment.approval_level
                    != ApprovalLevel.AUTOMATIC,
                    "approval_level": risk_assessment.approval_level.value,
                    "security_level": risk_assessment.security_level.value,
                },
            }

            # Call PARLANT service for validation
            parlant_result = await self.parlant_service.validate_operation(
                operation=parlant_request["operation_type"],
                context=parlant_request,
                user_intent=f"Execute {request.method} {request.url.path}",
            )

            # Process PARLANT result
            if parlant_result.get("approved", False):
                result = ValidationResult.APPROVED
            elif parlant_result.get("requires_confirmation", False):
                result = ValidationResult.REQUIRES_CONFIRMATION
            else:
                result = ValidationResult.REJECTED

            return ValidationResultDetail(
                result=result,
                reason=parlant_result.get("reason", "PARLANT validation result"),
                confidence=parlant_result.get("confidence", 0.8),
                validation_time_ms=(time.time() - validation_start) * 1000,
                parlant_session_id=parlant_result.get("session_id"),
                additional_data=parlant_result,
            )

        except Exception as e:
            self.logger.error(f"PARLANT validation error: {str(e)}")

            # On validation service failure, allow low-risk operations
            if risk_assessment.risk_level in [RiskLevel.LOW, RiskLevel.MINIMAL]:
                return ValidationResultDetail(
                    result=ValidationResult.APPROVED,
                    reason="Validation service unavailable - low risk auto-approved",
                    confidence=0.5,
                    validation_time_ms=(time.time() - validation_start) * 1000,
                )
            else:
                return ValidationResultDetail(
                    result=ValidationResult.REJECTED,
                    reason="Validation service unavailable - high risk operations blocked",
                    confidence=0.9,
                    validation_time_ms=(time.time() - validation_start) * 1000,
                )

    def _create_body_summary(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a sanitized summary of request body for logging"""

        summary = {}

        # Include safe fields
        safe_fields = ["language", "timeout", "working_directory", "job_priority"]
        for field in safe_fields:
            if field in body:
                summary[field] = body[field]

        # Sanitize sensitive fields
        if "code" in body:
            code = str(body["code"])
            summary["code_length"] = len(code)
            summary["code_hash"] = hashlib.sha256(code.encode()).hexdigest()[:16]
            summary["code_preview"] = code[:100] + "..." if len(code) > 100 else code

        return summary

    async def _request_conversational_confirmation(
        self, request: Request, context: Dict[str, Any], risk_assessment: RiskAssessment
    ) -> "ConfirmationResult":
        """Request conversational confirmation for high-risk operations"""

        confirmation_request = {
            "operation_description": f"{request.method} {request.url.path}",
            "risk_level": risk_assessment.risk_level.value,
            "risk_factors": risk_assessment.risk_factors,
            "threat_indicators": risk_assessment.threat_indicators,
            "user_context": context["user_context"],
            "business_impact": "Medium",  # TODO: Calculate from context
            "reversible": False,  # TODO: Determine from operation type
            "approval_timeout_seconds": 60,
        }

        try:
            # Use PARLANT service for conversational confirmation
            confirmation_result = await self.parlant_service.request_user_confirmation(
                confirmation_request
            )

            return ConfirmationResult(
                approved=confirmation_result.get("approved", False),
                reason=confirmation_result.get("reason", "User decision"),
                confirmation_method="conversational",
                approver_id=confirmation_result.get("approver_id"),
                session_id=confirmation_result.get("session_id"),
            )

        except Exception as e:
            self.logger.error(f"Confirmation request failed: {str(e)}")

            # Default to rejection on confirmation failure
            return ConfirmationResult(
                approved=False,
                reason=f"Confirmation system unavailable: {str(e)}",
                confirmation_method="system_default",
                approver_id=None,
                session_id=None,
            )

    async def _execute_with_audit_trail(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
        context: Dict[str, Any],
        risk_assessment: RiskAssessment,
    ) -> Response:
        """Execute request with comprehensive audit trail"""

        execution_start = time.time()

        # Create audit entry
        audit_entry = {
            "request_id": context["request_id"],
            "user_id": context["user_context"]["user_id"],
            "session_id": context["user_context"]["session_id"],
            "operation": f"{request.method} {request.url.path}",
            "risk_level": risk_assessment.risk_level.value,
            "approval_level": risk_assessment.approval_level.value,
            "execution_start": datetime.now().isoformat(),
            "request_summary": self._create_body_summary(context["body"]),
        }

        try:
            # Execute the request
            response = await call_next(request)

            # Complete audit entry
            audit_entry.update(
                {
                    "execution_end": datetime.now().isoformat(),
                    "execution_time_ms": (time.time() - execution_start) * 1000,
                    "response_status": response.status_code,
                    "success": 200 <= response.status_code < 300,
                }
            )

            # Log audit entry
            await self._log_audit_entry(audit_entry)

            return response

        except Exception as e:
            # Log execution failure
            audit_entry.update(
                {
                    "execution_end": datetime.now().isoformat(),
                    "execution_time_ms": (time.time() - execution_start) * 1000,
                    "success": False,
                    "error": str(e),
                    "error_type": type(e).__name__,
                }
            )

            await self._log_audit_entry(audit_entry)
            raise

    async def _create_rejection_response(
        self, validation_result: Union["ValidationResultDetail", "ConfirmationResult"]
    ) -> JSONResponse:
        """Create standardized rejection response"""

        return JSONResponse(
            status_code=403,
            content={
                "error": "PARLANT_VALIDATION_REJECTED",
                "message": "Operation rejected by conversational validation",
                "reason": validation_result.reason,
                "validation_time_ms": getattr(
                    validation_result, "validation_time_ms", 0
                ),
                "session_id": getattr(validation_result, "session_id", None),
                "timestamp": datetime.now().isoformat(),
            },
        )

    async def _update_performance_metrics(
        self, validation_time_ms: float, approved: bool
    ):
        """Update performance metrics for monitoring"""

        self.validation_metrics["validated_requests"] += 1

        if approved:
            self.validation_metrics["approved_requests"] += 1
        else:
            self.validation_metrics["rejected_requests"] += 1

        # Update timing metrics
        current_avg = self.validation_metrics["average_validation_time_ms"]
        validated_count = self.validation_metrics["validated_requests"]

        self.validation_metrics["average_validation_time_ms"] = (
            current_avg * (validated_count - 1) + validation_time_ms
        ) / validated_count

        self.validation_metrics["max_validation_time_ms"] = max(
            self.validation_metrics["max_validation_time_ms"], validation_time_ms
        )

        # Log performance warning if exceeding target
        if validation_time_ms > self.performance_target_ms:
            self.logger.warning(
                f"Validation time exceeded target: {validation_time_ms:.1f}ms > {self.performance_target_ms}ms"
            )

    async def _log_audit_entry(self, audit_entry: Dict[str, Any]):
        """Log audit entry for compliance and monitoring"""

        self.logger.info("PARLANT validation audit", extra=audit_entry)

        # Send to enterprise security orchestrator if available
        if self.security_orchestrator:
            try:
                await self.security_orchestrator.log_security_event(audit_entry)
            except Exception as e:
                self.logger.error(f"Failed to log to security orchestrator: {str(e)}")

    async def _log_validation_failure(self, request: Request, error: Exception):
        """Log validation middleware failures for monitoring"""

        failure_entry = {
            "event_type": "validation_middleware_failure",
            "request_path": request.url.path,
            "request_method": request.method,
            "error": str(error),
            "error_type": type(error).__name__,
            "timestamp": datetime.now().isoformat(),
        }

        self.logger.error("PARLANT validation middleware failure", extra=failure_entry)

    def get_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""

        return {
            **self.validation_metrics,
            "validation_enabled": self.validation_enabled,
            "performance_target_ms": self.performance_target_ms,
            "approval_rate": (
                self.validation_metrics["approved_requests"]
                / max(1, self.validation_metrics["validated_requests"])
            ),
            "average_performance_compliance": (
                self.validation_metrics["average_validation_time_ms"]
                <= self.performance_target_ms
            ),
        }


class ValidationResultDetail:
    """Detailed validation result"""

    def __init__(
        self,
        result: ValidationResult,
        reason: str,
        confidence: float,
        validation_time_ms: float,
        parlant_session_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ):
        self.result = result
        self.reason = reason
        self.confidence = confidence
        self.validation_time_ms = validation_time_ms
        self.parlant_session_id = parlant_session_id
        self.additional_data = additional_data or {}


class ConfirmationResult:
    """Conversational confirmation result"""

    def __init__(
        self,
        approved: bool,
        reason: str,
        confirmation_method: str,
        approver_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        self.approved = approved
        self.reason = reason
        self.confirmation_method = confirmation_method
        self.approver_id = approver_id
        self.session_id = session_id


# Factory function for easy integration
def create_parlant_middleware(
    app: FastAPI, parlant_service: Optional[ParlantIntegrationService] = None, **kwargs
) -> ParlantValidationMiddleware:
    """
    Factory function to create and configure PARLANT validation middleware

    Args:
        app: FastAPI application instance
        parlant_service: Optional PARLANT service instance
        **kwargs: Additional configuration options

    Returns:
        Configured ParlantValidationMiddleware instance
    """

    middleware = ParlantValidationMiddleware(
        app=app, parlant_service=parlant_service, **kwargs
    )

    # Add middleware to application
    app.add_middleware(ParlantValidationMiddleware, **kwargs)

    return middleware
