"""
PARLANT Unified Security Framework for Open-Interpreter

Integrates all PARLANT validation components into a comprehensive, high-performance
security framework with sub-500ms validation targets, concurrent processing, and
enterprise-grade compliance. Provides unified API for all security validations
across Open-Interpreter's Python-based systems.

This framework combines:
- FastAPI middleware for HTTP request validation
- Code execution security validation with risk assessment
- File system operation validation with approval workflows
- Terminal command validation with security classification
- LLM interaction validation and audit trail system

Performance Features:
- Sub-500ms validation for interactive operations
- Concurrent validation processing for scalability
- Intelligent caching with multi-level hierarchy
- Performance monitoring and optimization
- Enterprise-grade compliance and audit trails

@author PARLANT Integration Specialist
@since 1.0.0
@security_level MAXIMUM
@performance_target <500ms
"""

import asyncio
import hashlib
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .enterprise_security_integration import EnterpriseSecurityOrchestrator
from .parlant_code_execution_validator import ParlantCodeExecutionValidator
from .parlant_file_system_validator import ParlantFileSystemValidator
from .parlant_integration import ParlantIntegrationService
from .parlant_llm_validator import ParlantLLMValidator
from .parlant_terminal_validator import ParlantTerminalValidator
from .ultra_secure_code_execution import SecurityLevel


class ValidationDomain(Enum):
    """Security validation domains"""

    HTTP_REQUEST = "http_request"
    CODE_EXECUTION = "code_execution"
    FILE_SYSTEM = "file_system"
    TERMINAL_COMMAND = "terminal_command"
    LLM_INTERACTION = "llm_interaction"
    INTEGRATED_WORKFLOW = "integrated_workflow"


class ValidationPriority(Enum):
    """Validation priority levels"""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class CacheLevel(Enum):
    """Cache hierarchy levels"""

    L1_MEMORY = "l1_memory"  # <5ms access, 30s TTL
    L2_REDIS = "l2_redis"  # <15ms access, 5min TTL
    L3_DATABASE = "l3_database"  # <50ms access, 1hr TTL


@dataclass
class ValidationRequest:
    """Unified validation request"""

    request_id: str
    domain: ValidationDomain
    priority: ValidationPriority
    operation_type: str
    request_data: Dict[str, Any]
    user_context: Optional[Dict[str, Any]] = None
    security_context: Optional[Dict[str, Any]] = None
    business_justification: str = ""
    timeout_ms: int = 500
    cache_enabled: bool = True
    concurrent_processing: bool = True
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ValidationResponse:
    """Unified validation response"""

    request_id: str
    decision: str
    confidence: float
    reasoning: str
    domain: ValidationDomain
    validation_time_ms: float
    cache_hit: bool = False
    conditions: List[str] = field(default_factory=list)
    restrictions: List[str] = field(default_factory=list)
    monitoring_required: bool = False
    approval_session_id: Optional[str] = None
    approver_ids: List[str] = field(default_factory=list)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics"""

    total_validations: int = 0
    average_validation_time_ms: float = 0.0
    p95_validation_time_ms: float = 0.0
    p99_validation_time_ms: float = 0.0
    cache_hit_rate: float = 0.0
    concurrent_utilization: float = 0.0
    performance_target_compliance: float = 0.0
    domain_metrics: Dict[ValidationDomain, Dict[str, Any]] = field(default_factory=dict)


class ParlantUnifiedSecurityFramework:
    """
    PARLANT Unified Security Framework

    Provides comprehensive security validation across all Open-Interpreter
    domains with sub-500ms performance targets and enterprise-grade compliance.

    Features:
    - Unified API for all validation domains
    - Sub-500ms validation with concurrent processing
    - Multi-level caching for performance optimization
    - Enterprise compliance and audit trails
    - Real-time performance monitoring and optimization
    """

    def __init__(
        self,
        parlant_service: Optional[ParlantIntegrationService] = None,
        security_orchestrator: Optional[EnterpriseSecurityOrchestrator] = None,
        **kwargs,
    ):
        """Initialize PARLANT Unified Security Framework"""

        # Initialize core services
        self.parlant_service = parlant_service or ParlantIntegrationService()
        self.security_orchestrator = security_orchestrator

        # Configuration
        self.performance_target_ms = kwargs.get("performance_target_ms", 500)
        self.max_concurrent_validations = kwargs.get("max_concurrent_validations", 20)
        self.cache_enabled = kwargs.get("cache_enabled", True)
        self.strict_performance_mode = kwargs.get("strict_performance_mode", True)

        # Initialize domain validators
        self.domain_validators = {}
        self._initialize_domain_validators(kwargs)

        # Performance optimization
        self.validation_cache = {}
        self.cache_lock = threading.RLock()
        self.validation_semaphore = asyncio.Semaphore(self.max_concurrent_validations)

        # Thread pool for CPU-intensive operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=kwargs.get("thread_pool_size", 10),
            thread_name_prefix="parlant-validator",
        )

        # Performance tracking
        self.performance_metrics = PerformanceMetrics()
        self.validation_times = []
        self.metrics_lock = threading.RLock()

        # Active validations tracking
        self.active_validations = {}
        self.active_validations_lock = threading.RLock()

        # Cache configuration
        self.cache_config = {
            CacheLevel.L1_MEMORY: {
                "max_size": kwargs.get("l1_cache_size", 1000),
                "ttl_seconds": kwargs.get("l1_ttl_seconds", 30),
                "storage": {},
            },
            CacheLevel.L2_REDIS: {
                "max_size": kwargs.get("l2_cache_size", 10000),
                "ttl_seconds": kwargs.get("l2_ttl_seconds", 300),
                "storage": {},  # Would be Redis in production
            },
            CacheLevel.L3_DATABASE: {
                "max_size": kwargs.get("l3_cache_size", 100000),
                "ttl_seconds": kwargs.get("l3_ttl_seconds", 3600),
                "storage": {},  # Would be database in production
            },
        }

        # Logging
        self.logger = logging.getLogger("ParlantUnifiedSecurityFramework")
        self.logger.info(
            "PARLANT Unified Security Framework initialized",
            extra={
                "performance_target_ms": self.performance_target_ms,
                "max_concurrent_validations": self.max_concurrent_validations,
                "cache_enabled": self.cache_enabled,
                "domain_validators": list(self.domain_validators.keys()),
                "strict_performance_mode": self.strict_performance_mode,
            },
        )

    def _initialize_domain_validators(self, config: Dict[str, Any]):
        """Initialize all domain-specific validators"""

        try:
            # Code execution validator
            self.domain_validators[ValidationDomain.CODE_EXECUTION] = (
                ParlantCodeExecutionValidator(
                    parlant_service=self.parlant_service,
                    security_orchestrator=self.security_orchestrator,
                    performance_target_ms=self.performance_target_ms,
                    **config.get("code_execution", {}),
                )
            )

            # File system validator
            self.domain_validators[ValidationDomain.FILE_SYSTEM] = (
                ParlantFileSystemValidator(
                    parlant_service=self.parlant_service,
                    security_orchestrator=self.security_orchestrator,
                    performance_target_ms=self.performance_target_ms,
                    **config.get("file_system", {}),
                )
            )

            # Terminal validator
            self.domain_validators[ValidationDomain.TERMINAL_COMMAND] = (
                ParlantTerminalValidator(
                    parlant_service=self.parlant_service,
                    security_orchestrator=self.security_orchestrator,
                    performance_target_ms=self.performance_target_ms,
                    **config.get("terminal", {}),
                )
            )

            # LLM validator
            self.domain_validators[ValidationDomain.LLM_INTERACTION] = (
                ParlantLLMValidator(
                    parlant_service=self.parlant_service,
                    security_orchestrator=self.security_orchestrator,
                    performance_target_ms=self.performance_target_ms,
                    **config.get("llm", {}),
                )
            )

            self.logger.info(
                f"Initialized {len(self.domain_validators)} domain validators"
            )

        except Exception as e:
            self.logger.error(f"Failed to initialize domain validators: {str(e)}")
            raise

    async def validate(self, request: ValidationRequest) -> ValidationResponse:
        """
        Main validation entry point with performance optimization

        Provides unified validation across all domains with sub-500ms targets,
        intelligent caching, and concurrent processing.
        """

        validation_start = time.time()

        try:
            # Track active validation
            with self.active_validations_lock:
                self.active_validations[request.request_id] = {
                    "start_time": validation_start,
                    "domain": request.domain,
                    "priority": request.priority,
                }

            # Check cache first if enabled
            if request.cache_enabled and self.cache_enabled:
                cached_result = await self._check_cache(request)
                if cached_result:
                    await self._update_performance_metrics(
                        request.domain,
                        (time.time() - validation_start) * 1000,
                        cache_hit=True,
                    )
                    return cached_result

            # Perform validation with concurrency control
            async with self.validation_semaphore:
                validation_response = await self._perform_domain_validation(request)

            # Cache result if successful
            if request.cache_enabled and validation_response.confidence >= 0.8:
                await self._cache_result(request, validation_response)

            # Update performance metrics
            validation_time_ms = (time.time() - validation_start) * 1000
            validation_response.validation_time_ms = validation_time_ms

            await self._update_performance_metrics(
                request.domain, validation_time_ms, cache_hit=False
            )

            # Performance warning if target exceeded
            if validation_time_ms > self.performance_target_ms:
                self.logger.warning(
                    f"Validation time exceeded target: {validation_time_ms:.1f}ms > {self.performance_target_ms}ms",
                    extra={
                        "request_id": request.request_id,
                        "domain": request.domain.value,
                        "validation_time_ms": validation_time_ms,
                    },
                )

            # Create audit trail
            await self._create_unified_audit_trail(request, validation_response)

            return validation_response

        except Exception as e:
            self.logger.error(
                f"Validation error: {str(e)}",
                extra={
                    "request_id": request.request_id,
                    "domain": request.domain.value,
                    "error_type": type(e).__name__,
                },
            )

            # Return safe default on error
            return ValidationResponse(
                request_id=request.request_id,
                decision="blocked",
                confidence=0.9,
                reasoning=f"Validation system error: {str(e)}",
                domain=request.domain,
                validation_time_ms=(time.time() - validation_start) * 1000,
            )

        finally:
            # Clean up active validation tracking
            with self.active_validations_lock:
                self.active_validations.pop(request.request_id, None)

    async def _check_cache(
        self, request: ValidationRequest
    ) -> Optional[ValidationResponse]:
        """Check multi-level cache for existing validation result"""

        cache_key = self._generate_cache_key(request)

        # Check L1 (memory) cache first
        l1_result = await self._check_cache_level(CacheLevel.L1_MEMORY, cache_key)
        if l1_result:
            l1_result.cache_hit = True
            return l1_result

        # Check L2 (Redis) cache
        l2_result = await self._check_cache_level(CacheLevel.L2_REDIS, cache_key)
        if l2_result:
            # Promote to L1 cache
            await self._store_cache_level(CacheLevel.L1_MEMORY, cache_key, l2_result)
            l2_result.cache_hit = True
            return l2_result

        # Check L3 (database) cache
        l3_result = await self._check_cache_level(CacheLevel.L3_DATABASE, cache_key)
        if l3_result:
            # Promote to L2 and L1 caches
            await self._store_cache_level(CacheLevel.L2_REDIS, cache_key, l3_result)
            await self._store_cache_level(CacheLevel.L1_MEMORY, cache_key, l3_result)
            l3_result.cache_hit = True
            return l3_result

        return None

    def _generate_cache_key(self, request: ValidationRequest) -> str:
        """Generate cache key for validation request"""

        # Create deterministic hash of request data
        cache_data = {
            "domain": request.domain.value,
            "operation_type": request.operation_type,
            "request_data_hash": hashlib.sha256(
                json.dumps(request.request_data, sort_keys=True).encode()
            ).hexdigest()[:16],
            "user_id": (
                request.user_context.get("user_id", "anonymous")
                if request.user_context
                else "anonymous"
            ),
            "security_level": (
                request.security_context.get("security_level", "internal")
                if request.security_context
                else "internal"
            ),
        }

        return hashlib.sha256(
            json.dumps(cache_data, sort_keys=True).encode()
        ).hexdigest()[:32]

    async def _check_cache_level(
        self, cache_level: CacheLevel, cache_key: str
    ) -> Optional[ValidationResponse]:
        """Check specific cache level for validation result"""

        try:
            with self.cache_lock:
                cache_storage = self.cache_config[cache_level]["storage"]

                if cache_key in cache_storage:
                    entry = cache_storage[cache_key]

                    # Check if entry is still valid
                    if (
                        time.time() - entry["timestamp"]
                        < self.cache_config[cache_level]["ttl_seconds"]
                    ):
                        return entry["response"]
                    else:
                        # Remove expired entry
                        del cache_storage[cache_key]

        except Exception as e:
            self.logger.error(
                f"Cache check error for level {cache_level.value}: {str(e)}"
            )

        return None

    async def _store_cache_level(
        self, cache_level: CacheLevel, cache_key: str, response: ValidationResponse
    ):
        """Store validation result in specific cache level"""

        try:
            with self.cache_lock:
                cache_storage = self.cache_config[cache_level]["storage"]
                max_size = self.cache_config[cache_level]["max_size"]

                # Implement LRU eviction if cache is full
                if len(cache_storage) >= max_size:
                    # Remove oldest entry
                    oldest_key = min(
                        cache_storage.keys(),
                        key=lambda k: cache_storage[k]["timestamp"],
                    )
                    del cache_storage[oldest_key]

                # Store new entry
                cache_storage[cache_key] = {
                    "response": response,
                    "timestamp": time.time(),
                }

        except Exception as e:
            self.logger.error(
                f"Cache store error for level {cache_level.value}: {str(e)}"
            )

    async def _cache_result(
        self, request: ValidationRequest, response: ValidationResponse
    ):
        """Cache validation result across all cache levels"""

        cache_key = self._generate_cache_key(request)

        # Store in all cache levels
        await self._store_cache_level(CacheLevel.L1_MEMORY, cache_key, response)
        await self._store_cache_level(CacheLevel.L2_REDIS, cache_key, response)
        await self._store_cache_level(CacheLevel.L3_DATABASE, cache_key, response)

    async def _perform_domain_validation(
        self, request: ValidationRequest
    ) -> ValidationResponse:
        """Perform domain-specific validation with performance optimization"""

        validator = self.domain_validators.get(request.domain)
        if not validator:
            raise ValueError(f"No validator found for domain: {request.domain.value}")

        try:
            # Convert unified request to domain-specific format
            domain_request = await self._convert_to_domain_request(request, validator)

            # Perform validation with timeout
            if request.concurrent_processing:
                # Use asyncio for concurrent processing
                validation_result = await asyncio.wait_for(
                    self._execute_domain_validation(validator, domain_request),
                    timeout=request.timeout_ms / 1000.0,
                )
            else:
                # Sequential processing
                validation_result = await self._execute_domain_validation(
                    validator, domain_request
                )

            # Convert domain-specific response to unified format
            unified_response = await self._convert_to_unified_response(
                request, validation_result
            )

            return unified_response

        except asyncio.TimeoutError:
            self.logger.error(f"Validation timeout for domain {request.domain.value}")
            return ValidationResponse(
                request_id=request.request_id,
                decision="blocked",
                confidence=0.9,
                reasoning=f"Validation timeout after {request.timeout_ms}ms",
                domain=request.domain,
                validation_time_ms=request.timeout_ms,
            )

        except Exception as e:
            self.logger.error(f"Domain validation error: {str(e)}")
            return ValidationResponse(
                request_id=request.request_id,
                decision="blocked",
                confidence=0.9,
                reasoning=f"Domain validation error: {str(e)}",
                domain=request.domain,
                validation_time_ms=0.0,
            )

    async def _convert_to_domain_request(
        self, request: ValidationRequest, validator: Any
    ) -> Any:
        """Convert unified request to domain-specific request format"""

        if request.domain == ValidationDomain.CODE_EXECUTION:
            from .parlant_code_execution_validator import ExecutionRequest
            from .ultra_secure_code_execution import (
                ExecutionEnvironment,
                SecurityContext,
            )

            security_context = SecurityContext(
                user_id=(
                    request.user_context.get("user_id", "unknown")
                    if request.user_context
                    else "unknown"
                ),
                session_id=(
                    request.user_context.get("session_id", str(uuid.uuid4()))
                    if request.user_context
                    else str(uuid.uuid4())
                ),
                security_clearance=SecurityLevel.INTERNAL,
            )

            return ExecutionRequest(
                request_id=request.request_id,
                code=request.request_data.get("code", ""),
                language=request.request_data.get("language", "python"),
                security_context=security_context,
                execution_environment=ExecutionEnvironment.SANDBOXED,
                user_intent=request.business_justification,
            )

        elif request.domain == ValidationDomain.FILE_SYSTEM:
            from .parlant_file_system_validator import (
                FileOperationRequest,
                FileOperationType,
            )

            return FileOperationRequest(
                request_id=request.request_id,
                operation_type=FileOperationType(
                    request.request_data.get("operation_type", "read")
                ),
                source_path=request.request_data.get("source_path"),
                target_path=request.request_data.get("target_path"),
                user_context=request.user_context,
                business_justification=request.business_justification,
            )

        elif request.domain == ValidationDomain.TERMINAL_COMMAND:
            from .parlant_terminal_validator import TerminalValidationRequest

            return TerminalValidationRequest(
                request_id=request.request_id,
                command=request.request_data.get("command", ""),
                shell_type=request.request_data.get("shell_type", "bash"),
                user_context=request.user_context,
                business_justification=request.business_justification,
            )

        elif request.domain == ValidationDomain.LLM_INTERACTION:
            from .parlant_llm_validator import LLMInteractionType, LLMValidationRequest

            return LLMValidationRequest(
                request_id=request.request_id,
                interaction_type=LLMInteractionType(
                    request.request_data.get("interaction_type", "chat_message")
                ),
                prompt=request.request_data.get("prompt", ""),
                user_context=request.user_context,
                business_justification=request.business_justification,
            )

        else:
            raise ValueError(f"Unsupported domain: {request.domain.value}")

    async def _execute_domain_validation(
        self, validator: Any, domain_request: Any
    ) -> Any:
        """Execute domain-specific validation"""

        if hasattr(validator, "validate_code_execution"):
            return await validator.validate_code_execution(domain_request)
        elif hasattr(validator, "validate_file_operation"):
            return await validator.validate_file_operation(domain_request)
        elif hasattr(validator, "validate_terminal_command"):
            return await validator.validate_terminal_command(domain_request)
        elif hasattr(validator, "validate_llm_interaction"):
            return await validator.validate_llm_interaction(domain_request)
        else:
            raise ValueError(f"Invalid validator: {type(validator)}")

    async def _convert_to_unified_response(
        self, request: ValidationRequest, domain_result: Any
    ) -> ValidationResponse:
        """Convert domain-specific response to unified format"""

        # Extract common fields from domain result
        decision = getattr(domain_result, "decision", "unknown")
        if hasattr(decision, "value"):
            decision = decision.value

        confidence = getattr(domain_result, "confidence", 0.5)
        reasoning = getattr(domain_result, "reasoning", "Domain validation completed")
        conditions = getattr(domain_result, "conditions", [])
        restrictions = getattr(domain_result, "restrictions", [])
        monitoring_required = getattr(domain_result, "monitoring_required", False)
        approval_session_id = getattr(domain_result, "approval_session_id", None)
        approver_ids = getattr(domain_result, "approver_ids", [])
        audit_trail = getattr(domain_result, "audit_trail", [])

        return ValidationResponse(
            request_id=request.request_id,
            decision=decision,
            confidence=confidence,
            reasoning=reasoning,
            domain=request.domain,
            validation_time_ms=0.0,  # Will be set by caller
            conditions=conditions,
            restrictions=restrictions,
            monitoring_required=monitoring_required,
            approval_session_id=approval_session_id,
            approver_ids=approver_ids,
            audit_trail=audit_trail,
        )

    async def _update_performance_metrics(
        self,
        domain: ValidationDomain,
        validation_time_ms: float,
        cache_hit: bool = False,
    ):
        """Update comprehensive performance metrics"""

        with self.metrics_lock:
            # Update overall metrics
            self.performance_metrics.total_validations += 1

            # Update timing metrics
            current_avg = self.performance_metrics.average_validation_time_ms
            total_validations = self.performance_metrics.total_validations

            self.performance_metrics.average_validation_time_ms = (
                current_avg * (total_validations - 1) + validation_time_ms
            ) / total_validations

            # Track validation times for percentile calculations
            self.validation_times.append(validation_time_ms)

            # Keep only recent validation times (last 1000)
            if len(self.validation_times) > 1000:
                self.validation_times = self.validation_times[-1000:]

            # Calculate percentiles
            if self.validation_times:
                sorted_times = sorted(self.validation_times)
                p95_index = int(0.95 * len(sorted_times))
                p99_index = int(0.99 * len(sorted_times))

                self.performance_metrics.p95_validation_time_ms = sorted_times[
                    p95_index
                ]
                self.performance_metrics.p99_validation_time_ms = sorted_times[
                    p99_index
                ]

            # Update cache hit rate
            if cache_hit:
                cache_hits = getattr(self, "_cache_hits", 0) + 1
                setattr(self, "_cache_hits", cache_hits)
            else:
                cache_misses = getattr(self, "_cache_misses", 0) + 1
                setattr(self, "_cache_misses", cache_misses)

            total_cache_requests = getattr(self, "_cache_hits", 0) + getattr(
                self, "_cache_misses", 0
            )
            if total_cache_requests > 0:
                self.performance_metrics.cache_hit_rate = (
                    getattr(self, "_cache_hits", 0) / total_cache_requests
                )

            # Update performance target compliance
            compliant_validations = sum(
                1 for t in self.validation_times if t <= self.performance_target_ms
            )
            if self.validation_times:
                self.performance_metrics.performance_target_compliance = (
                    compliant_validations / len(self.validation_times)
                )

            # Update domain-specific metrics
            if domain not in self.performance_metrics.domain_metrics:
                self.performance_metrics.domain_metrics[domain] = {
                    "total_validations": 0,
                    "average_time_ms": 0.0,
                    "cache_hit_rate": 0.0,
                }

            domain_metrics = self.performance_metrics.domain_metrics[domain]
            domain_metrics["total_validations"] += 1

            domain_avg = domain_metrics["average_time_ms"]
            domain_total = domain_metrics["total_validations"]
            domain_metrics["average_time_ms"] = (
                domain_avg * (domain_total - 1) + validation_time_ms
            ) / domain_total

    async def _create_unified_audit_trail(
        self, request: ValidationRequest, response: ValidationResponse
    ):
        """Create comprehensive audit trail entry"""

        audit_entry = {
            "event_type": "unified_security_validation",
            "request_id": request.request_id,
            "domain": request.domain.value,
            "operation_type": request.operation_type,
            "user_id": (
                request.user_context.get("user_id", "unknown")
                if request.user_context
                else "unknown"
            ),
            "validation_decision": response.decision,
            "confidence": response.confidence,
            "reasoning": response.reasoning,
            "validation_time_ms": response.validation_time_ms,
            "cache_hit": response.cache_hit,
            "monitoring_required": response.monitoring_required,
            "approval_session_id": response.approval_session_id,
            "approver_ids": response.approver_ids,
            "performance_compliant": response.validation_time_ms
            <= self.performance_target_ms,
            "timestamp": datetime.now().isoformat(),
        }

        # Add to response audit trail
        response.audit_trail.append(audit_entry)

        # Log for monitoring
        self.logger.info("Unified security validation audit", extra=audit_entry)

        # Send to enterprise security orchestrator if available
        if self.security_orchestrator:
            try:
                await self.security_orchestrator.log_security_event(audit_entry)
            except Exception as e:
                self.logger.error(f"Failed to log to security orchestrator: {str(e)}")

    async def validate_integrated_workflow(
        self, workflow_requests: List[ValidationRequest]
    ) -> List[ValidationResponse]:
        """
        Validate multiple operations as an integrated workflow

        Provides concurrent validation of multiple operations with
        workflow-level optimization and dependency management.
        """

        workflow_start = time.time()
        workflow_id = str(uuid.uuid4())

        self.logger.info(
            "Starting integrated workflow validation",
            extra={
                "workflow_id": workflow_id,
                "request_count": len(workflow_requests),
                "domains": [req.domain.value for req in workflow_requests],
            },
        )

        try:
            # Group requests by priority for optimal processing order
            prioritized_requests = self._prioritize_workflow_requests(workflow_requests)

            # Execute validations concurrently with dependency management
            if len(workflow_requests) <= self.max_concurrent_validations:
                # All requests can be processed concurrently
                validation_tasks = [
                    self.validate(request) for request in prioritized_requests
                ]
                responses = await asyncio.gather(
                    *validation_tasks, return_exceptions=True
                )
            else:
                # Process in batches
                responses = await self._process_workflow_batches(prioritized_requests)

            # Handle any exceptions in responses
            final_responses = []
            for i, response in enumerate(responses):
                if isinstance(response, Exception):
                    self.logger.error(f"Workflow validation error: {str(response)}")
                    final_responses.append(
                        ValidationResponse(
                            request_id=workflow_requests[i].request_id,
                            decision="blocked",
                            confidence=0.9,
                            reasoning=f"Workflow validation error: {str(response)}",
                            domain=workflow_requests[i].domain,
                            validation_time_ms=0.0,
                        )
                    )
                else:
                    final_responses.append(response)

            # Log workflow completion
            workflow_time_ms = (time.time() - workflow_start) * 1000
            self.logger.info(
                "Integrated workflow validation completed",
                extra={
                    "workflow_id": workflow_id,
                    "total_time_ms": workflow_time_ms,
                    "request_count": len(workflow_requests),
                    "approved_count": sum(
                        1 for r in final_responses if r.decision == "approved"
                    ),
                    "blocked_count": sum(
                        1 for r in final_responses if r.decision == "blocked"
                    ),
                },
            )

            return final_responses

        except Exception as e:
            self.logger.error(f"Integrated workflow validation error: {str(e)}")

            # Return error responses for all requests
            return [
                ValidationResponse(
                    request_id=req.request_id,
                    decision="blocked",
                    confidence=0.9,
                    reasoning=f"Workflow validation system error: {str(e)}",
                    domain=req.domain,
                    validation_time_ms=0.0,
                )
                for req in workflow_requests
            ]

    def _prioritize_workflow_requests(
        self, requests: List[ValidationRequest]
    ) -> List[ValidationRequest]:
        """Prioritize workflow requests for optimal processing"""

        # Sort by priority and then by estimated processing time
        priority_order = {
            ValidationPriority.EMERGENCY: 0,
            ValidationPriority.CRITICAL: 1,
            ValidationPriority.HIGH: 2,
            ValidationPriority.NORMAL: 3,
            ValidationPriority.LOW: 4,
        }

        # Estimate processing time based on domain
        domain_time_estimates = {
            ValidationDomain.HTTP_REQUEST: 50,
            ValidationDomain.LLM_INTERACTION: 100,
            ValidationDomain.FILE_SYSTEM: 150,
            ValidationDomain.TERMINAL_COMMAND: 200,
            ValidationDomain.CODE_EXECUTION: 300,
        }

        return sorted(
            requests,
            key=lambda req: (
                priority_order.get(req.priority, 999),
                domain_time_estimates.get(req.domain, 500),
            ),
        )

    async def _process_workflow_batches(
        self, requests: List[ValidationRequest]
    ) -> List[ValidationResponse]:
        """Process workflow requests in optimized batches"""

        batch_size = self.max_concurrent_validations
        responses = []

        for i in range(0, len(requests), batch_size):
            batch = requests[i : i + batch_size]

            batch_tasks = [self.validate(request) for request in batch]
            batch_responses = await asyncio.gather(*batch_tasks, return_exceptions=True)

            responses.extend(batch_responses)

        return responses

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics"""

        with self.metrics_lock:
            # Calculate concurrent utilization
            with self.active_validations_lock:
                current_utilization = (
                    len(self.active_validations) / self.max_concurrent_validations
                )

            return {
                "total_validations": self.performance_metrics.total_validations,
                "average_validation_time_ms": self.performance_metrics.average_validation_time_ms,
                "p95_validation_time_ms": self.performance_metrics.p95_validation_time_ms,
                "p99_validation_time_ms": self.performance_metrics.p99_validation_time_ms,
                "cache_hit_rate": self.performance_metrics.cache_hit_rate,
                "concurrent_utilization": current_utilization,
                "performance_target_compliance": self.performance_metrics.performance_target_compliance,
                "performance_target_ms": self.performance_target_ms,
                "max_concurrent_validations": self.max_concurrent_validations,
                "domain_metrics": {
                    domain.value: metrics
                    for domain, metrics in self.performance_metrics.domain_metrics.items()
                },
                "cache_statistics": {
                    level.value: {
                        "size": len(config["storage"]),
                        "max_size": config["max_size"],
                        "ttl_seconds": config["ttl_seconds"],
                    }
                    for level, config in self.cache_config.items()
                },
                "active_validations": len(self.active_validations),
                "system_health": {
                    "performance_compliant": self.performance_metrics.performance_target_compliance
                    >= 0.95,
                    "cache_healthy": self.performance_metrics.cache_hit_rate >= 0.6,
                    "concurrency_healthy": current_utilization < 0.8,
                },
            }

    def get_domain_validator_metrics(self) -> Dict[str, Any]:
        """Get metrics from all domain validators"""

        metrics = {}

        for domain, validator in self.domain_validators.items():
            try:
                if hasattr(validator, "get_metrics"):
                    metrics[domain.value] = validator.get_metrics()
                else:
                    metrics[domain.value] = {"error": "Metrics not available"}
            except Exception as e:
                metrics[domain.value] = {"error": str(e)}

        return metrics

    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check for the security framework"""

        health_start = time.time()

        try:
            # Check each domain validator
            validator_health = {}
            for domain, validator in self.domain_validators.items():
                try:
                    # Simple validation test
                    test_response = await asyncio.wait_for(
                        self._test_validator_health(domain, validator), timeout=1.0
                    )
                    validator_health[domain.value] = {
                        "status": "healthy",
                        "response_time_ms": test_response.get("response_time_ms", 0),
                    }
                except Exception as e:
                    validator_health[domain.value] = {
                        "status": "unhealthy",
                        "error": str(e),
                    }

            # Get performance metrics
            performance_metrics = self.get_performance_metrics()

            # Overall health assessment
            overall_health = all(
                status["status"] == "healthy" for status in validator_health.values()
            )

            health_check_time_ms = (time.time() - health_start) * 1000

            return {
                "overall_status": "healthy" if overall_health else "unhealthy",
                "health_check_time_ms": health_check_time_ms,
                "validator_health": validator_health,
                "performance_metrics": performance_metrics,
                "system_info": {
                    "framework_version": "1.0.0",
                    "performance_target_ms": self.performance_target_ms,
                    "cache_enabled": self.cache_enabled,
                    "max_concurrent_validations": self.max_concurrent_validations,
                },
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {
                "overall_status": "unhealthy",
                "error": str(e),
                "health_check_time_ms": (time.time() - health_start) * 1000,
                "timestamp": datetime.now().isoformat(),
            }

    async def _test_validator_health(
        self, domain: ValidationDomain, validator: Any
    ) -> Dict[str, Any]:
        """Test health of a specific domain validator"""

        test_start = time.time()

        # Create minimal test request for each domain
        if domain == ValidationDomain.CODE_EXECUTION:
            # Test with simple safe code
            test_request = ValidationRequest(
                request_id=f"health-{domain.value}",
                domain=domain,
                priority=ValidationPriority.LOW,
                operation_type="test",
                request_data={"code": "print('hello')", "language": "python"},
                timeout_ms=1000,
                cache_enabled=False,
            )
        else:
            # Generic test request
            test_request = ValidationRequest(
                request_id=f"health-{domain.value}",
                domain=domain,
                priority=ValidationPriority.LOW,
                operation_type="test",
                request_data={"test": True},
                timeout_ms=1000,
                cache_enabled=False,
            )

        try:
            # Perform minimal validation test
            response = await self._perform_domain_validation(test_request)

            return {
                "status": "healthy",
                "response_time_ms": (time.time() - test_start) * 1000,
                "test_response": response.decision,
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "response_time_ms": (time.time() - test_start) * 1000,
            }

    def shutdown(self):
        """Gracefully shutdown the security framework"""

        self.logger.info("Shutting down PARLANT Unified Security Framework")

        try:
            # Shutdown thread pool
            self.thread_pool.shutdown(wait=True, timeout=30)

            # Clear caches
            with self.cache_lock:
                for cache_config in self.cache_config.values():
                    cache_config["storage"].clear()

            # Log final metrics
            final_metrics = self.get_performance_metrics()
            self.logger.info("Final performance metrics", extra=final_metrics)

            self.logger.info("PARLANT Unified Security Framework shutdown complete")

        except Exception as e:
            self.logger.error(f"Error during shutdown: {str(e)}")


# Factory function for easy integration
async def create_parlant_security_framework(
    parlant_service: Optional[ParlantIntegrationService] = None, **kwargs
) -> ParlantUnifiedSecurityFramework:
    """
    Factory function to create PARLANT Unified Security Framework

    Args:
        parlant_service: Optional PARLANT service instance
        **kwargs: Additional configuration options

    Returns:
        Configured ParlantUnifiedSecurityFramework instance
    """

    if parlant_service is None:
        parlant_service = ParlantIntegrationService()

    return ParlantUnifiedSecurityFramework(parlant_service=parlant_service, **kwargs)
