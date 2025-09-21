"""
Open Interpreter Integration Framework

This package provides comprehensive integration patterns for Open-Interpreter
with external systems, particularly for conversational validation and security.
"""

from .context_managers import ConversationalSession, SecurityContext, ValidationScope
from .decorators import (
    audit_logged,
    conversational_validation,
    risk_assessed,
    security_validated,
)
from .parlant_bridge import (
    ConversationalContext,
    ParlantBridgeService,
    ParlantValidationError,
    RiskAssessment,
    SecurityLevel,
    ValidationRequest,
    ValidationResponse,
)

__all__ = [
    # Core Services
    "ParlantBridgeService",
    "ParlantValidationError",
    # Data Models
    "ConversationalContext",
    "SecurityLevel",
    "RiskAssessment",
    "ValidationRequest",
    "ValidationResponse",
    # Decorators
    "conversational_validation",
    "security_validated",
    "risk_assessed",
    "audit_logged",
    # Context Managers
    "ConversationalSession",
    "SecurityContext",
    "ValidationScope",
]
