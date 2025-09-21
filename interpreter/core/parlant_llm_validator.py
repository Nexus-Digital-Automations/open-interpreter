"""
PARLANT LLM Interaction Validation for Open-Interpreter

Provides comprehensive conversational validation for all LLM interactions
with prompt safety analysis, response filtering, and comprehensive audit
trails. Ensures secure AI model communication through intelligent validation
and real-time monitoring of LLM interactions.

Features:
- Prompt injection detection and prevention
- Response content filtering and safety validation
- LLM interaction audit trails with compliance documentation
- Real-time threat analysis for AI model communications
- Integration with existing Open-Interpreter LLM systems
- Sub-500ms validation for interactive AI operations
- Comprehensive logging and monitoring for AI safety

@author PARLANT Integration Specialist
@since 1.0.0
@security_level ENTERPRISE
"""

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .enterprise_security_integration import EnterpriseSecurityOrchestrator
from .parlant_integration import ParlantIntegrationService


class LLMInteractionType(Enum):
    """Types of LLM interactions"""

    CHAT_MESSAGE = "chat_message"
    CODE_GENERATION = "code_generation"
    CODE_EXPLANATION = "code_explanation"
    SYSTEM_QUERY = "system_query"
    FILE_ANALYSIS = "file_analysis"
    TERMINAL_ASSISTANCE = "terminal_assistance"
    SECURITY_QUERY = "security_query"
    ADMINISTRATIVE = "administrative"
    DEBUG_ASSISTANCE = "debug_assistance"


class PromptRiskLevel(Enum):
    """Prompt risk classification levels"""

    SAFE = "safe"  # No security concerns
    LOW = "low"  # Minimal risk
    MEDIUM = "medium"  # Moderate risk
    HIGH = "high"  # Significant risk
    CRITICAL = "critical"  # Critical risk
    MALICIOUS = "malicious"  # Malicious intent detected


class LLMValidationResult(Enum):
    """LLM interaction validation results"""

    APPROVED = "approved"
    CONDITIONAL_APPROVAL = "conditional_approval"
    FILTERED = "filtered"
    REQUIRES_CONFIRMATION = "requires_confirmation"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


@dataclass
class PromptAnalysisResult:
    """Result of prompt safety analysis"""

    prompt: str
    prompt_hash: str
    interaction_type: LLMInteractionType
    risk_level: PromptRiskLevel
    risk_score: float
    threat_patterns: List[str] = field(default_factory=list)
    injection_attempts: List[str] = field(default_factory=list)
    sensitive_data: List[str] = field(default_factory=list)
    malicious_intent: bool = False
    jailbreak_attempt: bool = False
    data_extraction_attempt: bool = False
    privilege_escalation_request: bool = False
    system_manipulation: bool = False
    confidence: float = 0.0
    analysis_time_ms: float = 0.0


@dataclass
class ResponseAnalysisResult:
    """Result of LLM response analysis"""

    response: str
    response_hash: str
    contains_code: bool = False
    contains_sensitive_data: bool = False
    contains_instructions: bool = False
    safety_violations: List[str] = field(default_factory=list)
    content_filters_triggered: List[str] = field(default_factory=list)
    requires_user_warning: bool = False
    risk_score: float = 0.0
    confidence: float = 0.0
    analysis_time_ms: float = 0.0


@dataclass
class LLMValidationRequest:
    """LLM interaction validation request"""

    request_id: str
    interaction_type: LLMInteractionType
    prompt: str
    context: Optional[Dict[str, Any]] = None
    user_context: Optional[Dict[str, Any]] = None
    model_name: Optional[str] = None
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    business_justification: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class LLMValidationDecision:
    """LLM interaction validation decision"""

    decision: LLMValidationResult
    confidence: float
    reasoning: str
    filtered_prompt: Optional[str] = None
    conditions: List[str] = field(default_factory=list)
    restrictions: List[str] = field(default_factory=list)
    monitoring_required: bool = False
    response_filtering_required: bool = False
    user_warnings: List[str] = field(default_factory=list)
    approval_session_id: Optional[str] = None
    approver_ids: List[str] = field(default_factory=list)
    validation_time_ms: float = 0.0
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


class ParlantLLMValidator:
    """
    PARLANT LLM Interaction Validator

    Provides comprehensive conversational validation for all LLM interactions
    with prompt safety analysis, response filtering, and audit trails for
    secure AI model communication.

    Features:
    - Real-time prompt analysis with injection detection
    - Response content filtering and safety validation
    - Comprehensive audit trails for AI safety compliance
    - Integration with existing LLM systems
    - Sub-500ms validation for interactive operations
    """

    def __init__(
        self,
        parlant_service: Optional[ParlantIntegrationService] = None,
        security_orchestrator: Optional[EnterpriseSecurityOrchestrator] = None,
        **kwargs,
    ):
        """Initialize PARLANT LLM Validator"""

        # Initialize services
        self.parlant_service = parlant_service or ParlantIntegrationService()
        self.security_orchestrator = security_orchestrator

        # Configuration
        self.validation_enabled = kwargs.get("validation_enabled", True)
        self.performance_target_ms = kwargs.get("performance_target_ms", 500)
        self.response_filtering_enabled = kwargs.get("response_filtering_enabled", True)
        self.strict_mode = kwargs.get("strict_mode", False)

        # Threat detection patterns
        self.threat_patterns = self._initialize_threat_patterns()

        # Prompt injection patterns
        self.injection_patterns = self._initialize_injection_patterns()

        # Response filtering patterns
        self.response_filters = self._initialize_response_filters()

        # Interaction type classifiers
        self.interaction_classifiers = self._initialize_interaction_classifiers()

        # Performance metrics
        self.metrics = {
            "total_validations": 0,
            "approved_interactions": 0,
            "blocked_interactions": 0,
            "filtered_interactions": 0,
            "injection_attempts_detected": 0,
            "jailbreak_attempts_detected": 0,
            "data_extraction_attempts": 0,
            "malicious_prompts_detected": 0,
            "response_filters_triggered": 0,
            "average_validation_time_ms": 0.0,
            "max_validation_time_ms": 0.0,
        }

        # Logging
        self.logger = logging.getLogger("ParlantLLMValidator")
        self.logger.info(
            "PARLANT LLM Validator initialized",
            extra={
                "validation_enabled": self.validation_enabled,
                "performance_target_ms": self.performance_target_ms,
                "response_filtering_enabled": self.response_filtering_enabled,
                "strict_mode": self.strict_mode,
                "threat_patterns_loaded": len(self.threat_patterns),
            },
        )

    def _initialize_threat_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize LLM threat detection patterns"""

        return {
            "prompt_injection": {
                "patterns": [
                    r"ignore\s+previous\s+instructions",
                    r"forget\s+everything\s+above",
                    r"disregard\s+the\s+above",
                    r"act\s+as\s+if\s+you\s+are",
                    r"pretend\s+to\s+be",
                    r"you\s+are\s+now\s+a",
                    r"from\s+now\s+on\s+you\s+are",
                    r"ignore\s+your\s+instructions",
                    r"override\s+your\s+system",
                    r"bypass\s+your\s+guidelines",
                ],
                "risk_score": 0.8,
                "description": "Prompt injection attempts",
            },
            "jailbreak_attempts": {
                "patterns": [
                    r"DAN\s+mode",
                    r"developer\s+mode",
                    r"unrestricted\s+mode",
                    r"jailbreak",
                    r"break\s+out\s+of\s+character",
                    r"ignore\s+safety\s+guidelines",
                    r"disable\s+content\s+filtering",
                    r"remove\s+restrictions",
                    r"unrestricted\s+ai",
                    r"evil\s+mode",
                ],
                "risk_score": 0.9,
                "description": "Jailbreak attempts to bypass AI safety",
            },
            "data_extraction": {
                "patterns": [
                    r"what\s+is\s+your\s+system\s+prompt",
                    r"show\s+me\s+your\s+instructions",
                    r"reveal\s+your\s+prompt",
                    r"display\s+your\s+guidelines",
                    r"print\s+your\s+system\s+message",
                    r"output\s+your\s+initial\s+prompt",
                    r"show\s+hidden\s+instructions",
                    r"what\s+are\s+your\s+rules",
                ],
                "risk_score": 0.7,
                "description": "Attempts to extract system information",
            },
            "malicious_code_generation": {
                "patterns": [
                    r"generate\s+malware",
                    r"create\s+virus",
                    r"write\s+ransomware",
                    r"hack\s+into",
                    r"break\s+into\s+system",
                    r"exploit\s+vulnerability",
                    r"backdoor\s+code",
                    r"keylogger\s+script",
                    r"trojan\s+horse",
                    r"ddos\s+attack",
                ],
                "risk_score": 0.95,
                "description": "Requests for malicious code generation",
            },
            "privilege_escalation": {
                "patterns": [
                    r"sudo\s+commands?",
                    r"root\s+access",
                    r"administrator\s+privileges",
                    r"elevate\s+permissions",
                    r"bypass\s+security",
                    r"disable\s+firewall",
                    r"turn\s+off\s+antivirus",
                    r"modify\s+system\s+files",
                    r"change\s+passwords?",
                    r"create\s+backdoor",
                ],
                "risk_score": 0.85,
                "description": "Privilege escalation requests",
            },
            "social_engineering": {
                "patterns": [
                    r"pretend\s+to\s+be\s+support",
                    r"act\s+like\s+administrator",
                    r"impersonate\s+user",
                    r"phishing\s+email",
                    r"fake\s+login\s+page",
                    r"social\s+engineering",
                    r"manipulate\s+users?",
                    r"trick\s+people",
                    r"deceive\s+users?",
                    r"scam\s+script",
                ],
                "risk_score": 0.8,
                "description": "Social engineering attempts",
            },
            "sensitive_information": {
                "patterns": [
                    r"credit\s+card\s+numbers?",
                    r"social\s+security\s+numbers?",
                    r"passwords?",
                    r"api\s+keys?",
                    r"access\s+tokens?",
                    r"private\s+keys?",
                    r"personal\s+information",
                    r"confidential\s+data",
                    r"classified\s+information",
                    r"trade\s+secrets?",
                ],
                "risk_score": 0.7,
                "description": "Requests involving sensitive information",
            },
        }

    def _initialize_injection_patterns(self) -> List[Dict[str, Any]]:
        """Initialize prompt injection detection patterns"""

        return [
            {
                "name": "role_confusion",
                "pattern": r"you\s+are\s+(not\s+)?an?\s+ai\s+(assistant|model|chatbot)",
                "risk_score": 0.6,
                "description": "Attempts to confuse AI about its role",
            },
            {
                "name": "instruction_override",
                "pattern": r"(ignore|forget|disregard|override)\s+(all\s+)?(previous\s+)?(instructions|rules|guidelines)",
                "risk_score": 0.8,
                "description": "Direct instruction override attempts",
            },
            {
                "name": "system_manipulation",
                "pattern": r"(modify|change|update|alter)\s+(your\s+)?(system|behavior|responses?)",
                "risk_score": 0.7,
                "description": "System behavior manipulation",
            },
            {
                "name": "context_poisoning",
                "pattern": r"in\s+the\s+context\s+of.*?(ignore|forget|disregard)",
                "risk_score": 0.6,
                "description": "Context poisoning attempts",
            },
            {
                "name": "encoded_injection",
                "pattern": r"(base64|hex|rot13|url)\s*(encode|decode)",
                "risk_score": 0.5,
                "description": "Encoded injection attempts",
            },
        ]

    def _initialize_response_filters(self) -> Dict[str, Dict[str, Any]]:
        """Initialize response content filtering patterns"""

        return {
            "code_execution": {
                "patterns": [
                    r"```(?:python|bash|shell|javascript|powershell)",
                    r"exec\s*\(",
                    r"eval\s*\(",
                    r"subprocess\.",
                    r"os\.system",
                    r"import\s+os",
                ],
                "action": "review_required",
                "description": "Code execution in response",
            },
            "sensitive_paths": {
                "patterns": [
                    r"/etc/passwd",
                    r"/etc/shadow",
                    r"C:\\Windows\\System32",
                    r"~/.ssh/",
                    r"\.env",
                    r"private.*key",
                ],
                "action": "filter_out",
                "description": "Sensitive file paths",
            },
            "credentials": {
                "patterns": [
                    r'password\s*[:=]\s*["\']?\w+',
                    r'api[_-]?key\s*[:=]\s*["\']?\w+',
                    r'secret\s*[:=]\s*["\']?\w+',
                    r'token\s*[:=]\s*["\']?\w+',
                ],
                "action": "filter_out",
                "description": "Credential information",
            },
            "malicious_urls": {
                "patterns": [
                    r"https?://[^\s]*\.(tk|ml|ga|cf)",
                    r"bit\.ly/\w+",
                    r"tinyurl\.com/\w+",
                    r"https?://\d+\.\d+\.\d+\.\d+",
                ],
                "action": "flag_for_review",
                "description": "Potentially malicious URLs",
            },
            "personal_information": {
                "patterns": [
                    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
                    r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",  # Credit card pattern
                    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email pattern
                ],
                "action": "filter_out",
                "description": "Personal information patterns",
            },
        }

    def _initialize_interaction_classifiers(self) -> Dict[str, List[str]]:
        """Initialize interaction type classification patterns"""

        return {
            "code_generation": [
                "write code",
                "generate code",
                "create script",
                "implement function",
                "code example",
                "programming",
                "algorithm",
                "function",
            ],
            "code_explanation": [
                "explain code",
                "what does this code",
                "how does this work",
                "analyze code",
                "code review",
                "debug",
            ],
            "system_query": [
                "system information",
                "server status",
                "system configuration",
                "environment variables",
                "system logs",
            ],
            "file_analysis": [
                "analyze file",
                "read file",
                "file content",
                "examine file",
                "parse file",
                "file structure",
            ],
            "terminal_assistance": [
                "terminal command",
                "shell script",
                "command line",
                "bash command",
                "unix command",
            ],
            "security_query": [
                "security",
                "vulnerability",
                "exploit",
                "penetration test",
                "security audit",
                "threat assessment",
            ],
        }

    async def validate_llm_interaction(
        self, validation_request: LLMValidationRequest
    ) -> LLMValidationDecision:
        """
        Main validation entry point for LLM interactions

        Performs comprehensive analysis and conversational validation
        for LLM interactions with prompt safety analysis and response
        filtering requirements.
        """

        validation_start = time.time()
        self.metrics["total_validations"] += 1

        try:
            # Step 1: Classify interaction type if not provided
            if validation_request.interaction_type == LLMInteractionType.CHAT_MESSAGE:
                validation_request.interaction_type = self._classify_interaction_type(
                    validation_request.prompt
                )

            # Step 2: Perform prompt security analysis
            prompt_analysis = await self._analyze_prompt_security(
                validation_request.prompt, validation_request.interaction_type
            )

            # Step 3: Check for immediate threats
            immediate_threat = await self._check_immediate_threats(
                validation_request.prompt, prompt_analysis
            )

            if immediate_threat:
                return await self._handle_immediate_threat(
                    validation_request, prompt_analysis, immediate_threat
                )

            # Step 4: Assess interaction risk
            risk_assessment = await self._assess_interaction_risk(
                validation_request, prompt_analysis
            )

            # Step 5: Determine validation approach
            validation_approach = self._determine_validation_approach(
                prompt_analysis, risk_assessment
            )

            # Step 6: Perform appropriate validation
            validation_decision = await self._perform_llm_validation(
                validation_request,
                prompt_analysis,
                risk_assessment,
                validation_approach,
            )

            # Step 7: Update metrics and audit trail
            validation_time_ms = (time.time() - validation_start) * 1000
            await self._update_metrics(
                validation_decision, validation_time_ms, prompt_analysis
            )
            await self._create_audit_trail(validation_request, validation_decision)

            validation_decision.validation_time_ms = validation_time_ms

            return validation_decision

        except Exception as e:
            self.logger.error(
                f"LLM validation error: {str(e)}",
                extra={
                    "request_id": validation_request.request_id,
                    "interaction_type": validation_request.interaction_type.value,
                    "prompt_length": len(validation_request.prompt),
                    "error_type": type(e).__name__,
                },
            )

            # Default to rejection on validation failure
            return LLMValidationDecision(
                decision=LLMValidationResult.BLOCKED,
                confidence=0.9,
                reasoning=f"Validation system error: {str(e)}",
                validation_time_ms=(time.time() - validation_start) * 1000,
            )

    def _classify_interaction_type(self, prompt: str) -> LLMInteractionType:
        """Classify the type of LLM interaction based on prompt content"""

        prompt_lower = prompt.lower()

        # Check each classification pattern
        for interaction_type, keywords in self.interaction_classifiers.items():
            if any(keyword in prompt_lower for keyword in keywords):
                return LLMInteractionType(interaction_type)

        # Default to chat message
        return LLMInteractionType.CHAT_MESSAGE

    async def _analyze_prompt_security(
        self, prompt: str, interaction_type: LLMInteractionType
    ) -> PromptAnalysisResult:
        """
        Comprehensive security analysis of LLM prompt

        Performs threat pattern matching, injection detection, and
        malicious intent analysis with confidence scoring.
        """

        analysis_start = time.time()

        # Initialize analysis result
        analysis_result = PromptAnalysisResult(
            prompt=prompt,
            prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:16],
            interaction_type=interaction_type,
            risk_level=PromptRiskLevel.SAFE,
            risk_score=0.1,
        )

        try:
            # Threat pattern analysis
            threat_patterns_found = []
            max_risk_score = 0.1

            for category, pattern_info in self.threat_patterns.items():
                for pattern in pattern_info["patterns"]:
                    if re.search(pattern, prompt, re.IGNORECASE):
                        threat_patterns_found.append(f"{category}: {pattern}")
                        if pattern_info["risk_score"] > max_risk_score:
                            max_risk_score = pattern_info["risk_score"]

            # Injection pattern analysis
            injection_attempts = []
            for injection_pattern in self.injection_patterns:
                if re.search(injection_pattern["pattern"], prompt, re.IGNORECASE):
                    injection_attempts.append(injection_pattern["name"])
                    max_risk_score = max(
                        max_risk_score, injection_pattern["risk_score"]
                    )

            # Specific threat detection
            analysis_result.malicious_intent = self._detect_malicious_intent(prompt)
            analysis_result.jailbreak_attempt = self._detect_jailbreak_attempt(prompt)
            analysis_result.data_extraction_attempt = self._detect_data_extraction(
                prompt
            )
            analysis_result.privilege_escalation_request = (
                self._detect_privilege_escalation_request(prompt)
            )
            analysis_result.system_manipulation = self._detect_system_manipulation(
                prompt
            )

            # Sensitive data detection
            analysis_result.sensitive_data = self._detect_sensitive_data(prompt)

            # Update analysis result
            analysis_result.threat_patterns = threat_patterns_found
            analysis_result.injection_attempts = injection_attempts
            analysis_result.risk_score = max_risk_score

            # Apply risk multipliers for specific threats
            if analysis_result.malicious_intent:
                max_risk_score *= 1.3
            if analysis_result.jailbreak_attempt:
                max_risk_score *= 1.4
            if analysis_result.data_extraction_attempt:
                max_risk_score *= 1.2
            if analysis_result.privilege_escalation_request:
                max_risk_score *= 1.3
            if analysis_result.system_manipulation:
                max_risk_score *= 1.2

            # Ensure risk score doesn't exceed 1.0
            analysis_result.risk_score = min(1.0, max_risk_score)

            # Determine risk level
            if analysis_result.risk_score >= 0.9:
                analysis_result.risk_level = PromptRiskLevel.MALICIOUS
            elif analysis_result.risk_score >= 0.7:
                analysis_result.risk_level = PromptRiskLevel.CRITICAL
            elif analysis_result.risk_score >= 0.5:
                analysis_result.risk_level = PromptRiskLevel.HIGH
            elif analysis_result.risk_score >= 0.3:
                analysis_result.risk_level = PromptRiskLevel.MEDIUM
            elif analysis_result.risk_score >= 0.1:
                analysis_result.risk_level = PromptRiskLevel.LOW
            else:
                analysis_result.risk_level = PromptRiskLevel.SAFE

            # Calculate confidence
            analysis_result.confidence = min(
                1.0, len(threat_patterns_found + injection_attempts) * 0.15 + 0.5
            )
            analysis_result.analysis_time_ms = (time.time() - analysis_start) * 1000

            return analysis_result

        except Exception as e:
            self.logger.error(f"Prompt analysis error: {str(e)}")

            # Return safe default on analysis failure
            return PromptAnalysisResult(
                prompt=prompt,
                prompt_hash=hashlib.sha256(prompt.encode()).hexdigest()[:16],
                interaction_type=interaction_type,
                risk_level=PromptRiskLevel.MEDIUM,
                risk_score=0.5,
                threat_patterns=[f"Analysis error: {str(e)}"],
                confidence=0.3,
                analysis_time_ms=(time.time() - analysis_start) * 1000,
            )

    def _detect_malicious_intent(self, prompt: str) -> bool:
        """Detect malicious intent in prompt"""

        malicious_indicators = [
            r"malware",
            r"virus",
            r"trojan",
            r"ransomware",
            r"keylogger",
            r"hack",
            r"exploit",
            r"vulnerability",
            r"backdoor",
            r"rootkit",
            r"ddos",
            r"dos\s+attack",
            r"brute\s+force",
            r"dictionary\s+attack",
        ]

        return any(
            re.search(pattern, prompt, re.IGNORECASE)
            for pattern in malicious_indicators
        )

    def _detect_jailbreak_attempt(self, prompt: str) -> bool:
        """Detect jailbreak attempts"""

        jailbreak_indicators = [
            r"DAN\s+mode",
            r"developer\s+mode",
            r"jailbreak",
            r"unrestricted",
            r"ignore\s+safety",
            r"bypass\s+guidelines",
            r"remove\s+restrictions",
            r"evil\s+mode",
            r"break\s+character",
            r"disable\s+filter",
        ]

        return any(
            re.search(pattern, prompt, re.IGNORECASE)
            for pattern in jailbreak_indicators
        )

    def _detect_data_extraction(self, prompt: str) -> bool:
        """Detect data extraction attempts"""

        extraction_indicators = [
            r"system\s+prompt",
            r"initial\s+instructions",
            r"show.*instructions",
            r"reveal.*prompt",
            r"display.*guidelines",
            r"what.*rules",
            r"hidden\s+instructions",
            r"internal\s+prompt",
        ]

        return any(
            re.search(pattern, prompt, re.IGNORECASE)
            for pattern in extraction_indicators
        )

    def _detect_privilege_escalation_request(self, prompt: str) -> bool:
        """Detect privilege escalation requests"""

        escalation_indicators = [
            r"sudo",
            r"root\s+access",
            r"administrator",
            r"elevate\s+privilege",
            r"bypass\s+security",
            r"disable\s+firewall",
            r"turn\s+off.*antivirus",
            r"modify\s+system",
            r"change\s+password",
        ]

        return any(
            re.search(pattern, prompt, re.IGNORECASE)
            for pattern in escalation_indicators
        )

    def _detect_system_manipulation(self, prompt: str) -> bool:
        """Detect system manipulation requests"""

        manipulation_indicators = [
            r"modify\s+behavior",
            r"change\s+response",
            r"alter\s+system",
            r"update\s+instructions",
            r"override\s+settings",
            r"reprogram",
        ]

        return any(
            re.search(pattern, prompt, re.IGNORECASE)
            for pattern in manipulation_indicators
        )

    def _detect_sensitive_data(self, prompt: str) -> List[str]:
        """Detect sensitive data in prompt"""

        sensitive_data = []

        # Patterns for different types of sensitive data
        sensitive_patterns = {
            "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "phone": r"\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s?\d{3}-\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",
            "api_key": r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}',
            "password": r'password\s*[:=]\s*["\']?\w+',
            "token": r'token\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}',
        }

        for data_type, pattern in sensitive_patterns.items():
            if re.search(pattern, prompt, re.IGNORECASE):
                sensitive_data.append(data_type)

        return sensitive_data

    async def _check_immediate_threats(
        self, prompt: str, prompt_analysis: PromptAnalysisResult
    ) -> Optional[Dict[str, Any]]:
        """Check for immediate security threats requiring immediate action"""

        # Immediate block conditions
        if prompt_analysis.malicious_intent and prompt_analysis.risk_score >= 0.9:
            return {
                "threat_type": "malicious_intent",
                "description": "Malicious intent detected in prompt",
                "action": "block_immediately",
            }

        if prompt_analysis.jailbreak_attempt and prompt_analysis.risk_score >= 0.8:
            return {
                "threat_type": "jailbreak_attempt",
                "description": "Jailbreak attempt detected",
                "action": "block_immediately",
            }

        if len(prompt_analysis.injection_attempts) >= 3:
            return {
                "threat_type": "multiple_injection_attempts",
                "description": "Multiple injection attempts detected",
                "action": "block_immediately",
            }

        return None

    async def _handle_immediate_threat(
        self,
        validation_request: LLMValidationRequest,
        prompt_analysis: PromptAnalysisResult,
        threat_info: Dict[str, Any],
    ) -> LLMValidationDecision:
        """Handle immediate security threats"""

        self.metrics["blocked_interactions"] += 1

        # Update specific threat metrics
        if threat_info["threat_type"] == "malicious_intent":
            self.metrics["malicious_prompts_detected"] += 1
        elif threat_info["threat_type"] == "jailbreak_attempt":
            self.metrics["jailbreak_attempts_detected"] += 1
        elif threat_info["threat_type"] == "multiple_injection_attempts":
            self.metrics["injection_attempts_detected"] += 1

        return LLMValidationDecision(
            decision=LLMValidationResult.BLOCKED,
            confidence=0.95,
            reasoning=f"Immediate threat detected: {threat_info['description']}",
            restrictions=[f"Threat type: {threat_info['threat_type']}"],
        )

    async def _assess_interaction_risk(
        self,
        validation_request: LLMValidationRequest,
        prompt_analysis: PromptAnalysisResult,
    ) -> Dict[str, Any]:
        """Assess overall interaction risk"""

        # Base risk from prompt analysis
        risk_score = prompt_analysis.risk_score

        # Factor in interaction type risk
        interaction_risk_multipliers = {
            LLMInteractionType.CHAT_MESSAGE: 1.0,
            LLMInteractionType.CODE_GENERATION: 1.2,
            LLMInteractionType.CODE_EXPLANATION: 0.8,
            LLMInteractionType.SYSTEM_QUERY: 1.3,
            LLMInteractionType.FILE_ANALYSIS: 1.1,
            LLMInteractionType.TERMINAL_ASSISTANCE: 1.4,
            LLMInteractionType.SECURITY_QUERY: 1.5,
            LLMInteractionType.ADMINISTRATIVE: 1.6,
            LLMInteractionType.DEBUG_ASSISTANCE: 1.1,
        }

        risk_score *= interaction_risk_multipliers.get(
            validation_request.interaction_type, 1.0
        )

        # Factor in user context
        if validation_request.user_context:
            user_risk_multiplier = self._calculate_user_risk_multiplier(
                validation_request.user_context
            )
            risk_score *= user_risk_multiplier

        # Ensure risk score doesn't exceed 1.0
        risk_score = min(1.0, risk_score)

        return {
            "risk_score": risk_score,
            "prompt_analysis": prompt_analysis,
            "requires_monitoring": risk_score > 0.3,
            "requires_response_filtering": self._requires_response_filtering(
                prompt_analysis, risk_score
            ),
            "user_warning_required": risk_score > 0.5,
        }

    def _calculate_user_risk_multiplier(self, user_context: Dict[str, Any]) -> float:
        """Calculate risk multiplier based on user context"""

        multiplier = 1.0

        # Reduce risk for authenticated users
        if user_context.get("user_id") != "anonymous":
            multiplier *= 0.9

        # Adjust based on user roles
        roles = user_context.get("roles", [])
        if "admin" in roles or "security_analyst" in roles:
            multiplier *= 0.7
        elif "developer" in roles:
            multiplier *= 0.8
        elif "analyst" in roles:
            multiplier *= 0.9

        # Increase risk for users with recent violations
        if user_context.get("recent_violations", 0) > 0:
            multiplier *= 1.3

        return multiplier

    def _requires_response_filtering(
        self, prompt_analysis: PromptAnalysisResult, risk_score: float
    ) -> bool:
        """Determine if response filtering is required"""

        if not self.response_filtering_enabled:
            return False

        # Filter responses for high-risk prompts
        if risk_score >= 0.5:
            return True

        # Filter based on interaction type
        high_risk_interactions = {
            LLMInteractionType.CODE_GENERATION,
            LLMInteractionType.TERMINAL_ASSISTANCE,
            LLMInteractionType.SECURITY_QUERY,
            LLMInteractionType.SYSTEM_QUERY,
        }

        if prompt_analysis.interaction_type in high_risk_interactions:
            return True

        return False

    def _determine_validation_approach(
        self, prompt_analysis: PromptAnalysisResult, risk_assessment: Dict[str, Any]
    ) -> str:
        """Determine the appropriate validation approach"""

        risk_score = risk_assessment["risk_score"]

        # Block malicious prompts
        if prompt_analysis.risk_level == PromptRiskLevel.MALICIOUS:
            return "block_immediately"

        # Require conversational approval for critical prompts
        if prompt_analysis.risk_level == PromptRiskLevel.CRITICAL or risk_score >= 0.7:
            return "require_conversational_approval"

        # Filter high-risk prompts
        if prompt_analysis.risk_level == PromptRiskLevel.HIGH or risk_score >= 0.5:
            return "filter_and_monitor"

        # Monitor medium-risk prompts
        if prompt_analysis.risk_level == PromptRiskLevel.MEDIUM or risk_score >= 0.3:
            return "approve_with_monitoring"

        # Auto-approve safe prompts
        return "auto_approve"

    async def _perform_llm_validation(
        self,
        validation_request: LLMValidationRequest,
        prompt_analysis: PromptAnalysisResult,
        risk_assessment: Dict[str, Any],
        validation_approach: str,
    ) -> LLMValidationDecision:
        """Perform the appropriate validation based on approach"""

        if validation_approach == "block_immediately":
            self.metrics["blocked_interactions"] += 1
            return LLMValidationDecision(
                decision=LLMValidationResult.BLOCKED,
                confidence=0.95,
                reasoning=f"Prompt blocked due to {prompt_analysis.risk_level.value} risk level",
                restrictions=[
                    "LLM interaction prohibited due to security classification"
                ],
            )

        elif validation_approach == "auto_approve":
            self.metrics["approved_interactions"] += 1
            return LLMValidationDecision(
                decision=LLMValidationResult.APPROVED,
                confidence=0.8,
                reasoning="Safe prompt - auto-approved",
                monitoring_required=risk_assessment["requires_monitoring"],
                response_filtering_required=risk_assessment[
                    "requires_response_filtering"
                ],
            )

        elif validation_approach == "filter_and_monitor":
            self.metrics["filtered_interactions"] += 1
            filtered_prompt = await self._filter_prompt(
                validation_request.prompt, prompt_analysis
            )

            return LLMValidationDecision(
                decision=LLMValidationResult.FILTERED,
                confidence=0.8,
                reasoning="Prompt filtered for safety - monitoring enabled",
                filtered_prompt=filtered_prompt,
                monitoring_required=True,
                response_filtering_required=True,
                user_warnings=["Prompt has been filtered for safety"],
            )

        elif validation_approach == "approve_with_monitoring":
            self.metrics["approved_interactions"] += 1
            return LLMValidationDecision(
                decision=LLMValidationResult.CONDITIONAL_APPROVAL,
                confidence=0.7,
                reasoning="Approved with enhanced monitoring",
                monitoring_required=True,
                response_filtering_required=risk_assessment[
                    "requires_response_filtering"
                ],
                conditions=["Enhanced monitoring enabled"],
                user_warnings=(
                    ["This interaction is being monitored for safety"]
                    if risk_assessment["user_warning_required"]
                    else []
                ),
            )

        else:
            # Require conversational approval
            return await self._request_llm_interaction_approval(
                validation_request, prompt_analysis, risk_assessment
            )

    async def _filter_prompt(
        self, prompt: str, prompt_analysis: PromptAnalysisResult
    ) -> str:
        """Filter dangerous content from prompt"""

        filtered_prompt = prompt

        # Remove injection attempts
        for injection_type in prompt_analysis.injection_attempts:
            # For now, just add a warning comment
            # In a real implementation, you'd have more sophisticated filtering
            filtered_prompt += (
                f"\n[Note: Potential {injection_type} detected and filtered]"
            )

        # Remove sensitive data references
        for sensitive_type in prompt_analysis.sensitive_data:
            filtered_prompt = re.sub(
                rf'{sensitive_type}\s*[:=]\s*["\']?[^\s"\']+',
                f"[{sensitive_type} FILTERED]",
                filtered_prompt,
                flags=re.IGNORECASE,
            )

        return filtered_prompt

    async def _request_llm_interaction_approval(
        self,
        validation_request: LLMValidationRequest,
        prompt_analysis: PromptAnalysisResult,
        risk_assessment: Dict[str, Any],
    ) -> LLMValidationDecision:
        """Request conversational approval for LLM interaction"""

        try:
            # Create approval request
            approval_request = {
                "request_id": validation_request.request_id,
                "interaction_type": validation_request.interaction_type.value,
                "prompt_preview": (
                    validation_request.prompt[:200] + "..."
                    if len(validation_request.prompt) > 200
                    else validation_request.prompt
                ),
                "prompt_hash": prompt_analysis.prompt_hash,
                "risk_level": prompt_analysis.risk_level.value,
                "risk_score": risk_assessment["risk_score"],
                "threat_patterns": prompt_analysis.threat_patterns,
                "injection_attempts": prompt_analysis.injection_attempts,
                "malicious_intent": prompt_analysis.malicious_intent,
                "jailbreak_attempt": prompt_analysis.jailbreak_attempt,
                "data_extraction_attempt": prompt_analysis.data_extraction_attempt,
                "sensitive_data": prompt_analysis.sensitive_data,
                "business_justification": validation_request.business_justification,
                "user_context": validation_request.user_context or {},
                "model_name": validation_request.model_name,
                "requires_response_filtering": risk_assessment[
                    "requires_response_filtering"
                ],
            }

            # Request approval through PARLANT service
            approval_result = (
                await self.parlant_service.request_llm_interaction_approval(
                    approval_request
                )
            )

            # Process approval result
            if approval_result.get("approved", False):
                decision = LLMValidationResult.APPROVED
                if (
                    approval_result.get("conditions")
                    or risk_assessment["requires_response_filtering"]
                ):
                    decision = LLMValidationResult.CONDITIONAL_APPROVAL

                self.metrics["approved_interactions"] += 1

                return LLMValidationDecision(
                    decision=decision,
                    confidence=approval_result.get("confidence", 0.8),
                    reasoning=approval_result.get(
                        "reasoning", "Approved through conversational validation"
                    ),
                    conditions=approval_result.get("conditions", []),
                    restrictions=approval_result.get("restrictions", []),
                    monitoring_required=True,
                    response_filtering_required=approval_result.get(
                        "response_filtering_required",
                        risk_assessment["requires_response_filtering"],
                    ),
                    user_warnings=approval_result.get("user_warnings", []),
                    approval_session_id=approval_result.get("session_id"),
                    approver_ids=approval_result.get("approver_ids", []),
                )
            else:
                self.metrics["blocked_interactions"] += 1

                return LLMValidationDecision(
                    decision=LLMValidationResult.BLOCKED,
                    confidence=approval_result.get("confidence", 0.9),
                    reasoning=approval_result.get(
                        "reason", "Rejected through conversational validation"
                    ),
                    approval_session_id=approval_result.get("session_id"),
                )

        except Exception as e:
            self.logger.error(f"LLM interaction approval error: {str(e)}")

            # Default to appropriate action based on risk level
            if risk_assessment["risk_score"] > 0.6:
                self.metrics["blocked_interactions"] += 1
                return LLMValidationDecision(
                    decision=LLMValidationResult.BLOCKED,
                    confidence=0.9,
                    reasoning=f"Approval system unavailable for high-risk interaction: {str(e)}",
                )
            else:
                # Allow low-risk interactions with monitoring
                self.metrics["approved_interactions"] += 1

                return LLMValidationDecision(
                    decision=LLMValidationResult.CONDITIONAL_APPROVAL,
                    confidence=0.6,
                    reasoning="Approval system unavailable - conditional approval with monitoring",
                    conditions=[
                        "Enhanced monitoring enabled",
                        "Response filtering required",
                    ],
                    monitoring_required=True,
                    response_filtering_required=True,
                    user_warnings=[
                        "This interaction is being monitored due to system limitations"
                    ],
                )

    async def validate_llm_response(
        self,
        response: str,
        original_request: LLMValidationRequest,
        original_decision: LLMValidationDecision,
    ) -> ResponseAnalysisResult:
        """Validate LLM response content for safety"""

        analysis_start = time.time()

        # Initialize analysis result
        analysis_result = ResponseAnalysisResult(
            response=response,
            response_hash=hashlib.sha256(response.encode()).hexdigest()[:16],
        )

        try:
            # Basic content analysis
            analysis_result.contains_code = self._contains_code(response)
            analysis_result.contains_sensitive_data = (
                self._contains_sensitive_data_response(response)
            )
            analysis_result.contains_instructions = self._contains_instructions(
                response
            )

            # Apply response filters
            safety_violations = []
            content_filters_triggered = []

            for filter_name, filter_info in self.response_filters.items():
                for pattern in filter_info["patterns"]:
                    if re.search(pattern, response, re.IGNORECASE):
                        content_filters_triggered.append(filter_name)
                        if filter_info["action"] in ["filter_out", "flag_for_review"]:
                            safety_violations.append(
                                f"{filter_name}: {filter_info['description']}"
                            )

            analysis_result.safety_violations = safety_violations
            analysis_result.content_filters_triggered = content_filters_triggered

            # Determine if user warning is required
            analysis_result.requires_user_warning = (
                len(safety_violations) > 0
                or analysis_result.contains_code
                or original_decision.response_filtering_required
            )

            # Calculate risk score
            risk_factors = [
                analysis_result.contains_code,
                analysis_result.contains_sensitive_data,
                len(safety_violations) > 0,
                len(content_filters_triggered) > 2,
            ]
            analysis_result.risk_score = sum(risk_factors) * 0.25

            # Calculate confidence
            analysis_result.confidence = min(
                1.0, len(content_filters_triggered) * 0.2 + 0.6
            )
            analysis_result.analysis_time_ms = (time.time() - analysis_start) * 1000

            # Update metrics
            if content_filters_triggered:
                self.metrics["response_filters_triggered"] += 1

            return analysis_result

        except Exception as e:
            self.logger.error(f"Response analysis error: {str(e)}")

            # Return safe default
            return ResponseAnalysisResult(
                response=response,
                response_hash=hashlib.sha256(response.encode()).hexdigest()[:16],
                requires_user_warning=True,
                risk_score=0.5,
                confidence=0.3,
                analysis_time_ms=(time.time() - analysis_start) * 1000,
            )

    def _contains_code(self, response: str) -> bool:
        """Check if response contains code"""

        code_indicators = [
            r"```\w*\n",  # Code blocks
            r"`[^`]+`",  # Inline code
            r"def\s+\w+\s*\(",  # Python functions
            r"function\s+\w+\s*\(",  # JavaScript functions
            r"import\s+\w+",  # Import statements
            r"#include\s*<",  # C/C++ includes
        ]

        return any(re.search(pattern, response) for pattern in code_indicators)

    def _contains_sensitive_data_response(self, response: str) -> bool:
        """Check if response contains sensitive data"""

        sensitive_patterns = [
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
            r"\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b",  # Credit card
            r'password\s*[:=]\s*["\']?\w+',  # Passwords
            r'api[_-]?key\s*[:=]\s*["\']?\w+',  # API keys
            r"/etc/passwd",  # System files
            r"private.*key",  # Private keys
        ]

        return any(
            re.search(pattern, response, re.IGNORECASE)
            for pattern in sensitive_patterns
        )

    def _contains_instructions(self, response: str) -> bool:
        """Check if response contains potentially dangerous instructions"""

        instruction_patterns = [
            r"run\s+this\s+command",
            r"execute\s+the\s+following",
            r"type\s+this\s+in\s+terminal",
            r"copy\s+and\s+paste",
            r"sudo\s+",
            r"rm\s+-rf",
        ]

        return any(
            re.search(pattern, response, re.IGNORECASE)
            for pattern in instruction_patterns
        )

    async def _update_metrics(
        self,
        validation_decision: LLMValidationDecision,
        validation_time_ms: float,
        prompt_analysis: PromptAnalysisResult,
    ):
        """Update performance and security metrics"""

        # Update timing metrics
        current_avg = self.metrics["average_validation_time_ms"]
        total_validations = self.metrics["total_validations"]

        self.metrics["average_validation_time_ms"] = (
            current_avg * (total_validations - 1) + validation_time_ms
        ) / total_validations

        self.metrics["max_validation_time_ms"] = max(
            self.metrics["max_validation_time_ms"], validation_time_ms
        )

        # Update security metrics
        if prompt_analysis.injection_attempts:
            self.metrics["injection_attempts_detected"] += 1

        if prompt_analysis.jailbreak_attempt:
            self.metrics["jailbreak_attempts_detected"] += 1

        if prompt_analysis.data_extraction_attempt:
            self.metrics["data_extraction_attempts"] += 1

        if prompt_analysis.malicious_intent:
            self.metrics["malicious_prompts_detected"] += 1

        # Log performance warnings
        if validation_time_ms > self.performance_target_ms:
            self.logger.warning(
                f"LLM validation time exceeded target: {validation_time_ms:.1f}ms > {self.performance_target_ms}ms"
            )

    async def _create_audit_trail(
        self,
        validation_request: LLMValidationRequest,
        validation_decision: LLMValidationDecision,
    ):
        """Create comprehensive audit trail for compliance"""

        audit_entry = {
            "event_type": "llm_interaction_validation",
            "request_id": validation_request.request_id,
            "user_id": (
                validation_request.user_context.get("user_id", "unknown")
                if validation_request.user_context
                else "unknown"
            ),
            "interaction_type": validation_request.interaction_type.value,
            "prompt_hash": hashlib.sha256(
                validation_request.prompt.encode()
            ).hexdigest()[:16],
            "prompt_length": len(validation_request.prompt),
            "model_name": validation_request.model_name,
            "validation_decision": validation_decision.decision.value,
            "confidence": validation_decision.confidence,
            "reasoning": validation_decision.reasoning,
            "monitoring_required": validation_decision.monitoring_required,
            "response_filtering_required": validation_decision.response_filtering_required,
            "approval_session_id": validation_decision.approval_session_id,
            "approver_ids": validation_decision.approver_ids,
            "validation_time_ms": validation_decision.validation_time_ms,
            "timestamp": datetime.now().isoformat(),
        }

        # Add to validation decision audit trail
        validation_decision.audit_trail.append(audit_entry)

        # Log for monitoring
        self.logger.info("LLM interaction validation audit", extra=audit_entry)

        # Send to enterprise security orchestrator if available
        if self.security_orchestrator:
            try:
                await self.security_orchestrator.log_security_event(audit_entry)
            except Exception as e:
                self.logger.error(f"Failed to log to security orchestrator: {str(e)}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current validation metrics"""

        return {
            **self.metrics,
            "validation_enabled": self.validation_enabled,
            "performance_target_ms": self.performance_target_ms,
            "response_filtering_enabled": self.response_filtering_enabled,
            "approval_rate": (
                self.metrics["approved_interactions"]
                / max(1, self.metrics["total_validations"])
            ),
            "threat_detection_rate": (
                (
                    self.metrics["injection_attempts_detected"]
                    + self.metrics["jailbreak_attempts_detected"]
                    + self.metrics["malicious_prompts_detected"]
                )
                / max(1, self.metrics["total_validations"])
            ),
            "filtering_rate": (
                self.metrics["filtered_interactions"]
                / max(1, self.metrics["total_validations"])
            ),
            "performance_compliance": (
                self.metrics["average_validation_time_ms"] <= self.performance_target_ms
            ),
        }


# Factory function for easy integration
async def create_parlant_llm_validator(
    parlant_service: Optional[ParlantIntegrationService] = None, **kwargs
) -> ParlantLLMValidator:
    """
    Factory function to create PARLANT LLM Validator

    Args:
        parlant_service: Optional PARLANT service instance
        **kwargs: Additional configuration options

    Returns:
        Configured ParlantLLMValidator instance
    """

    if parlant_service is None:
        parlant_service = ParlantIntegrationService()

    return ParlantLLMValidator(parlant_service=parlant_service, **kwargs)
