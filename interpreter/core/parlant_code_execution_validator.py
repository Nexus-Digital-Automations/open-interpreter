"""
PARLANT Code Execution Security Validation for Open-Interpreter

Provides comprehensive conversational validation for all code execution operations
with advanced risk assessment, real-time approval workflows, and enterprise-grade
security compliance. Integrates seamlessly with existing Open-Interpreter security
frameworks while adding conversational AI validation layer.

Features:
- Real-time code analysis with threat detection
- Conversational approval workflows for high-risk operations
- Integration with existing ultra-secure code execution framework
- Sub-500ms validation for interactive operations
- Comprehensive audit trails and compliance documentation

@author PARLANT Integration Specialist
@since 1.0.0
@security_level MAXIMUM
"""

import ast
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
from .ultra_secure_code_execution import (
    ApprovalLevel,
    ExecutionEnvironment,
    ExecutionRequest,
    RiskAssessment,
    RiskLevel,
    UltraSecureCodeExecutionValidator,
)


class CodeThreatLevel(Enum):
    """Code threat classification levels"""

    SAFE = "safe"  # No security concerns
    SUSPICIOUS = "suspicious"  # Potentially dangerous patterns
    DANGEROUS = "dangerous"  # High-risk operations
    MALICIOUS = "malicious"  # Definite security threats
    CATASTROPHIC = "catastrophic"  # System-destroying potential


class ExecutionValidationResult(Enum):
    """Code execution validation results"""

    APPROVED = "approved"
    CONDITIONAL_APPROVAL = "conditional_approval"
    REQUIRES_CONFIRMATION = "requires_confirmation"
    REQUIRES_DUAL_APPROVAL = "requires_dual_approval"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


@dataclass
class CodeAnalysisResult:
    """Comprehensive code analysis result"""

    threat_level: CodeThreatLevel
    risk_score: float
    threat_patterns: List[str] = field(default_factory=list)
    suspicious_functions: List[str] = field(default_factory=list)
    dangerous_imports: List[str] = field(default_factory=list)
    file_operations: List[str] = field(default_factory=list)
    network_operations: List[str] = field(default_factory=list)
    system_commands: List[str] = field(default_factory=list)
    privilege_escalation: List[str] = field(default_factory=list)
    data_exfiltration: List[str] = field(default_factory=list)
    obfuscation_detected: bool = False
    complexity_score: float = 0.0
    confidence: float = 0.0
    analysis_time_ms: float = 0.0


@dataclass
class ConversationalApprovalRequest:
    """Request for conversational approval of code execution"""

    request_id: str
    code_preview: str
    code_hash: str
    threat_level: CodeThreatLevel
    risk_factors: List[str]
    business_justification: str
    user_context: Dict[str, Any]
    execution_environment: str
    estimated_impact: str
    reversible: bool
    approval_timeout_seconds: int = 300
    requires_dual_approval: bool = False


@dataclass
class ValidationDecision:
    """Final validation decision with comprehensive metadata"""

    decision: ExecutionValidationResult
    confidence: float
    reasoning: str
    conditions: List[str] = field(default_factory=list)
    restrictions: List[str] = field(default_factory=list)
    monitoring_required: bool = False
    approval_session_id: Optional[str] = None
    approver_ids: List[str] = field(default_factory=list)
    validation_time_ms: float = 0.0
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


class ParlantCodeExecutionValidator:
    """
    PARLANT Code Execution Security Validator

    Provides comprehensive conversational validation for all code execution
    operations in Open-Interpreter with real-time threat analysis, approval
    workflows, and enterprise compliance.

    Integration with existing security frameworks:
    - UltraSecureCodeExecutionValidator for technical validation
    - ParlantIntegrationService for conversational workflows
    - EnterpriseSecurityOrchestrator for compliance and auditing
    """

    def __init__(
        self,
        parlant_service: Optional[ParlantIntegrationService] = None,
        ultra_secure_validator: Optional[UltraSecureCodeExecutionValidator] = None,
        security_orchestrator: Optional[EnterpriseSecurityOrchestrator] = None,
        **kwargs,
    ):
        """Initialize PARLANT Code Execution Validator"""

        # Initialize services
        self.parlant_service = parlant_service or ParlantIntegrationService()
        self.ultra_secure_validator = ultra_secure_validator
        self.security_orchestrator = security_orchestrator

        # Configuration
        self.validation_enabled = kwargs.get("validation_enabled", True)
        self.performance_target_ms = kwargs.get("performance_target_ms", 500)
        self.risk_threshold_medium = kwargs.get("risk_threshold_medium", 0.4)
        self.risk_threshold_high = kwargs.get("risk_threshold_high", 0.7)
        self.risk_threshold_critical = kwargs.get("risk_threshold_critical", 0.9)

        # Threat detection patterns
        self.threat_patterns = self._initialize_threat_patterns()

        # Language-specific analyzers
        self.language_analyzers = {
            "python": self._analyze_python_code,
            "javascript": self._analyze_javascript_code,
            "shell": self._analyze_shell_code,
            "bash": self._analyze_shell_code,
            "powershell": self._analyze_powershell_code,
        }

        # Performance metrics
        self.metrics = {
            "total_validations": 0,
            "approved_executions": 0,
            "blocked_executions": 0,
            "conversational_approvals": 0,
            "threat_detections": 0,
            "average_validation_time_ms": 0.0,
            "max_validation_time_ms": 0.0,
        }

        # Logging
        self.logger = logging.getLogger("ParlantCodeExecutionValidator")
        self.logger.info(
            "PARLANT Code Execution Validator initialized",
            extra={
                "validation_enabled": self.validation_enabled,
                "performance_target_ms": self.performance_target_ms,
                "threat_patterns_loaded": len(self.threat_patterns),
                "supported_languages": list(self.language_analyzers.keys()),
            },
        )

    def _initialize_threat_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize comprehensive threat detection patterns"""

        return {
            "code_injection": {
                "patterns": [
                    r"exec\s*\(",
                    r"eval\s*\(",
                    r"__import__\s*\(",
                    r"compile\s*\(",
                    r"getattr\s*\(\s*\w+\s*,\s*input\s*\(\s*\)\s*\)",
                ],
                "risk_score": 0.9,
                "description": "Dynamic code execution patterns",
            },
            "system_commands": {
                "patterns": [
                    r"subprocess\.",
                    r"os\.system",
                    r"os\.popen",
                    r"commands\.",
                    r"shell=True",
                ],
                "risk_score": 0.8,
                "description": "System command execution",
            },
            "file_manipulation": {
                "patterns": [
                    r'open\s*\([^)]*["\']w["\']',
                    r'open\s*\([^)]*["\']a["\']',
                    r"\.write\s*\(",
                    r"\.remove\s*\(",
                    r"\.unlink\s*\(",
                    r"shutil\.rmtree",
                    r"os\.remove",
                    r"os\.rmdir",
                ],
                "risk_score": 0.6,
                "description": "File system modification operations",
            },
            "network_operations": {
                "patterns": [
                    r"requests\.(get|post|put|delete)",
                    r"urllib\.request",
                    r"socket\.",
                    r"http\.client",
                    r"ftplib\.",
                    r"smtplib\.",
                ],
                "risk_score": 0.5,
                "description": "Network communication operations",
            },
            "privilege_escalation": {
                "patterns": [
                    r"sudo\s+",
                    r"su\s+",
                    r"chmod\s+777",
                    r"chown\s+",
                    r"setuid",
                    r"setgid",
                ],
                "risk_score": 0.95,
                "description": "Privilege escalation attempts",
            },
            "data_exfiltration": {
                "patterns": [
                    r"base64\.b64encode",
                    r"urllib\.parse\.quote",
                    r"json\.dumps.*requests\.",
                    r"pickle\.dumps",
                    r"gzip\.compress",
                ],
                "risk_score": 0.7,
                "description": "Data encoding/transmission patterns",
            },
            "obfuscation": {
                "patterns": [
                    r'[\'"]\s*\+\s*[\'"]',  # String concatenation
                    r"chr\s*\(\s*\d+\s*\)",  # Character encoding
                    r"\\x[0-9a-fA-F]{2}",  # Hex encoding
                    r"\\[0-7]{3}",  # Octal encoding
                    r"rot13|base64",  # Common encodings
                ],
                "risk_score": 0.8,
                "description": "Code obfuscation techniques",
            },
            "crypto_operations": {
                "patterns": [
                    r"cryptography\.",
                    r"Crypto\.",
                    r"hashlib\.",
                    r"hmac\.",
                    r"secrets\.",
                ],
                "risk_score": 0.3,
                "description": "Cryptographic operations",
            },
            "dangerous_modules": {
                "patterns": [
                    r"import\s+ctypes",
                    r"import\s+marshal",
                    r"import\s+code",
                    r"import\s+pty",
                    r"import\s+telnetlib",
                ],
                "risk_score": 0.8,
                "description": "Import of dangerous modules",
            },
        }

    async def validate_code_execution(
        self,
        execution_request: ExecutionRequest,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> ValidationDecision:
        """
        Main validation entry point for code execution requests

        Performs comprehensive analysis and conversational validation
        for code execution with performance optimization and audit trails.
        """

        validation_start = time.time()
        self.metrics["total_validations"] += 1

        try:
            # Step 1: Perform technical code analysis
            analysis_result = await self._analyze_code_security(
                execution_request.code, execution_request.language
            )

            # Step 2: Create comprehensive risk assessment
            risk_assessment = await self._create_risk_assessment(
                execution_request, analysis_result, user_context
            )

            # Step 3: Determine validation approach
            validation_approach = self._determine_validation_approach(
                analysis_result, risk_assessment
            )

            # Step 4: Perform appropriate validation
            validation_decision = await self._perform_validation(
                execution_request,
                analysis_result,
                risk_assessment,
                validation_approach,
                user_context,
            )

            # Step 5: Update metrics and audit trail
            validation_time_ms = (time.time() - validation_start) * 1000
            await self._update_metrics(validation_decision, validation_time_ms)
            await self._create_audit_trail(execution_request, validation_decision)

            # Add timing information
            validation_decision.validation_time_ms = validation_time_ms

            return validation_decision

        except Exception as e:
            self.logger.error(
                f"Code validation error: {str(e)}",
                extra={
                    "request_id": execution_request.request_id,
                    "language": execution_request.language,
                    "error_type": type(e).__name__,
                },
            )

            # Default to rejection on validation failure
            return ValidationDecision(
                decision=ExecutionValidationResult.BLOCKED,
                confidence=0.9,
                reasoning=f"Validation system error: {str(e)}",
                validation_time_ms=(time.time() - validation_start) * 1000,
            )

    async def _analyze_code_security(
        self, code: str, language: str
    ) -> CodeAnalysisResult:
        """
        Comprehensive security analysis of code

        Performs static analysis, pattern matching, and threat detection
        with language-specific analysis capabilities.
        """

        analysis_start = time.time()

        # Initialize analysis result
        analysis_result = CodeAnalysisResult(
            threat_level=CodeThreatLevel.SAFE, risk_score=0.0
        )

        try:
            # General threat pattern analysis
            threat_patterns_found = []
            risk_scores = []

            for category, pattern_info in self.threat_patterns.items():
                for pattern in pattern_info["patterns"]:
                    if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                        threat_patterns_found.append(f"{category}: {pattern}")
                        risk_scores.append(pattern_info["risk_score"])

            # Language-specific analysis
            if language.lower() in self.language_analyzers:
                lang_analysis = await self.language_analyzers[language.lower()](code)
                analysis_result.suspicious_functions.extend(
                    lang_analysis.get("suspicious_functions", [])
                )
                analysis_result.dangerous_imports.extend(
                    lang_analysis.get("dangerous_imports", [])
                )
                analysis_result.system_commands.extend(
                    lang_analysis.get("system_commands", [])
                )

            # Calculate overall risk score
            if risk_scores:
                analysis_result.risk_score = min(
                    1.0, max(risk_scores) + (len(risk_scores) * 0.1)
                )
            else:
                analysis_result.risk_score = 0.1  # Base risk for any code execution

            # Determine threat level
            if analysis_result.risk_score >= 0.9:
                analysis_result.threat_level = CodeThreatLevel.CATASTROPHIC
            elif analysis_result.risk_score >= 0.7:
                analysis_result.threat_level = CodeThreatLevel.MALICIOUS
            elif analysis_result.risk_score >= 0.5:
                analysis_result.threat_level = CodeThreatLevel.DANGEROUS
            elif analysis_result.risk_score >= 0.3:
                analysis_result.threat_level = CodeThreatLevel.SUSPICIOUS
            else:
                analysis_result.threat_level = CodeThreatLevel.SAFE

            # Set additional properties
            analysis_result.threat_patterns = threat_patterns_found
            analysis_result.obfuscation_detected = self._detect_obfuscation(code)
            analysis_result.complexity_score = self._calculate_complexity_score(code)
            analysis_result.confidence = min(
                1.0, len(threat_patterns_found) * 0.2 + 0.5
            )
            analysis_result.analysis_time_ms = (time.time() - analysis_start) * 1000

            return analysis_result

        except Exception as e:
            self.logger.error(f"Code analysis error: {str(e)}")

            # Return safe default on analysis failure
            return CodeAnalysisResult(
                threat_level=CodeThreatLevel.SUSPICIOUS,
                risk_score=0.5,
                threat_patterns=[f"Analysis error: {str(e)}"],
                confidence=0.3,
                analysis_time_ms=(time.time() - analysis_start) * 1000,
            )

    async def _analyze_python_code(self, code: str) -> Dict[str, Any]:
        """Python-specific security analysis using AST parsing"""

        try:
            # Parse code into AST
            tree = ast.parse(code)

            suspicious_functions = []
            dangerous_imports = []
            system_commands = []

            # Walk the AST
            for node in ast.walk(tree):
                # Check for dangerous function calls
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        if func_name in ["exec", "eval", "compile", "__import__"]:
                            suspicious_functions.append(func_name)

                # Check for dangerous imports
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ["os", "subprocess", "ctypes", "marshal"]:
                            dangerous_imports.append(alias.name)

                elif isinstance(node, ast.ImportFrom):
                    if node.module in ["os", "subprocess", "ctypes"]:
                        dangerous_imports.append(node.module)

                # Check for attribute access to system functions
                elif isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name):
                        if node.value.id == "os" and node.attr in [
                            "system",
                            "popen",
                            "execv",
                        ]:
                            system_commands.append(f"os.{node.attr}")

            return {
                "suspicious_functions": suspicious_functions,
                "dangerous_imports": dangerous_imports,
                "system_commands": system_commands,
            }

        except SyntaxError:
            # Invalid Python syntax
            return {
                "suspicious_functions": ["syntax_error"],
                "dangerous_imports": [],
                "system_commands": [],
            }

    async def _analyze_javascript_code(self, code: str) -> Dict[str, Any]:
        """JavaScript-specific security analysis"""

        suspicious_functions = []
        system_commands = []

        # Check for dangerous JavaScript patterns
        dangerous_patterns = {
            r"eval\s*\(": "eval",
            r"Function\s*\(": "Function_constructor",
            r'require\s*\(\s*["\']child_process["\']': "child_process",
            r'require\s*\(\s*["\']fs["\']': "file_system",
            r"process\.exit": "process_exit",
            r"process\.env": "environment_access",
        }

        for pattern, func_name in dangerous_patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                suspicious_functions.append(func_name)

        return {
            "suspicious_functions": suspicious_functions,
            "dangerous_imports": [],
            "system_commands": system_commands,
        }

    async def _analyze_shell_code(self, code: str) -> Dict[str, Any]:
        """Shell/Bash-specific security analysis"""

        system_commands = []
        dangerous_imports = []

        # Check for dangerous shell commands
        dangerous_commands = [
            "rm",
            "rmdir",
            "dd",
            "mkfs",
            "fdisk",
            "chmod",
            "chown",
            "sudo",
            "su",
            "crontab",
            "systemctl",
            "service",
            "iptables",
            "ufw",
            "wget",
            "curl",
        ]

        for cmd in dangerous_commands:
            if re.search(rf"\b{cmd}\b", code, re.IGNORECASE):
                system_commands.append(cmd)

        return {
            "suspicious_functions": [],
            "dangerous_imports": dangerous_imports,
            "system_commands": system_commands,
        }

    async def _analyze_powershell_code(self, code: str) -> Dict[str, Any]:
        """PowerShell-specific security analysis"""

        suspicious_functions = []
        system_commands = []

        # Check for dangerous PowerShell patterns
        dangerous_patterns = {
            r"Invoke-Expression": "invoke_expression",
            r"IEX\s": "iex_alias",
            r"Start-Process": "start_process",
            r"New-Object\s+System\.Net": "network_object",
            r"DownloadString": "download_string",
            r"EncodedCommand": "encoded_command",
        }

        for pattern, func_name in dangerous_patterns.items():
            if re.search(pattern, code, re.IGNORECASE):
                suspicious_functions.append(func_name)

        return {
            "suspicious_functions": suspicious_functions,
            "dangerous_imports": [],
            "system_commands": system_commands,
        }

    def _detect_obfuscation(self, code: str) -> bool:
        """Detect code obfuscation techniques"""

        obfuscation_indicators = [
            len(re.findall(r'[\'"]\s*\+\s*[\'"]', code))
            > 5,  # Excessive string concatenation
            len(re.findall(r"\\x[0-9a-fA-F]{2}", code)) > 3,  # Hex encoding
            len(re.findall(r"chr\s*\(\s*\d+\s*\)", code)) > 3,  # Character encoding
            "base64" in code.lower() and "decode" in code.lower(),
            len([c for c in code if not c.isprintable()])
            > 10,  # Non-printable characters
        ]

        return sum(obfuscation_indicators) >= 2

    def _calculate_complexity_score(self, code: str) -> float:
        """Calculate code complexity score"""

        # Simple complexity metrics
        lines = len(code.split("\n"))
        functions = len(re.findall(r"def\s+\w+|function\s+\w+", code, re.IGNORECASE))
        loops = len(re.findall(r"for\s+|while\s+", code, re.IGNORECASE))
        conditionals = len(re.findall(r"if\s+|elif\s+|else\s*:", code, re.IGNORECASE))

        # Normalize to 0-1 scale
        complexity = min(
            1.0, (lines + functions * 5 + loops * 3 + conditionals * 2) / 100.0
        )

        return complexity

    async def _create_risk_assessment(
        self,
        execution_request: ExecutionRequest,
        analysis_result: CodeAnalysisResult,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """Create comprehensive risk assessment for execution request"""

        # Base risk from code analysis
        risk_score = analysis_result.risk_score

        # Factor in execution environment
        env_risk_multipliers = {
            ExecutionEnvironment.NATIVE: 1.2,
            ExecutionEnvironment.RESTRICTED: 1.0,
            ExecutionEnvironment.SANDBOXED: 0.8,
            ExecutionEnvironment.CONTAINER: 0.7,
            ExecutionEnvironment.VIRTUAL_MACHINE: 0.6,
        }

        risk_score *= env_risk_multipliers.get(
            execution_request.execution_environment, 1.0
        )

        # Factor in user context
        if user_context:
            user_risk_multiplier = self._calculate_user_risk_multiplier(user_context)
            risk_score *= user_risk_multiplier

        # Determine risk level
        if risk_score >= self.risk_threshold_critical:
            risk_level = RiskLevel.CRITICAL
            approval_level = ApprovalLevel.DUAL_APPROVAL
        elif risk_score >= self.risk_threshold_high:
            risk_level = RiskLevel.HIGH
            approval_level = ApprovalLevel.SINGLE_APPROVAL
        elif risk_score >= self.risk_threshold_medium:
            risk_level = RiskLevel.MEDIUM
            approval_level = ApprovalLevel.SINGLE_APPROVAL
        else:
            risk_level = RiskLevel.LOW
            approval_level = ApprovalLevel.AUTOMATIC

        # Compile risk factors
        risk_factors = []
        risk_factors.extend(analysis_result.threat_patterns)
        if analysis_result.suspicious_functions:
            risk_factors.append(
                f"Suspicious functions: {', '.join(analysis_result.suspicious_functions)}"
            )
        if analysis_result.dangerous_imports:
            risk_factors.append(
                f"Dangerous imports: {', '.join(analysis_result.dangerous_imports)}"
            )
        if analysis_result.obfuscation_detected:
            risk_factors.append("Code obfuscation detected")

        return RiskAssessment(
            risk_level=risk_level,
            security_level=execution_request.security_context.security_clearance,
            approval_level=approval_level,
            risk_factors=risk_factors,
            threat_indicators=analysis_result.threat_patterns,
            compliance_violations=[],  # TODO: Implement compliance checking
            mitigation_required=[],
            estimated_damage=(
                "high" if risk_score > 0.7 else "medium" if risk_score > 0.4 else "low"
            ),
            confidence_score=analysis_result.confidence,
            assessment_timestamp=datetime.now(),
        )

    def _calculate_user_risk_multiplier(self, user_context: Dict[str, Any]) -> float:
        """Calculate risk multiplier based on user context"""

        multiplier = 1.0

        # Reduce risk for trusted users
        if user_context.get("user_id") != "anonymous":
            multiplier *= 0.9

        # Adjust based on user roles
        roles = user_context.get("roles", [])
        if "admin" in roles:
            multiplier *= 0.7
        elif "developer" in roles:
            multiplier *= 0.8
        elif "analyst" in roles:
            multiplier *= 0.9

        # Increase risk for suspicious user patterns
        if user_context.get("recent_violations", 0) > 0:
            multiplier *= 1.3

        return multiplier

    def _determine_validation_approach(
        self, analysis_result: CodeAnalysisResult, risk_assessment: RiskAssessment
    ) -> str:
        """Determine the appropriate validation approach"""

        if analysis_result.threat_level == CodeThreatLevel.CATASTROPHIC:
            return "block_immediately"
        elif analysis_result.threat_level == CodeThreatLevel.MALICIOUS:
            return "require_dual_approval"
        elif analysis_result.threat_level == CodeThreatLevel.DANGEROUS:
            return "require_conversational_approval"
        elif analysis_result.threat_level == CodeThreatLevel.SUSPICIOUS:
            return "require_confirmation"
        else:
            return "auto_approve"

    async def _perform_validation(
        self,
        execution_request: ExecutionRequest,
        analysis_result: CodeAnalysisResult,
        risk_assessment: RiskAssessment,
        validation_approach: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> ValidationDecision:
        """Perform the appropriate validation based on approach"""

        if validation_approach == "block_immediately":
            self.metrics["blocked_executions"] += 1
            return ValidationDecision(
                decision=ExecutionValidationResult.BLOCKED,
                confidence=0.95,
                reasoning=f"Code blocked due to {analysis_result.threat_level.value} threat level",
                restrictions=["Code execution prohibited"],
            )

        elif validation_approach == "auto_approve":
            self.metrics["approved_executions"] += 1
            return ValidationDecision(
                decision=ExecutionValidationResult.APPROVED,
                confidence=0.8,
                reasoning="Low risk code - auto-approved",
                monitoring_required=True,
            )

        else:
            # Require conversational approval
            return await self._request_conversational_approval(
                execution_request,
                analysis_result,
                risk_assessment,
                validation_approach,
                user_context,
            )

    async def _request_conversational_approval(
        self,
        execution_request: ExecutionRequest,
        analysis_result: CodeAnalysisResult,
        risk_assessment: RiskAssessment,
        validation_approach: str,
        user_context: Optional[Dict[str, Any]] = None,
    ) -> ValidationDecision:
        """Request conversational approval through PARLANT service"""

        try:
            # Create approval request
            approval_request = ConversationalApprovalRequest(
                request_id=execution_request.request_id,
                code_preview=(
                    execution_request.code[:500] + "..."
                    if len(execution_request.code) > 500
                    else execution_request.code
                ),
                code_hash=hashlib.sha256(execution_request.code.encode()).hexdigest()[
                    :16
                ],
                threat_level=analysis_result.threat_level,
                risk_factors=risk_assessment.risk_factors,
                business_justification=execution_request.business_justification,
                user_context=user_context or {},
                execution_environment=execution_request.execution_environment.value,
                estimated_impact=risk_assessment.estimated_damage,
                reversible=self._is_operation_reversible(execution_request.code),
                requires_dual_approval=(validation_approach == "require_dual_approval"),
            )

            # Request approval through PARLANT service
            approval_result = (
                await self.parlant_service.request_code_execution_approval(
                    approval_request.__dict__
                )
            )

            self.metrics["conversational_approvals"] += 1

            # Process approval result
            if approval_result.get("approved", False):
                decision = ExecutionValidationResult.APPROVED
                if approval_result.get("conditions"):
                    decision = ExecutionValidationResult.CONDITIONAL_APPROVAL

                self.metrics["approved_executions"] += 1

                return ValidationDecision(
                    decision=decision,
                    confidence=approval_result.get("confidence", 0.8),
                    reasoning=approval_result.get(
                        "reasoning", "Approved through conversational validation"
                    ),
                    conditions=approval_result.get("conditions", []),
                    restrictions=approval_result.get("restrictions", []),
                    monitoring_required=True,
                    approval_session_id=approval_result.get("session_id"),
                    approver_ids=approval_result.get("approver_ids", []),
                )
            else:
                self.metrics["blocked_executions"] += 1

                return ValidationDecision(
                    decision=ExecutionValidationResult.BLOCKED,
                    confidence=approval_result.get("confidence", 0.9),
                    reasoning=approval_result.get(
                        "reason", "Rejected through conversational validation"
                    ),
                    approval_session_id=approval_result.get("session_id"),
                )

        except Exception as e:
            self.logger.error(f"Conversational approval error: {str(e)}")

            # Default to blocking on approval system failure
            self.metrics["blocked_executions"] += 1

            return ValidationDecision(
                decision=ExecutionValidationResult.BLOCKED,
                confidence=0.9,
                reasoning=f"Approval system unavailable: {str(e)}",
            )

    def _is_operation_reversible(self, code: str) -> bool:
        """Determine if the operation is reversible"""

        # Simple heuristics for reversibility
        irreversible_patterns = [
            r"\.remove\s*\(",
            r"\.unlink\s*\(",
            r"shutil\.rmtree",
            r"os\.remove",
            r"rm\s+-rf",
            r"del\s+",
            r"DROP\s+TABLE",
            r"DELETE\s+FROM",
        ]

        for pattern in irreversible_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return False

        return True

    async def _update_metrics(
        self, validation_decision: ValidationDecision, validation_time_ms: float
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

        # Update threat detection metrics
        if validation_decision.decision == ExecutionValidationResult.BLOCKED:
            self.metrics["threat_detections"] += 1

        # Log performance warnings
        if validation_time_ms > self.performance_target_ms:
            self.logger.warning(
                f"Validation time exceeded target: {validation_time_ms:.1f}ms > {self.performance_target_ms}ms"
            )

    async def _create_audit_trail(
        self,
        execution_request: ExecutionRequest,
        validation_decision: ValidationDecision,
    ):
        """Create comprehensive audit trail for compliance"""

        audit_entry = {
            "event_type": "code_execution_validation",
            "request_id": execution_request.request_id,
            "user_id": execution_request.security_context.user_id,
            "session_id": execution_request.security_context.session_id,
            "language": execution_request.language,
            "code_hash": hashlib.sha256(execution_request.code.encode()).hexdigest(),
            "validation_decision": validation_decision.decision.value,
            "confidence": validation_decision.confidence,
            "reasoning": validation_decision.reasoning,
            "approval_session_id": validation_decision.approval_session_id,
            "approver_ids": validation_decision.approver_ids,
            "validation_time_ms": validation_decision.validation_time_ms,
            "timestamp": datetime.now().isoformat(),
        }

        # Add to validation decision audit trail
        validation_decision.audit_trail.append(audit_entry)

        # Log for monitoring
        self.logger.info("Code execution validation audit", extra=audit_entry)

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
            "approval_rate": (
                self.metrics["approved_executions"]
                / max(1, self.metrics["total_validations"])
            ),
            "threat_detection_rate": (
                self.metrics["threat_detections"]
                / max(1, self.metrics["total_validations"])
            ),
            "performance_compliance": (
                self.metrics["average_validation_time_ms"] <= self.performance_target_ms
            ),
        }


# Factory function for easy integration
async def create_parlant_code_validator(
    parlant_service: Optional[ParlantIntegrationService] = None, **kwargs
) -> ParlantCodeExecutionValidator:
    """
    Factory function to create PARLANT Code Execution Validator

    Args:
        parlant_service: Optional PARLANT service instance
        **kwargs: Additional configuration options

    Returns:
        Configured ParlantCodeExecutionValidator instance
    """

    if parlant_service is None:
        parlant_service = ParlantIntegrationService()

    return ParlantCodeExecutionValidator(parlant_service=parlant_service, **kwargs)
