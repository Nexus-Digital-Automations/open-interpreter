"""
PARLANT Terminal Command Validation for Open-Interpreter

Provides comprehensive conversational validation for all terminal command execution
with command risk classification, privilege escalation detection, and approval
workflows. Ensures secure terminal operations through intelligent conversation
validation with real-time threat analysis.

Features:
- Command security classification with automatic risk assessment
- Privilege escalation detection and prevention
- Real-time command analysis with threat pattern recognition
- Conversational approval workflows for dangerous commands
- Integration with existing Open-Interpreter terminal interface
- Comprehensive audit trails and compliance documentation
- Sub-500ms validation for interactive terminal operations

@author PARLANT Integration Specialist
@since 1.0.0
@security_level MAXIMUM
"""

import hashlib
import logging
import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .enterprise_security_integration import EnterpriseSecurityOrchestrator
from .parlant_integration import ParlantIntegrationService


class CommandCategory(Enum):
    """Terminal command categories"""

    SYSTEM_ADMINISTRATION = "system_administration"
    FILE_OPERATIONS = "file_operations"
    NETWORK_OPERATIONS = "network_operations"
    PROCESS_MANAGEMENT = "process_management"
    SECURITY_OPERATIONS = "security_operations"
    DEVELOPMENT_TOOLS = "development_tools"
    DATA_OPERATIONS = "data_operations"
    INFORMATIONAL = "informational"
    DANGEROUS = "dangerous"
    MALICIOUS = "malicious"


class CommandRiskLevel(Enum):
    """Terminal command risk levels"""

    SAFE = "safe"  # No security concerns
    LOW = "low"  # Minimal risk
    MEDIUM = "medium"  # Moderate risk
    HIGH = "high"  # Significant risk
    CRITICAL = "critical"  # Critical risk
    CATASTROPHIC = "catastrophic"  # System-destroying potential


class TerminalValidationResult(Enum):
    """Terminal command validation results"""

    APPROVED = "approved"
    CONDITIONAL_APPROVAL = "conditional_approval"
    REQUIRES_CONFIRMATION = "requires_confirmation"
    REQUIRES_DUAL_APPROVAL = "requires_dual_approval"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    SANDBOX_REQUIRED = "sandbox_required"


@dataclass
class CommandAnalysisResult:
    """Result of terminal command analysis"""

    command: str
    category: CommandCategory
    risk_level: CommandRiskLevel
    risk_score: float
    threat_patterns: List[str] = field(default_factory=list)
    dangerous_flags: List[str] = field(default_factory=list)
    privilege_escalation: bool = False
    destructive_potential: bool = False
    network_access: bool = False
    file_modifications: List[str] = field(default_factory=list)
    system_impact: str = "low"
    reversible: bool = True
    confidence: float = 0.0
    analysis_time_ms: float = 0.0


@dataclass
class TerminalValidationRequest:
    """Terminal command validation request"""

    request_id: str
    command: str
    shell_type: str = "bash"
    working_directory: Optional[str] = None
    environment_variables: Optional[Dict[str, str]] = None
    user_context: Optional[Dict[str, Any]] = None
    business_justification: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class TerminalValidationDecision:
    """Terminal command validation decision"""

    decision: TerminalValidationResult
    confidence: float
    reasoning: str
    conditions: List[str] = field(default_factory=list)
    restrictions: List[str] = field(default_factory=list)
    sandbox_required: bool = False
    monitoring_required: bool = False
    timeout_seconds: Optional[int] = None
    allowed_directories: List[str] = field(default_factory=list)
    blocked_operations: List[str] = field(default_factory=list)
    approval_session_id: Optional[str] = None
    approver_ids: List[str] = field(default_factory=list)
    validation_time_ms: float = 0.0
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


class ParlantTerminalValidator:
    """
    PARLANT Terminal Command Validator

    Provides comprehensive conversational validation for all terminal command
    execution with real-time threat analysis, privilege escalation detection,
    and approval workflows for secure terminal operations.

    Features:
    - Real-time command analysis with threat pattern recognition
    - Privilege escalation detection and prevention
    - Conversational approval for dangerous commands
    - Integration with existing terminal interface
    - Comprehensive audit trails and compliance documentation
    """

    def __init__(
        self,
        parlant_service: Optional[ParlantIntegrationService] = None,
        security_orchestrator: Optional[EnterpriseSecurityOrchestrator] = None,
        **kwargs,
    ):
        """Initialize PARLANT Terminal Validator"""

        # Initialize services
        self.parlant_service = parlant_service or ParlantIntegrationService()
        self.security_orchestrator = security_orchestrator

        # Configuration
        self.validation_enabled = kwargs.get("validation_enabled", True)
        self.performance_target_ms = kwargs.get("performance_target_ms", 500)
        self.sandbox_dangerous_commands = kwargs.get("sandbox_dangerous_commands", True)
        self.block_privilege_escalation = kwargs.get("block_privilege_escalation", True)

        # Command classification patterns
        self.command_patterns = self._initialize_command_patterns()

        # Dangerous command signatures
        self.dangerous_signatures = self._initialize_dangerous_signatures()

        # Shell-specific analyzers
        self.shell_analyzers = {
            "bash": self._analyze_bash_command,
            "sh": self._analyze_bash_command,
            "zsh": self._analyze_bash_command,
            "fish": self._analyze_bash_command,
            "powershell": self._analyze_powershell_command,
            "cmd": self._analyze_cmd_command,
        }

        # Performance metrics
        self.metrics = {
            "total_validations": 0,
            "approved_commands": 0,
            "blocked_commands": 0,
            "sandboxed_commands": 0,
            "conversational_approvals": 0,
            "privilege_escalation_attempts": 0,
            "destructive_commands_detected": 0,
            "average_validation_time_ms": 0.0,
            "max_validation_time_ms": 0.0,
        }

        # Logging
        self.logger = logging.getLogger("ParlantTerminalValidator")
        self.logger.info(
            "PARLANT Terminal Validator initialized",
            extra={
                "validation_enabled": self.validation_enabled,
                "performance_target_ms": self.performance_target_ms,
                "sandbox_dangerous_commands": self.sandbox_dangerous_commands,
                "command_patterns_loaded": len(self.command_patterns),
                "supported_shells": list(self.shell_analyzers.keys()),
            },
        )

    def _initialize_command_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize command classification patterns"""

        return {
            "privilege_escalation": {
                "patterns": [
                    r"\bsudo\b",
                    r"\bsu\b\s+",
                    r"\bsetuid\b",
                    r"\bsetgid\b",
                    r"\bchmod\s+[+]?[sugo]*[xst]",
                    r"\bchown\b",
                    r"\bpkexec\b",
                ],
                "category": CommandCategory.SECURITY_OPERATIONS,
                "risk_level": CommandRiskLevel.HIGH,
                "risk_score": 0.9,
            },
            "destructive_operations": {
                "patterns": [
                    r"\brm\s+-[rf]+",
                    r"\brmdir\b",
                    r"\bmkfs\b",
                    r"\bdd\s+.*of=",
                    r"\bfdisk\b",
                    r"\bcfdisk\b",
                    r"\bparted\b",
                    r"\bformat\b",
                    r">\s*/dev/",
                    r"\bshred\b",
                ],
                "category": CommandCategory.DANGEROUS,
                "risk_level": CommandRiskLevel.CATASTROPHIC,
                "risk_score": 0.95,
            },
            "network_operations": {
                "patterns": [
                    r"\bwget\b",
                    r"\bcurl\b",
                    r"\bftp\b",
                    r"\bscp\b",
                    r"\brsync\b",
                    r"\bssh\b",
                    r"\btelnet\b",
                    r"\bnc\b",
                    r"\bnetcat\b",
                    r"\bnmap\b",
                ],
                "category": CommandCategory.NETWORK_OPERATIONS,
                "risk_level": CommandRiskLevel.MEDIUM,
                "risk_score": 0.6,
            },
            "system_configuration": {
                "patterns": [
                    r"\bsystemctl\b",
                    r"\bservice\b",
                    r"\bcrontab\b",
                    r"\biptables\b",
                    r"\bufw\b",
                    r"\bmount\b",
                    r"\bumount\b",
                    r"\bmodprobe\b",
                    r"\binsmod\b",
                    r"\brmmod\b",
                ],
                "category": CommandCategory.SYSTEM_ADMINISTRATION,
                "risk_level": CommandRiskLevel.HIGH,
                "risk_score": 0.8,
            },
            "package_management": {
                "patterns": [
                    r"\bapt\s+install\b",
                    r"\bapt-get\s+install\b",
                    r"\byum\s+install\b",
                    r"\bdnf\s+install\b",
                    r"\bpacman\s+-S\b",
                    r"\bbrew\s+install\b",
                    r"\bpip\s+install\b",
                    r"\bnpm\s+install\b",
                ],
                "category": CommandCategory.SYSTEM_ADMINISTRATION,
                "risk_level": CommandRiskLevel.MEDIUM,
                "risk_score": 0.6,
            },
            "process_management": {
                "patterns": [
                    r"\bkill\b",
                    r"\bkillall\b",
                    r"\bpkill\b",
                    r"\bps\b",
                    r"\btop\b",
                    r"\bhtop\b",
                    r"\bjobs\b",
                    r"\bnohup\b",
                    r"\bdisown\b",
                ],
                "category": CommandCategory.PROCESS_MANAGEMENT,
                "risk_level": CommandRiskLevel.LOW,
                "risk_score": 0.3,
            },
            "file_operations": {
                "patterns": [
                    r"\bcp\b",
                    r"\bmv\b",
                    r"\bln\b",
                    r"\bfind\b",
                    r"\blocate\b",
                    r"\bgrep\b",
                    r"\bsed\b",
                    r"\bawk\b",
                    r"\btar\b",
                    r"\bzip\b",
                    r"\bunzip\b",
                ],
                "category": CommandCategory.FILE_OPERATIONS,
                "risk_level": CommandRiskLevel.LOW,
                "risk_score": 0.2,
            },
            "information_gathering": {
                "patterns": [
                    r"\bls\b",
                    r"\bpwd\b",
                    r"\bwhoami\b",
                    r"\bid\b",
                    r"\buname\b",
                    r"\bdf\b",
                    r"\bdu\b",
                    r"\bfree\b",
                    r"\buptime\b",
                    r"\bdate\b",
                    r"\benv\b",
                ],
                "category": CommandCategory.INFORMATIONAL,
                "risk_level": CommandRiskLevel.SAFE,
                "risk_score": 0.1,
            },
            "development_tools": {
                "patterns": [
                    r"\bgit\b",
                    r"\bmake\b",
                    r"\bgcc\b",
                    r"\bg\+\+\b",
                    r"\bpython\b",
                    r"\bnode\b",
                    r"\bnpm\b",
                    r"\byarn\b",
                    r"\bdocker\b",
                    r"\bkubectl\b",
                ],
                "category": CommandCategory.DEVELOPMENT_TOOLS,
                "risk_level": CommandRiskLevel.LOW,
                "risk_score": 0.3,
            },
        }

    def _initialize_dangerous_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize dangerous command signatures for immediate blocking"""

        return {
            "fork_bomb": {
                "patterns": [
                    r":\(\)\{.*:\|:.*\}",  # :(){:|:&};:
                    r"while\s+true.*do.*done",
                    r"for\s*\(\(.*\)\).*do.*done",
                ],
                "description": "Fork bomb or infinite loop detection",
                "action": "block_immediately",
            },
            "data_destruction": {
                "patterns": [
                    r"rm\s+-rf\s+/",
                    r"dd\s+.*if=/dev/zero.*of=/",
                    r"mkfs\s+/dev/",
                    r">\s*/dev/sda",
                    r"format\s+c:",
                ],
                "description": "Data destruction patterns",
                "action": "block_immediately",
            },
            "reverse_shell": {
                "patterns": [
                    r"nc\s+-[lnvz]*e\s+/bin/[sbz]*sh",
                    r"bash\s+-i\s*>&\s*/dev/tcp/",
                    r"python.*socket.*subprocess",
                    r"exec\s+\d+<>/dev/tcp/",
                ],
                "description": "Reverse shell patterns",
                "action": "block_immediately",
            },
            "credential_harvesting": {
                "patterns": [
                    r"cat\s+/etc/passwd",
                    r"cat\s+/etc/shadow",
                    r'find\s+.*-name\s+["\'].*password["\']',
                    r"grep\s+-r\s+password\s+/",
                    r"history\s*\|\s*grep\s+password",
                ],
                "description": "Credential harvesting attempts",
                "action": "require_dual_approval",
            },
            "system_compromise": {
                "patterns": [
                    r"echo\s+.*>>\s*/etc/passwd",
                    r"echo\s+.*>>\s*/etc/hosts",
                    r"crontab\s+-e",
                    r"chmod\s+\+s\s+",
                    r"echo\s+.*>\s*/etc/ld\.so\.preload",
                ],
                "description": "System compromise patterns",
                "action": "require_dual_approval",
            },
        }

    async def validate_terminal_command(
        self, validation_request: TerminalValidationRequest
    ) -> TerminalValidationDecision:
        """
        Main validation entry point for terminal commands

        Performs comprehensive analysis and conversational validation
        for terminal commands with real-time threat detection and
        approval workflows.
        """

        validation_start = time.time()
        self.metrics["total_validations"] += 1

        try:
            # Step 1: Perform command security analysis
            analysis_result = await self._analyze_command_security(
                validation_request.command, validation_request.shell_type
            )

            # Step 2: Check for immediate threats
            immediate_threat = await self._check_immediate_threats(
                validation_request.command, analysis_result
            )

            if immediate_threat:
                return await self._handle_immediate_threat(
                    validation_request, analysis_result, immediate_threat
                )

            # Step 3: Assess overall command risk
            risk_assessment = await self._assess_command_risk(
                validation_request, analysis_result
            )

            # Step 4: Determine validation approach
            validation_approach = self._determine_validation_approach(
                analysis_result, risk_assessment
            )

            # Step 5: Perform appropriate validation
            validation_decision = await self._perform_terminal_validation(
                validation_request,
                analysis_result,
                risk_assessment,
                validation_approach,
            )

            # Step 6: Update metrics and audit trail
            validation_time_ms = (time.time() - validation_start) * 1000
            await self._update_metrics(
                validation_decision, validation_time_ms, analysis_result
            )
            await self._create_audit_trail(validation_request, validation_decision)

            validation_decision.validation_time_ms = validation_time_ms

            return validation_decision

        except Exception as e:
            self.logger.error(
                f"Terminal validation error: {str(e)}",
                extra={
                    "request_id": validation_request.request_id,
                    "command": validation_request.command[:100],  # Truncate for logging
                    "shell_type": validation_request.shell_type,
                    "error_type": type(e).__name__,
                },
            )

            # Default to rejection on validation failure
            return TerminalValidationDecision(
                decision=TerminalValidationResult.BLOCKED,
                confidence=0.9,
                reasoning=f"Validation system error: {str(e)}",
                validation_time_ms=(time.time() - validation_start) * 1000,
            )

    async def _analyze_command_security(
        self, command: str, shell_type: str
    ) -> CommandAnalysisResult:
        """
        Comprehensive security analysis of terminal command

        Performs pattern matching, argument analysis, and threat detection
        with shell-specific analysis capabilities.
        """

        analysis_start = time.time()

        # Initialize analysis result
        analysis_result = CommandAnalysisResult(
            command=command,
            category=CommandCategory.INFORMATIONAL,
            risk_level=CommandRiskLevel.SAFE,
            risk_score=0.1,
        )

        try:
            # Tokenize command for analysis
            try:
                tokens = shlex.split(command)
                if not tokens:
                    return analysis_result

                main_command = tokens[0]
                arguments = tokens[1:] if len(tokens) > 1 else []
            except ValueError:
                # Invalid shell syntax
                analysis_result.threat_patterns.append("Invalid shell syntax")
                analysis_result.risk_level = CommandRiskLevel.MEDIUM
                analysis_result.risk_score = 0.5
                return analysis_result

            # Pattern-based analysis
            max_risk_score = 0.1
            threat_patterns = []
            command_categories = []

            for category, pattern_info in self.command_patterns.items():
                for pattern in pattern_info["patterns"]:
                    if re.search(pattern, command, re.IGNORECASE):
                        threat_patterns.append(f"{category}: {pattern}")
                        command_categories.append(pattern_info["category"])
                        if pattern_info["risk_score"] > max_risk_score:
                            max_risk_score = pattern_info["risk_score"]
                            analysis_result.risk_level = pattern_info["risk_level"]
                            analysis_result.category = pattern_info["category"]

            analysis_result.threat_patterns = threat_patterns
            analysis_result.risk_score = max_risk_score

            # Analyze command arguments for dangerous flags
            dangerous_flags = self._analyze_command_arguments(main_command, arguments)
            analysis_result.dangerous_flags = dangerous_flags

            # Check for privilege escalation
            analysis_result.privilege_escalation = self._detect_privilege_escalation(
                command
            )

            # Check for destructive potential
            analysis_result.destructive_potential = self._detect_destructive_potential(
                command
            )

            # Check for network access
            analysis_result.network_access = self._detect_network_access(command)

            # Analyze file modifications
            analysis_result.file_modifications = self._detect_file_modifications(
                command
            )

            # Determine system impact
            analysis_result.system_impact = self._assess_system_impact(analysis_result)

            # Determine reversibility
            analysis_result.reversible = self._is_command_reversible(
                command, analysis_result
            )

            # Shell-specific analysis
            if shell_type.lower() in self.shell_analyzers:
                shell_analysis = await self.shell_analyzers[shell_type.lower()](
                    command, tokens
                )
                # Merge shell-specific results
                analysis_result.threat_patterns.extend(
                    shell_analysis.get("additional_threats", [])
                )
                analysis_result.risk_score = max(
                    analysis_result.risk_score,
                    shell_analysis.get("shell_risk_score", 0.0),
                )

            # Calculate confidence
            analysis_result.confidence = min(1.0, len(threat_patterns) * 0.15 + 0.4)
            analysis_result.analysis_time_ms = (time.time() - analysis_start) * 1000

            return analysis_result

        except Exception as e:
            self.logger.error(f"Command analysis error: {str(e)}")

            # Return safe default on analysis failure
            return CommandAnalysisResult(
                command=command,
                category=CommandCategory.DANGEROUS,
                risk_level=CommandRiskLevel.HIGH,
                risk_score=0.7,
                threat_patterns=[f"Analysis error: {str(e)}"],
                confidence=0.3,
                analysis_time_ms=(time.time() - analysis_start) * 1000,
            )

    def _analyze_command_arguments(
        self, command: str, arguments: List[str]
    ) -> List[str]:
        """Analyze command arguments for dangerous flags"""

        dangerous_flags = []

        # Command-specific dangerous argument patterns
        dangerous_arg_patterns = {
            "rm": [r"-[rf]+", r"--recursive", r"--force"],
            "chmod": [r"777", r"666", r"\+s", r"\+x"],
            "dd": [r"of=/dev/", r"if=/dev/"],
            "mount": [r"--bind", r"-o.*exec"],
            "iptables": [r"-F", r"--flush", r"-X"],
            "wget": [r"-O\s*/dev/", r"--output-document=/dev/"],
            "curl": [r"-o\s*/dev/", r"--output=/dev/"],
        }

        if command in dangerous_arg_patterns:
            for arg in arguments:
                for pattern in dangerous_arg_patterns[command]:
                    if re.search(pattern, arg, re.IGNORECASE):
                        dangerous_flags.append(f"{command}: {arg}")

        return dangerous_flags

    def _detect_privilege_escalation(self, command: str) -> bool:
        """Detect privilege escalation attempts"""

        escalation_patterns = [
            r"\bsudo\b",
            r"\bsu\b\s+",
            r"\bpkexec\b",
            r"\bsetuid\b",
            r"\bsetgid\b",
            r"chmod.*\+s",
            r"chown.*root",
        ]

        return any(
            re.search(pattern, command, re.IGNORECASE)
            for pattern in escalation_patterns
        )

    def _detect_destructive_potential(self, command: str) -> bool:
        """Detect destructive command potential"""

        destructive_patterns = [
            r"\brm\b.*-[rf]",
            r"\brmdir\b",
            r"\bmkfs\b",
            r"\bdd\b.*of=",
            r"\bfdisk\b",
            r"\bformat\b",
            r">\s*/dev/",
            r"\bshred\b",
            r"\bwipe\b",
        ]

        return any(
            re.search(pattern, command, re.IGNORECASE)
            for pattern in destructive_patterns
        )

    def _detect_network_access(self, command: str) -> bool:
        """Detect network access operations"""

        network_patterns = [
            r"\bwget\b",
            r"\bcurl\b",
            r"\bftp\b",
            r"\bscp\b",
            r"\brsync\b",
            r"\bssh\b",
            r"\btelnet\b",
            r"\bnc\b",
            r"\bnetcat\b",
            r"\bnmap\b",
            r"/dev/tcp/",
            r"/dev/udp/",
        ]

        return any(
            re.search(pattern, command, re.IGNORECASE) for pattern in network_patterns
        )

    def _detect_file_modifications(self, command: str) -> List[str]:
        """Detect potential file modifications"""

        modifications = []

        # Look for output redirection
        redirect_patterns = [
            r">\s*([^\s&|;]+)",  # Standard output redirection
            r">>\s*([^\s&|;]+)",  # Append redirection
            r"tee\s+([^\s&|;]+)",  # tee command
        ]

        for pattern in redirect_patterns:
            matches = re.findall(pattern, command)
            modifications.extend(matches)

        # Look for explicit file modification commands
        modification_commands = {
            "cp": r"cp\s+\S+\s+(\S+)",
            "mv": r"mv\s+\S+\s+(\S+)",
            "touch": r"touch\s+(\S+)",
            "mkdir": r"mkdir\s+(\S+)",
            "ln": r"ln\s+.*\s+(\S+)",
        }

        for cmd, pattern in modification_commands.items():
            if cmd in command:
                matches = re.findall(pattern, command)
                modifications.extend(matches)

        return modifications

    def _assess_system_impact(self, analysis_result: CommandAnalysisResult) -> str:
        """Assess potential system impact"""

        if analysis_result.privilege_escalation:
            return "critical"
        elif analysis_result.destructive_potential:
            return "high"
        elif analysis_result.file_modifications:
            return "medium"
        elif analysis_result.network_access:
            return "medium"
        else:
            return "low"

    def _is_command_reversible(
        self, command: str, analysis_result: CommandAnalysisResult
    ) -> bool:
        """Determine if command effects are reversible"""

        # Commands that are inherently irreversible
        irreversible_patterns = [
            r"\brm\b",
            r"\brmdir\b",
            r"\bmkfs\b",
            r"\bdd\b.*of=",
            r"\bshred\b",
            r"\bwipe\b",
            r">\s*/dev/",
        ]

        if any(
            re.search(pattern, command, re.IGNORECASE)
            for pattern in irreversible_patterns
        ):
            return False

        # Destructive operations are typically irreversible
        if analysis_result.destructive_potential:
            return False

        return True

    async def _analyze_bash_command(
        self, command: str, tokens: List[str]
    ) -> Dict[str, Any]:
        """Bash/shell-specific command analysis"""

        additional_threats = []
        shell_risk_score = 0.0

        # Check for shell injection patterns
        injection_patterns = [
            r"`.*`",  # Command substitution
            r"\$\(.*\)",  # Command substitution
            r";.*&",  # Command chaining with background
            r"\|\|",  # Or operator
            r"&&",  # And operator
        ]

        for pattern in injection_patterns:
            if re.search(pattern, command):
                additional_threats.append(f"Shell injection pattern: {pattern}")
                shell_risk_score = max(shell_risk_score, 0.6)

        # Check for environment variable manipulation
        if re.search(r"export\s+\w+=", command) or re.search(r"\w+=.*", command):
            additional_threats.append("Environment variable manipulation")
            shell_risk_score = max(shell_risk_score, 0.4)

        return {
            "additional_threats": additional_threats,
            "shell_risk_score": shell_risk_score,
        }

    async def _analyze_powershell_command(
        self, command: str, tokens: List[str]
    ) -> Dict[str, Any]:
        """PowerShell-specific command analysis"""

        additional_threats = []
        shell_risk_score = 0.0

        # Check for PowerShell-specific dangerous patterns
        dangerous_patterns = [
            r"Invoke-Expression",
            r"IEX\s",
            r"Start-Process",
            r"New-Object\s+System\.Net",
            r"DownloadString",
            r"EncodedCommand",
            r"Get-WmiObject",
            r"Set-ExecutionPolicy",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                additional_threats.append(f"PowerShell dangerous pattern: {pattern}")
                shell_risk_score = max(shell_risk_score, 0.7)

        return {
            "additional_threats": additional_threats,
            "shell_risk_score": shell_risk_score,
        }

    async def _analyze_cmd_command(
        self, command: str, tokens: List[str]
    ) -> Dict[str, Any]:
        """CMD-specific command analysis"""

        additional_threats = []
        shell_risk_score = 0.0

        # Check for CMD-specific dangerous patterns
        dangerous_patterns = [
            r"format\s+",
            r"del\s+/[sqf]",
            r"rd\s+/[sq]",
            r"attrib\s+.*\+h",
            r"reg\s+add",
            r"schtasks\s+/create",
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                additional_threats.append(f"CMD dangerous pattern: {pattern}")
                shell_risk_score = max(shell_risk_score, 0.7)

        return {
            "additional_threats": additional_threats,
            "shell_risk_score": shell_risk_score,
        }

    async def _check_immediate_threats(
        self, command: str, analysis_result: CommandAnalysisResult
    ) -> Optional[Dict[str, Any]]:
        """Check for immediate security threats requiring immediate action"""

        for signature_name, signature_info in self.dangerous_signatures.items():
            for pattern in signature_info["patterns"]:
                if re.search(pattern, command, re.IGNORECASE):
                    return {
                        "signature": signature_name,
                        "pattern": pattern,
                        "description": signature_info["description"],
                        "action": signature_info["action"],
                    }

        return None

    async def _handle_immediate_threat(
        self,
        validation_request: TerminalValidationRequest,
        analysis_result: CommandAnalysisResult,
        threat_info: Dict[str, Any],
    ) -> TerminalValidationDecision:
        """Handle immediate security threats"""

        self.metrics["blocked_commands"] += 1

        if threat_info["action"] == "block_immediately":
            return TerminalValidationDecision(
                decision=TerminalValidationResult.BLOCKED,
                confidence=0.95,
                reasoning=f"Command blocked due to immediate threat: {threat_info['description']}",
                restrictions=[f"Threat pattern detected: {threat_info['pattern']}"],
            )
        elif threat_info["action"] == "require_dual_approval":
            return TerminalValidationDecision(
                decision=TerminalValidationResult.REQUIRES_DUAL_APPROVAL,
                confidence=0.9,
                reasoning=f"Dual approval required for threat: {threat_info['description']}",
                conditions=["Dual approval required before execution"],
            )
        else:
            # Default to blocking for unknown actions
            return TerminalValidationDecision(
                decision=TerminalValidationResult.BLOCKED,
                confidence=0.9,
                reasoning=f"Unknown threat action: {threat_info['action']}",
            )

    async def _assess_command_risk(
        self,
        validation_request: TerminalValidationRequest,
        analysis_result: CommandAnalysisResult,
    ) -> Dict[str, Any]:
        """Assess overall command execution risk"""

        # Base risk from analysis
        risk_score = analysis_result.risk_score

        # Apply risk multipliers
        if analysis_result.privilege_escalation:
            risk_score *= 1.3
        if analysis_result.destructive_potential:
            risk_score *= 1.4
        if not analysis_result.reversible:
            risk_score *= 1.2
        if analysis_result.network_access:
            risk_score *= 1.1

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
            "analysis_result": analysis_result,
            "requires_sandbox": self._requires_sandbox(analysis_result, risk_score),
            "timeout_recommended": self._calculate_timeout(analysis_result),
            "monitoring_required": risk_score > 0.3,
        }

    def _calculate_user_risk_multiplier(self, user_context: Dict[str, Any]) -> float:
        """Calculate risk multiplier based on user context"""

        multiplier = 1.0

        # Reduce risk for authenticated users
        if user_context.get("user_id") != "anonymous":
            multiplier *= 0.9

        # Adjust based on user roles
        roles = user_context.get("roles", [])
        if "admin" in roles or "sysadmin" in roles:
            multiplier *= 0.6
        elif "developer" in roles:
            multiplier *= 0.8
        elif "operator" in roles:
            multiplier *= 0.9

        # Increase risk for users with recent violations
        if user_context.get("recent_violations", 0) > 0:
            multiplier *= 1.4

        return multiplier

    def _requires_sandbox(
        self, analysis_result: CommandAnalysisResult, risk_score: float
    ) -> bool:
        """Determine if command requires sandboxed execution"""

        if not self.sandbox_dangerous_commands:
            return False

        # Sandbox high-risk commands
        if risk_score >= 0.6:
            return True

        # Sandbox commands with destructive potential
        if analysis_result.destructive_potential:
            return True

        # Sandbox commands with network access
        if analysis_result.network_access and risk_score >= 0.4:
            return True

        return False

    def _calculate_timeout(
        self, analysis_result: CommandAnalysisResult
    ) -> Optional[int]:
        """Calculate recommended timeout for command execution"""

        # Default timeouts based on command category
        category_timeouts = {
            CommandCategory.INFORMATIONAL: 30,
            CommandCategory.FILE_OPERATIONS: 60,
            CommandCategory.DEVELOPMENT_TOOLS: 300,
            CommandCategory.NETWORK_OPERATIONS: 120,
            CommandCategory.PROCESS_MANAGEMENT: 60,
            CommandCategory.SYSTEM_ADMINISTRATION: 180,
            CommandCategory.SECURITY_OPERATIONS: 300,
            CommandCategory.DANGEROUS: 60,
            CommandCategory.MALICIOUS: 10,
        }

        return category_timeouts.get(analysis_result.category, 60)

    def _determine_validation_approach(
        self, analysis_result: CommandAnalysisResult, risk_assessment: Dict[str, Any]
    ) -> str:
        """Determine the appropriate validation approach"""

        risk_score = risk_assessment["risk_score"]

        # Block extremely dangerous commands
        if analysis_result.risk_level == CommandRiskLevel.CATASTROPHIC:
            return "block_immediately"

        # Require dual approval for critical commands
        if (
            analysis_result.risk_level == CommandRiskLevel.CRITICAL
            or risk_score >= 0.8
            or (
                analysis_result.privilege_escalation and self.block_privilege_escalation
            )
        ):
            return "require_dual_approval"

        # Require conversational approval for high-risk commands
        if analysis_result.risk_level == CommandRiskLevel.HIGH or risk_score >= 0.6:
            return "require_conversational_approval"

        # Require confirmation for medium-risk commands
        if analysis_result.risk_level == CommandRiskLevel.MEDIUM or risk_score >= 0.4:
            return "require_confirmation"

        # Auto-approve safe commands
        return "auto_approve"

    async def _perform_terminal_validation(
        self,
        validation_request: TerminalValidationRequest,
        analysis_result: CommandAnalysisResult,
        risk_assessment: Dict[str, Any],
        validation_approach: str,
    ) -> TerminalValidationDecision:
        """Perform the appropriate validation based on approach"""

        if validation_approach == "block_immediately":
            self.metrics["blocked_commands"] += 1
            return TerminalValidationDecision(
                decision=TerminalValidationResult.BLOCKED,
                confidence=0.95,
                reasoning=f"Command blocked due to {analysis_result.risk_level.value} risk level",
                restrictions=[
                    "Command execution prohibited due to security classification"
                ],
            )

        elif validation_approach == "auto_approve":
            self.metrics["approved_commands"] += 1
            decision = TerminalValidationResult.APPROVED

            # Check if sandbox is required
            if risk_assessment["requires_sandbox"]:
                decision = TerminalValidationResult.SANDBOX_REQUIRED
                self.metrics["sandboxed_commands"] += 1

            return TerminalValidationDecision(
                decision=decision,
                confidence=0.8,
                reasoning="Safe command - auto-approved",
                sandbox_required=risk_assessment["requires_sandbox"],
                monitoring_required=risk_assessment["monitoring_required"],
                timeout_seconds=risk_assessment["timeout_recommended"],
            )

        else:
            # Require conversational validation
            return await self._request_terminal_command_approval(
                validation_request,
                analysis_result,
                risk_assessment,
                validation_approach,
            )

    async def _request_terminal_command_approval(
        self,
        validation_request: TerminalValidationRequest,
        analysis_result: CommandAnalysisResult,
        risk_assessment: Dict[str, Any],
        validation_approach: str,
    ) -> TerminalValidationDecision:
        """Request conversational approval for terminal command"""

        try:
            # Create approval request
            approval_request = {
                "request_id": validation_request.request_id,
                "command": validation_request.command,
                "shell_type": validation_request.shell_type,
                "command_category": analysis_result.category.value,
                "risk_level": analysis_result.risk_level.value,
                "risk_score": risk_assessment["risk_score"],
                "threat_patterns": analysis_result.threat_patterns,
                "dangerous_flags": analysis_result.dangerous_flags,
                "privilege_escalation": analysis_result.privilege_escalation,
                "destructive_potential": analysis_result.destructive_potential,
                "network_access": analysis_result.network_access,
                "file_modifications": analysis_result.file_modifications,
                "system_impact": analysis_result.system_impact,
                "reversible": analysis_result.reversible,
                "business_justification": validation_request.business_justification,
                "user_context": validation_request.user_context or {},
                "requires_dual_approval": (
                    validation_approach == "require_dual_approval"
                ),
                "sandbox_recommended": risk_assessment["requires_sandbox"],
                "timeout_recommended": risk_assessment["timeout_recommended"],
            }

            # Request approval through PARLANT service
            approval_result = (
                await self.parlant_service.request_terminal_command_approval(
                    approval_request
                )
            )

            self.metrics["conversational_approvals"] += 1

            # Process approval result
            if approval_result.get("approved", False):
                decision = TerminalValidationResult.APPROVED
                if (
                    approval_result.get("conditions")
                    or risk_assessment["requires_sandbox"]
                ):
                    decision = TerminalValidationResult.CONDITIONAL_APPROVAL
                if approval_result.get(
                    "sandbox_required", risk_assessment["requires_sandbox"]
                ):
                    decision = TerminalValidationResult.SANDBOX_REQUIRED
                    self.metrics["sandboxed_commands"] += 1

                self.metrics["approved_commands"] += 1

                return TerminalValidationDecision(
                    decision=decision,
                    confidence=approval_result.get("confidence", 0.8),
                    reasoning=approval_result.get(
                        "reasoning", "Approved through conversational validation"
                    ),
                    conditions=approval_result.get("conditions", []),
                    restrictions=approval_result.get("restrictions", []),
                    sandbox_required=approval_result.get(
                        "sandbox_required", risk_assessment["requires_sandbox"]
                    ),
                    monitoring_required=True,
                    timeout_seconds=approval_result.get(
                        "timeout_seconds", risk_assessment["timeout_recommended"]
                    ),
                    allowed_directories=approval_result.get("allowed_directories", []),
                    blocked_operations=approval_result.get("blocked_operations", []),
                    approval_session_id=approval_result.get("session_id"),
                    approver_ids=approval_result.get("approver_ids", []),
                )
            else:
                self.metrics["blocked_commands"] += 1

                return TerminalValidationDecision(
                    decision=TerminalValidationResult.BLOCKED,
                    confidence=approval_result.get("confidence", 0.9),
                    reasoning=approval_result.get(
                        "reason", "Rejected through conversational validation"
                    ),
                    approval_session_id=approval_result.get("session_id"),
                )

        except Exception as e:
            self.logger.error(f"Terminal command approval error: {str(e)}")

            # Default to appropriate action based on risk level
            if risk_assessment["risk_score"] > 0.6:
                self.metrics["blocked_commands"] += 1
                return TerminalValidationDecision(
                    decision=TerminalValidationResult.BLOCKED,
                    confidence=0.9,
                    reasoning=f"Approval system unavailable for high-risk command: {str(e)}",
                )
            else:
                # Allow low-risk commands with sandbox/monitoring
                self.metrics["approved_commands"] += 1
                if risk_assessment["requires_sandbox"]:
                    self.metrics["sandboxed_commands"] += 1

                return TerminalValidationDecision(
                    decision=(
                        TerminalValidationResult.SANDBOX_REQUIRED
                        if risk_assessment["requires_sandbox"]
                        else TerminalValidationResult.CONDITIONAL_APPROVAL
                    ),
                    confidence=0.6,
                    reasoning="Approval system unavailable - conditional approval with enhanced security",
                    conditions=[
                        "Enhanced monitoring enabled",
                        "Restricted execution environment",
                    ],
                    sandbox_required=risk_assessment["requires_sandbox"],
                    monitoring_required=True,
                    timeout_seconds=risk_assessment["timeout_recommended"],
                )

    async def _update_metrics(
        self,
        validation_decision: TerminalValidationDecision,
        validation_time_ms: float,
        analysis_result: CommandAnalysisResult,
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
        if analysis_result.privilege_escalation:
            self.metrics["privilege_escalation_attempts"] += 1

        if analysis_result.destructive_potential:
            self.metrics["destructive_commands_detected"] += 1

        # Log performance warnings
        if validation_time_ms > self.performance_target_ms:
            self.logger.warning(
                f"Terminal validation time exceeded target: {validation_time_ms:.1f}ms > {self.performance_target_ms}ms"
            )

    async def _create_audit_trail(
        self,
        validation_request: TerminalValidationRequest,
        validation_decision: TerminalValidationDecision,
    ):
        """Create comprehensive audit trail for compliance"""

        audit_entry = {
            "event_type": "terminal_command_validation",
            "request_id": validation_request.request_id,
            "user_id": (
                validation_request.user_context.get("user_id", "unknown")
                if validation_request.user_context
                else "unknown"
            ),
            "command": validation_request.command,
            "command_hash": hashlib.sha256(
                validation_request.command.encode()
            ).hexdigest()[:16],
            "shell_type": validation_request.shell_type,
            "validation_decision": validation_decision.decision.value,
            "confidence": validation_decision.confidence,
            "reasoning": validation_decision.reasoning,
            "sandbox_required": validation_decision.sandbox_required,
            "monitoring_required": validation_decision.monitoring_required,
            "timeout_seconds": validation_decision.timeout_seconds,
            "approval_session_id": validation_decision.approval_session_id,
            "approver_ids": validation_decision.approver_ids,
            "validation_time_ms": validation_decision.validation_time_ms,
            "timestamp": datetime.now().isoformat(),
        }

        # Add to validation decision audit trail
        validation_decision.audit_trail.append(audit_entry)

        # Log for monitoring
        self.logger.info("Terminal command validation audit", extra=audit_entry)

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
                self.metrics["approved_commands"]
                / max(1, self.metrics["total_validations"])
            ),
            "sandbox_rate": (
                self.metrics["sandboxed_commands"]
                / max(1, self.metrics["total_validations"])
            ),
            "threat_detection_rate": (
                (
                    self.metrics["privilege_escalation_attempts"]
                    + self.metrics["destructive_commands_detected"]
                )
                / max(1, self.metrics["total_validations"])
            ),
            "performance_compliance": (
                self.metrics["average_validation_time_ms"] <= self.performance_target_ms
            ),
        }


# Factory function for easy integration
async def create_parlant_terminal_validator(
    parlant_service: Optional[ParlantIntegrationService] = None, **kwargs
) -> ParlantTerminalValidator:
    """
    Factory function to create PARLANT Terminal Validator

    Args:
        parlant_service: Optional PARLANT service instance
        **kwargs: Additional configuration options

    Returns:
        Configured ParlantTerminalValidator instance
    """

    if parlant_service is None:
        parlant_service = ParlantIntegrationService()

    return ParlantTerminalValidator(parlant_service=parlant_service, **kwargs)
