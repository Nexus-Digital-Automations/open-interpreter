"""
PARLANT File System Operation Validation for Open-Interpreter

Provides comprehensive conversational validation for all file system operations
with path sensitivity analysis, operation risk classification, and approval
workflows. Ensures secure file operations through intelligent conversation
validation with enterprise-grade audit trails.

Features:
- Path sensitivity analysis with automatic classification
- Operation type risk assessment (read, write, delete, execute)
- Conversational approval workflows for sensitive operations
- Integration with existing Open-Interpreter file tracking
- Real-time monitoring and audit trail generation
- Sub-500ms validation for interactive operations

@author PARLANT Integration Specialist
@since 1.0.0
@security_level ENTERPRISE
"""

import logging
import mimetypes
import os
import re
import stat
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .enterprise_security_integration import EnterpriseSecurityOrchestrator
from .parlant_integration import ParlantIntegrationService


class FileOperationType(Enum):
    """Types of file system operations"""

    READ = "read"
    WRITE = "write"
    CREATE = "create"
    DELETE = "delete"
    MOVE = "move"
    COPY = "copy"
    CHMOD = "chmod"
    CHOWN = "chown"
    SYMLINK = "symlink"
    EXECUTE = "execute"
    LIST_DIRECTORY = "list_directory"
    CREATE_DIRECTORY = "create_directory"
    DELETE_DIRECTORY = "delete_directory"


class PathSensitivityLevel(Enum):
    """Path sensitivity classification levels"""

    PUBLIC = "public"  # No restrictions
    INTERNAL = "internal"  # Internal files
    SENSITIVE = "sensitive"  # Contains sensitive data
    CONFIDENTIAL = "confidential"  # Highly sensitive
    RESTRICTED = "restricted"  # Access restricted
    SYSTEM_CRITICAL = "system_critical"  # System-critical files


class FileValidationResult(Enum):
    """File operation validation results"""

    APPROVED = "approved"
    CONDITIONAL_APPROVAL = "conditional_approval"
    REQUIRES_CONFIRMATION = "requires_confirmation"
    REQUIRES_DUAL_APPROVAL = "requires_dual_approval"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"


@dataclass
class PathAnalysisResult:
    """Result of path sensitivity analysis"""

    path: str
    sensitivity_level: PathSensitivityLevel
    risk_score: float
    sensitivity_factors: List[str] = field(default_factory=list)
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    permissions: Optional[str] = None
    owner: Optional[str] = None
    is_executable: bool = False
    is_system_file: bool = False
    contains_credentials: bool = False
    analysis_confidence: float = 0.0


@dataclass
class FileOperationRequest:
    """File operation request for validation"""

    request_id: str
    operation_type: FileOperationType
    source_path: Optional[str] = None
    target_path: Optional[str] = None
    permissions: Optional[str] = None
    content_preview: Optional[str] = None
    user_context: Optional[Dict[str, Any]] = None
    business_justification: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class FileValidationDecision:
    """File operation validation decision"""

    decision: FileValidationResult
    confidence: float
    reasoning: str
    conditions: List[str] = field(default_factory=list)
    restrictions: List[str] = field(default_factory=list)
    monitoring_required: bool = False
    backup_required: bool = False
    approval_session_id: Optional[str] = None
    approver_ids: List[str] = field(default_factory=list)
    validation_time_ms: float = 0.0
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


class ParlantFileSystemValidator:
    """
    PARLANT File System Operation Validator

    Provides comprehensive conversational validation for all file system
    operations with intelligent path analysis, risk assessment, and
    approval workflows for secure file operations.

    Features:
    - Automatic path sensitivity classification
    - Operation-specific risk assessment
    - Conversational approval for high-risk operations
    - Integration with existing file tracking systems
    - Comprehensive audit trails and compliance documentation
    """

    def __init__(
        self,
        parlant_service: Optional[ParlantIntegrationService] = None,
        security_orchestrator: Optional[EnterpriseSecurityOrchestrator] = None,
        **kwargs,
    ):
        """Initialize PARLANT File System Validator"""

        # Initialize services
        self.parlant_service = parlant_service or ParlantIntegrationService()
        self.security_orchestrator = security_orchestrator

        # Configuration
        self.validation_enabled = kwargs.get("validation_enabled", True)
        self.performance_target_ms = kwargs.get("performance_target_ms", 500)
        self.auto_backup_sensitive = kwargs.get("auto_backup_sensitive", True)
        self.quarantine_suspicious = kwargs.get("quarantine_suspicious", True)

        # Path sensitivity patterns
        self.sensitivity_patterns = self._initialize_sensitivity_patterns()

        # Operation risk matrix
        self.operation_risk_matrix = self._initialize_operation_risk_matrix()

        # File type classifications
        self.file_type_classifications = self._initialize_file_type_classifications()

        # Performance metrics
        self.metrics = {
            "total_validations": 0,
            "approved_operations": 0,
            "blocked_operations": 0,
            "conversational_approvals": 0,
            "sensitive_path_detections": 0,
            "backup_operations": 0,
            "average_validation_time_ms": 0.0,
            "max_validation_time_ms": 0.0,
        }

        # Logging
        self.logger = logging.getLogger("ParlantFileSystemValidator")
        self.logger.info(
            "PARLANT File System Validator initialized",
            extra={
                "validation_enabled": self.validation_enabled,
                "performance_target_ms": self.performance_target_ms,
                "auto_backup_sensitive": self.auto_backup_sensitive,
                "sensitivity_patterns_loaded": len(self.sensitivity_patterns),
            },
        )

    def _initialize_sensitivity_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize path sensitivity classification patterns"""

        return {
            "system_critical": {
                "patterns": [
                    r"^/etc/",
                    r"^/boot/",
                    r"^/sys/",
                    r"^/proc/",
                    r"^/dev/",
                    r"^/root/",
                    r"^C:\\Windows\\",
                    r"^C:\\Program Files\\",
                    r"^C:\\System32\\",
                ],
                "sensitivity_level": PathSensitivityLevel.SYSTEM_CRITICAL,
                "risk_score": 0.95,
            },
            "credentials": {
                "patterns": [
                    r"\.ssh/",
                    r"\.aws/",
                    r"\.config/",
                    r"\.env",
                    r"password",
                    r"secret",
                    r"key",
                    r"token",
                    r"credential",
                    r"private.*key",
                    r"id_rsa",
                    r"\.pem$",
                    r"\.p12$",
                    r"\.pfx$",
                ],
                "sensitivity_level": PathSensitivityLevel.RESTRICTED,
                "risk_score": 0.9,
            },
            "configuration": {
                "patterns": [
                    r"\.conf$",
                    r"\.config$",
                    r"\.ini$",
                    r"\.yaml$",
                    r"\.yml$",
                    r"\.json$",
                    r"\.toml$",
                    r"settings\.py$",
                    r"config\.js$",
                ],
                "sensitivity_level": PathSensitivityLevel.CONFIDENTIAL,
                "risk_score": 0.7,
            },
            "database": {
                "patterns": [
                    r"\.db$",
                    r"\.sqlite$",
                    r"\.sql$",
                    r"\.mdb$",
                    r"\.accdb$",
                    r"database",
                    r"backup",
                    r"dump",
                ],
                "sensitivity_level": PathSensitivityLevel.CONFIDENTIAL,
                "risk_score": 0.8,
            },
            "logs": {
                "patterns": [
                    r"\.log$",
                    r"\.logs/",
                    r"/var/log/",
                    r"access\.log",
                    r"error\.log",
                    r"security\.log",
                ],
                "sensitivity_level": PathSensitivityLevel.SENSITIVE,
                "risk_score": 0.6,
            },
            "user_data": {
                "patterns": [
                    r"^/home/",
                    r"^/Users/",
                    r"^C:\\Users\\",
                    r"Documents/",
                    r"Desktop/",
                    r"Downloads/",
                ],
                "sensitivity_level": PathSensitivityLevel.SENSITIVE,
                "risk_score": 0.5,
            },
            "temporary": {
                "patterns": [
                    r"^/tmp/",
                    r"^/var/tmp/",
                    r"^C:\\Temp\\",
                    r"\.tmp$",
                    r"\.temp$",
                ],
                "sensitivity_level": PathSensitivityLevel.INTERNAL,
                "risk_score": 0.3,
            },
        }

    def _initialize_operation_risk_matrix(
        self,
    ) -> Dict[FileOperationType, Dict[PathSensitivityLevel, float]]:
        """Initialize operation type vs path sensitivity risk matrix"""

        return {
            FileOperationType.READ: {
                PathSensitivityLevel.PUBLIC: 0.1,
                PathSensitivityLevel.INTERNAL: 0.2,
                PathSensitivityLevel.SENSITIVE: 0.4,
                PathSensitivityLevel.CONFIDENTIAL: 0.6,
                PathSensitivityLevel.RESTRICTED: 0.8,
                PathSensitivityLevel.SYSTEM_CRITICAL: 0.9,
            },
            FileOperationType.WRITE: {
                PathSensitivityLevel.PUBLIC: 0.3,
                PathSensitivityLevel.INTERNAL: 0.4,
                PathSensitivityLevel.SENSITIVE: 0.6,
                PathSensitivityLevel.CONFIDENTIAL: 0.8,
                PathSensitivityLevel.RESTRICTED: 0.95,
                PathSensitivityLevel.SYSTEM_CRITICAL: 0.99,
            },
            FileOperationType.DELETE: {
                PathSensitivityLevel.PUBLIC: 0.5,
                PathSensitivityLevel.INTERNAL: 0.6,
                PathSensitivityLevel.SENSITIVE: 0.8,
                PathSensitivityLevel.CONFIDENTIAL: 0.9,
                PathSensitivityLevel.RESTRICTED: 0.99,
                PathSensitivityLevel.SYSTEM_CRITICAL: 1.0,
            },
            FileOperationType.EXECUTE: {
                PathSensitivityLevel.PUBLIC: 0.4,
                PathSensitivityLevel.INTERNAL: 0.5,
                PathSensitivityLevel.SENSITIVE: 0.7,
                PathSensitivityLevel.CONFIDENTIAL: 0.8,
                PathSensitivityLevel.RESTRICTED: 0.95,
                PathSensitivityLevel.SYSTEM_CRITICAL: 0.99,
            },
            FileOperationType.CHMOD: {
                PathSensitivityLevel.PUBLIC: 0.6,
                PathSensitivityLevel.INTERNAL: 0.7,
                PathSensitivityLevel.SENSITIVE: 0.8,
                PathSensitivityLevel.CONFIDENTIAL: 0.9,
                PathSensitivityLevel.RESTRICTED: 0.95,
                PathSensitivityLevel.SYSTEM_CRITICAL: 0.99,
            },
        }

    def _initialize_file_type_classifications(self) -> Dict[str, Dict[str, Any]]:
        """Initialize file type security classifications"""

        return {
            "executable": {
                "extensions": [
                    ".exe",
                    ".bat",
                    ".sh",
                    ".cmd",
                    ".ps1",
                    ".py",
                    ".js",
                    ".jar",
                ],
                "risk_multiplier": 1.5,
                "requires_approval": True,
            },
            "archive": {
                "extensions": [".zip", ".tar", ".gz", ".rar", ".7z", ".bz2"],
                "risk_multiplier": 1.2,
                "requires_approval": False,
            },
            "document": {
                "extensions": [
                    ".pdf",
                    ".doc",
                    ".docx",
                    ".xls",
                    ".xlsx",
                    ".ppt",
                    ".pptx",
                ],
                "risk_multiplier": 0.8,
                "requires_approval": False,
            },
            "image": {
                "extensions": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg"],
                "risk_multiplier": 0.5,
                "requires_approval": False,
            },
            "text": {
                "extensions": [".txt", ".md", ".log", ".csv"],
                "risk_multiplier": 0.6,
                "requires_approval": False,
            },
            "config": {
                "extensions": [".conf", ".ini", ".yaml", ".yml", ".json", ".toml"],
                "risk_multiplier": 1.3,
                "requires_approval": True,
            },
        }

    async def validate_file_operation(
        self, operation_request: FileOperationRequest
    ) -> FileValidationDecision:
        """
        Main validation entry point for file operations

        Performs comprehensive analysis and conversational validation
        for file operations with path sensitivity analysis and risk assessment.
        """

        validation_start = time.time()
        self.metrics["total_validations"] += 1

        try:
            # Step 1: Analyze path sensitivity
            path_analysis = await self._analyze_path_sensitivity(
                operation_request.source_path, operation_request.target_path
            )

            # Step 2: Assess operation risk
            risk_assessment = await self._assess_operation_risk(
                operation_request, path_analysis
            )

            # Step 3: Determine validation approach
            validation_approach = self._determine_validation_approach(
                operation_request, path_analysis, risk_assessment
            )

            # Step 4: Perform appropriate validation
            validation_decision = await self._perform_file_validation(
                operation_request, path_analysis, risk_assessment, validation_approach
            )

            # Step 5: Handle backup requirements
            if validation_decision.backup_required:
                await self._schedule_backup(operation_request, path_analysis)

            # Step 6: Update metrics and audit trail
            validation_time_ms = (time.time() - validation_start) * 1000
            await self._update_metrics(validation_decision, validation_time_ms)
            await self._create_audit_trail(operation_request, validation_decision)

            validation_decision.validation_time_ms = validation_time_ms

            return validation_decision

        except Exception as e:
            self.logger.error(
                f"File validation error: {str(e)}",
                extra={
                    "request_id": operation_request.request_id,
                    "operation_type": operation_request.operation_type.value,
                    "source_path": operation_request.source_path,
                    "error_type": type(e).__name__,
                },
            )

            # Default to rejection on validation failure
            return FileValidationDecision(
                decision=FileValidationResult.BLOCKED,
                confidence=0.9,
                reasoning=f"Validation system error: {str(e)}",
                validation_time_ms=(time.time() - validation_start) * 1000,
            )

    async def _analyze_path_sensitivity(
        self, source_path: Optional[str], target_path: Optional[str]
    ) -> List[PathAnalysisResult]:
        """Analyze path sensitivity for source and target paths"""

        analysis_results = []

        # Analyze source path
        if source_path:
            source_analysis = await self._analyze_single_path(source_path)
            analysis_results.append(source_analysis)

        # Analyze target path
        if target_path:
            target_analysis = await self._analyze_single_path(target_path)
            analysis_results.append(target_analysis)

        return analysis_results

    async def _analyze_single_path(self, path: str) -> PathAnalysisResult:
        """Perform comprehensive analysis of a single path"""

        analysis_result = PathAnalysisResult(
            path=path, sensitivity_level=PathSensitivityLevel.PUBLIC, risk_score=0.1
        )

        try:
            # Normalize path
            normalized_path = os.path.normpath(path)
            path_obj = Path(normalized_path)

            # Analyze path patterns
            max_risk_score = 0.1
            sensitivity_factors = []

            for category, pattern_info in self.sensitivity_patterns.items():
                for pattern in pattern_info["patterns"]:
                    if re.search(pattern, normalized_path, re.IGNORECASE):
                        sensitivity_factors.append(f"{category}: {pattern}")
                        if pattern_info["risk_score"] > max_risk_score:
                            max_risk_score = pattern_info["risk_score"]
                            analysis_result.sensitivity_level = pattern_info[
                                "sensitivity_level"
                            ]

            analysis_result.risk_score = max_risk_score
            analysis_result.sensitivity_factors = sensitivity_factors

            # Analyze file properties if file exists
            if path_obj.exists():
                stat_result = path_obj.stat()
                analysis_result.file_size = stat_result.st_size
                analysis_result.permissions = oct(stat.S_IMODE(stat_result.st_mode))
                analysis_result.is_executable = bool(stat_result.st_mode & stat.S_IEXEC)

                # Detect file type
                analysis_result.file_type, _ = mimetypes.guess_type(path)

                # Check for system files
                analysis_result.is_system_file = self._is_system_file(normalized_path)

                # Check for credentials in filename/path
                analysis_result.contains_credentials = self._contains_credentials(
                    normalized_path
                )

            # Calculate confidence
            analysis_result.analysis_confidence = min(
                1.0, len(sensitivity_factors) * 0.2 + 0.5
            )

            return analysis_result

        except Exception as e:
            self.logger.error(f"Path analysis error for {path}: {str(e)}")

            # Return safe default on analysis failure
            return PathAnalysisResult(
                path=path,
                sensitivity_level=PathSensitivityLevel.SENSITIVE,
                risk_score=0.5,
                sensitivity_factors=[f"Analysis error: {str(e)}"],
                analysis_confidence=0.3,
            )

    def _is_system_file(self, path: str) -> bool:
        """Check if file is a system file"""

        system_patterns = [
            r"^/etc/",
            r"^/boot/",
            r"^/sys/",
            r"^/proc/",
            r"^/dev/",
            r"^C:\\Windows\\",
            r"^C:\\Program Files\\",
            r"^C:\\System32\\",
        ]

        return any(
            re.match(pattern, path, re.IGNORECASE) for pattern in system_patterns
        )

    def _contains_credentials(self, path: str) -> bool:
        """Check if path suggests credential-related content"""

        credential_keywords = [
            "password",
            "secret",
            "key",
            "token",
            "credential",
            "private",
            "id_rsa",
            "cert",
            "certificate",
        ]

        path_lower = path.lower()
        return any(keyword in path_lower for keyword in credential_keywords)

    async def _assess_operation_risk(
        self,
        operation_request: FileOperationRequest,
        path_analyses: List[PathAnalysisResult],
    ) -> Dict[str, Any]:
        """Assess overall risk for the file operation"""

        # Get maximum risk from all paths
        max_risk_score = 0.1
        max_sensitivity = PathSensitivityLevel.PUBLIC
        all_risk_factors = []

        for analysis in path_analyses:
            if analysis.risk_score > max_risk_score:
                max_risk_score = analysis.risk_score
                max_sensitivity = analysis.sensitivity_level
            all_risk_factors.extend(analysis.sensitivity_factors)

        # Apply operation type risk multiplier
        operation_risk = self.operation_risk_matrix.get(
            operation_request.operation_type, {}
        ).get(max_sensitivity, 0.5)

        # Calculate final risk score
        final_risk_score = min(1.0, (max_risk_score + operation_risk) / 2.0)

        # Apply file type risk multiplier
        if path_analyses:
            file_extension = Path(path_analyses[0].path).suffix.lower()
            for file_type, type_info in self.file_type_classifications.items():
                if file_extension in type_info["extensions"]:
                    final_risk_score *= type_info["risk_multiplier"]
                    break

        # Factor in user context
        if operation_request.user_context:
            user_risk_multiplier = self._calculate_user_risk_multiplier(
                operation_request.user_context
            )
            final_risk_score *= user_risk_multiplier

        return {
            "risk_score": min(1.0, final_risk_score),
            "max_sensitivity": max_sensitivity,
            "risk_factors": all_risk_factors,
            "operation_type": operation_request.operation_type,
            "reversible": self._is_operation_reversible(
                operation_request.operation_type
            ),
            "requires_backup": self._requires_backup(
                operation_request.operation_type, max_sensitivity
            ),
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
            multiplier *= 0.7
        elif "developer" in roles:
            multiplier *= 0.8
        elif "analyst" in roles:
            multiplier *= 0.9

        # Increase risk for users with recent violations
        if user_context.get("recent_violations", 0) > 0:
            multiplier *= 1.3

        return multiplier

    def _is_operation_reversible(self, operation_type: FileOperationType) -> bool:
        """Determine if operation is reversible"""

        reversible_operations = {
            FileOperationType.READ,
            FileOperationType.LIST_DIRECTORY,
            FileOperationType.CREATE,
            FileOperationType.WRITE,
            FileOperationType.COPY,
        }

        return operation_type in reversible_operations

    def _requires_backup(
        self, operation_type: FileOperationType, sensitivity_level: PathSensitivityLevel
    ) -> bool:
        """Determine if operation requires backup"""

        if not self.auto_backup_sensitive:
            return False

        destructive_operations = {
            FileOperationType.DELETE,
            FileOperationType.WRITE,
            FileOperationType.MOVE,
            FileOperationType.CHMOD,
            FileOperationType.CHOWN,
        }

        sensitive_levels = {
            PathSensitivityLevel.SENSITIVE,
            PathSensitivityLevel.CONFIDENTIAL,
            PathSensitivityLevel.RESTRICTED,
            PathSensitivityLevel.SYSTEM_CRITICAL,
        }

        return (
            operation_type in destructive_operations
            and sensitivity_level in sensitive_levels
        )

    def _determine_validation_approach(
        self,
        operation_request: FileOperationRequest,
        path_analyses: List[PathAnalysisResult],
        risk_assessment: Dict[str, Any],
    ) -> str:
        """Determine the appropriate validation approach"""

        risk_score = risk_assessment["risk_score"]
        sensitivity = risk_assessment["max_sensitivity"]

        # Block extremely high-risk operations immediately
        if risk_score >= 0.95 or sensitivity == PathSensitivityLevel.SYSTEM_CRITICAL:
            if operation_request.operation_type in [
                FileOperationType.DELETE,
                FileOperationType.CHMOD,
            ]:
                return "block_immediately"

        # Require dual approval for critical operations
        if risk_score >= 0.8 or sensitivity == PathSensitivityLevel.RESTRICTED:
            return "require_dual_approval"

        # Require conversational approval for high-risk operations
        if risk_score >= 0.6 or sensitivity == PathSensitivityLevel.CONFIDENTIAL:
            return "require_conversational_approval"

        # Require confirmation for medium-risk operations
        if risk_score >= 0.4 or sensitivity == PathSensitivityLevel.SENSITIVE:
            return "require_confirmation"

        # Auto-approve low-risk operations
        return "auto_approve"

    async def _perform_file_validation(
        self,
        operation_request: FileOperationRequest,
        path_analyses: List[PathAnalysisResult],
        risk_assessment: Dict[str, Any],
        validation_approach: str,
    ) -> FileValidationDecision:
        """Perform the appropriate validation based on approach"""

        if validation_approach == "block_immediately":
            self.metrics["blocked_operations"] += 1
            return FileValidationDecision(
                decision=FileValidationResult.BLOCKED,
                confidence=0.95,
                reasoning=f"Operation blocked due to critical risk level: {risk_assessment['max_sensitivity'].value}",
                restrictions=[
                    "File operation prohibited due to security classification"
                ],
            )

        elif validation_approach == "auto_approve":
            self.metrics["approved_operations"] += 1
            return FileValidationDecision(
                decision=FileValidationResult.APPROVED,
                confidence=0.8,
                reasoning="Low risk file operation - auto-approved",
                monitoring_required=True,
                backup_required=risk_assessment["requires_backup"],
            )

        else:
            # Require conversational validation
            return await self._request_file_operation_approval(
                operation_request, path_analyses, risk_assessment, validation_approach
            )

    async def _request_file_operation_approval(
        self,
        operation_request: FileOperationRequest,
        path_analyses: List[PathAnalysisResult],
        risk_assessment: Dict[str, Any],
        validation_approach: str,
    ) -> FileValidationDecision:
        """Request conversational approval for file operation"""

        try:
            # Create approval request
            approval_request = {
                "request_id": operation_request.request_id,
                "operation_type": operation_request.operation_type.value,
                "source_path": operation_request.source_path,
                "target_path": operation_request.target_path,
                "risk_score": risk_assessment["risk_score"],
                "sensitivity_level": risk_assessment["max_sensitivity"].value,
                "risk_factors": risk_assessment["risk_factors"],
                "business_justification": operation_request.business_justification,
                "user_context": operation_request.user_context or {},
                "reversible": risk_assessment["reversible"],
                "requires_backup": risk_assessment["requires_backup"],
                "requires_dual_approval": (
                    validation_approach == "require_dual_approval"
                ),
                "path_analysis": [
                    {
                        "path": analysis.path,
                        "sensitivity_level": analysis.sensitivity_level.value,
                        "risk_score": analysis.risk_score,
                        "file_type": analysis.file_type,
                        "file_size": analysis.file_size,
                        "is_system_file": analysis.is_system_file,
                        "contains_credentials": analysis.contains_credentials,
                    }
                    for analysis in path_analyses
                ],
            }

            # Request approval through PARLANT service
            approval_result = (
                await self.parlant_service.request_file_operation_approval(
                    approval_request
                )
            )

            self.metrics["conversational_approvals"] += 1

            # Process approval result
            if approval_result.get("approved", False):
                decision = FileValidationResult.APPROVED
                if approval_result.get("conditions"):
                    decision = FileValidationResult.CONDITIONAL_APPROVAL

                self.metrics["approved_operations"] += 1

                return FileValidationDecision(
                    decision=decision,
                    confidence=approval_result.get("confidence", 0.8),
                    reasoning=approval_result.get(
                        "reasoning", "Approved through conversational validation"
                    ),
                    conditions=approval_result.get("conditions", []),
                    restrictions=approval_result.get("restrictions", []),
                    monitoring_required=True,
                    backup_required=risk_assessment["requires_backup"],
                    approval_session_id=approval_result.get("session_id"),
                    approver_ids=approval_result.get("approver_ids", []),
                )
            else:
                self.metrics["blocked_operations"] += 1

                return FileValidationDecision(
                    decision=FileValidationResult.BLOCKED,
                    confidence=approval_result.get("confidence", 0.9),
                    reasoning=approval_result.get(
                        "reason", "Rejected through conversational validation"
                    ),
                    approval_session_id=approval_result.get("session_id"),
                )

        except Exception as e:
            self.logger.error(f"File operation approval error: {str(e)}")

            # Default to blocking on approval system failure for high-risk operations
            if risk_assessment["risk_score"] > 0.5:
                self.metrics["blocked_operations"] += 1
                return FileValidationDecision(
                    decision=FileValidationResult.BLOCKED,
                    confidence=0.9,
                    reasoning=f"Approval system unavailable for high-risk operation: {str(e)}",
                )
            else:
                # Allow low-risk operations with monitoring
                self.metrics["approved_operations"] += 1
                return FileValidationDecision(
                    decision=FileValidationResult.CONDITIONAL_APPROVAL,
                    confidence=0.6,
                    reasoning="Approval system unavailable - conditional approval with monitoring",
                    conditions=["Enhanced monitoring enabled"],
                    monitoring_required=True,
                )

    async def _schedule_backup(
        self,
        operation_request: FileOperationRequest,
        path_analyses: List[PathAnalysisResult],
    ):
        """Schedule backup for sensitive file operations"""

        try:
            backup_request = {
                "operation_id": operation_request.request_id,
                "source_path": operation_request.source_path,
                "operation_type": operation_request.operation_type.value,
                "backup_reason": "Pre-operation security backup",
                "priority": (
                    "high"
                    if any(
                        analysis.sensitivity_level
                        in [
                            PathSensitivityLevel.RESTRICTED,
                            PathSensitivityLevel.SYSTEM_CRITICAL,
                        ]
                        for analysis in path_analyses
                    )
                    else "medium"
                ),
            }

            # TODO: Integrate with backup service
            # await self.backup_service.schedule_backup(backup_request)

            self.metrics["backup_operations"] += 1
            self.logger.info(
                "Backup scheduled for file operation", extra=backup_request
            )

        except Exception as e:
            self.logger.error(f"Failed to schedule backup: {str(e)}")

    async def _update_metrics(
        self, validation_decision: FileValidationDecision, validation_time_ms: float
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
        if validation_decision.decision == FileValidationResult.BLOCKED:
            self.metrics["sensitive_path_detections"] += 1

        # Log performance warnings
        if validation_time_ms > self.performance_target_ms:
            self.logger.warning(
                f"File validation time exceeded target: {validation_time_ms:.1f}ms > {self.performance_target_ms}ms"
            )

    async def _create_audit_trail(
        self,
        operation_request: FileOperationRequest,
        validation_decision: FileValidationDecision,
    ):
        """Create comprehensive audit trail for compliance"""

        audit_entry = {
            "event_type": "file_operation_validation",
            "request_id": operation_request.request_id,
            "user_id": (
                operation_request.user_context.get("user_id", "unknown")
                if operation_request.user_context
                else "unknown"
            ),
            "operation_type": operation_request.operation_type.value,
            "source_path": operation_request.source_path,
            "target_path": operation_request.target_path,
            "validation_decision": validation_decision.decision.value,
            "confidence": validation_decision.confidence,
            "reasoning": validation_decision.reasoning,
            "backup_required": validation_decision.backup_required,
            "monitoring_required": validation_decision.monitoring_required,
            "approval_session_id": validation_decision.approval_session_id,
            "approver_ids": validation_decision.approver_ids,
            "validation_time_ms": validation_decision.validation_time_ms,
            "timestamp": datetime.now().isoformat(),
        }

        # Add to validation decision audit trail
        validation_decision.audit_trail.append(audit_entry)

        # Log for monitoring
        self.logger.info("File operation validation audit", extra=audit_entry)

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
                self.metrics["approved_operations"]
                / max(1, self.metrics["total_validations"])
            ),
            "sensitive_detection_rate": (
                self.metrics["sensitive_path_detections"]
                / max(1, self.metrics["total_validations"])
            ),
            "backup_rate": (
                self.metrics["backup_operations"]
                / max(1, self.metrics["total_validations"])
            ),
            "performance_compliance": (
                self.metrics["average_validation_time_ms"] <= self.performance_target_ms
            ),
        }


# Factory function for easy integration
async def create_parlant_file_validator(
    parlant_service: Optional[ParlantIntegrationService] = None, **kwargs
) -> ParlantFileSystemValidator:
    """
    Factory function to create PARLANT File System Validator

    Args:
        parlant_service: Optional PARLANT service instance
        **kwargs: Additional configuration options

    Returns:
        Configured ParlantFileSystemValidator instance
    """

    if parlant_service is None:
        parlant_service = ParlantIntegrationService()

    return ParlantFileSystemValidator(parlant_service=parlant_service, **kwargs)
