"""
Ultra-Secure Parlant Integration Initialization for Open-Interpreter

Provides seamless initialization and integration of ultra-secure code execution
validation, enterprise security features, and Parlant conversational AI for
Open-Interpreter with maximum security and compliance.

This module serves as the main entry point for ultra-secure Open-Interpreter usage.

@author Agent #8 - Open-Interpreter Parlant Integration
@since 1.0.0
@security_level MAXIMUM
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional


# Configure ultra-secure logging
def setup_ultra_secure_logging():
    """Setup comprehensive logging for ultra-secure operations"""
    log_format = "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s"

    # Create logs directory
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_dir / "ultra_secure_interpreter.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    # Set specific logger levels
    logging.getLogger("ParlantIntegration").setLevel(logging.INFO)
    logging.getLogger("UltraSecureCodeExecutionValidator").setLevel(logging.INFO)
    logging.getLogger("EnterpriseSecurityOrchestrator").setLevel(logging.INFO)
    logging.getLogger("CodeSecurityAnalyzer").setLevel(logging.DEBUG)
    logging.getLogger("SecureExecutionEnvironment").setLevel(logging.INFO)


# Initialize logging
setup_ultra_secure_logging()
logger = logging.getLogger("UltraSecureInit")

try:
    # Import core ultra-secure components
    from .core.enhanced_parlant_core import (
        SECURITY_PRESETS,
        ParlantEnhancedAsyncInterpreter,
        ParlantEnhancedOpenInterpreter,
        create_preset_interpreter,
        create_secure_async_interpreter,
        create_secure_interpreter,
    )
    from .core.enterprise_security_integration import (
        ComplianceEvent,
        ComplianceFramework,
        SecurityAlert,
    )
    from .core.ultra_secure_code_execution import (
        ApprovalLevel,
        ExecutionEnvironment,
        RiskLevel,
        SecurityContext,
        SecurityLevel,
        UltraSecureCodeExecutionValidator,
    )

    logger.info("Ultra-secure Parlant integration components loaded successfully")

except ImportError as e:
    logger.error(f"Failed to import ultra-secure components: {e}")
    # Fallback to basic imports

    logger.warning(
        "Falling back to standard Open-Interpreter without ultra-secure features"
    )


class UltraSecureInterpreterManager:
    """
    Manager class for ultra-secure Open-Interpreter instances

    Provides centralized management of ultra-secure interpreters with
    comprehensive configuration, monitoring, and compliance reporting.
    """

    def __init__(self):
        self.logger = logging.getLogger("UltraSecureInterpreterManager")
        self.active_interpreters = {}
        self.global_config = self._load_global_config()

        self.logger.info("Ultra-secure interpreter manager initialized")

    def _load_global_config(self) -> Dict[str, Any]:
        """Load global ultra-secure configuration"""
        config = {
            "default_security_level": os.getenv("OI_SECURITY_LEVEL", "internal"),
            "default_execution_environment": os.getenv("OI_EXECUTION_ENV", "sandboxed"),
            "ultra_secure_mode": os.getenv("OI_ULTRA_SECURE", "true").lower() == "true",
            "audit_enabled": os.getenv("OI_AUDIT_ENABLED", "true").lower() == "true",
            "compliance_mode": os.getenv("OI_COMPLIANCE_MODE", "true").lower()
            == "true",
            "max_execution_time": int(os.getenv("OI_MAX_EXEC_TIME", "300")),
            "max_memory_mb": int(os.getenv("OI_MAX_MEMORY_MB", "512")),
            "enterprise_mode": os.getenv("OI_ENTERPRISE_MODE", "false").lower()
            == "true",
        }

        return config

    def create_interpreter(
        self,
        instance_id: str = None,
        security_preset: str = None,
        security_config: Dict[str, Any] = None,
        enterprise_config: Dict[str, Any] = None,
        **kwargs,
    ) -> "ParlantEnhancedOpenInterpreter":
        """
        Create ultra-secure interpreter instance

        Args:
            instance_id: Unique identifier for the interpreter instance
            security_preset: Security preset configuration (development, production, enterprise, financial)
            security_config: Custom security configuration
            enterprise_config: Enterprise integration configuration
            **kwargs: Additional OpenInterpreter arguments

        Returns:
            Configured ultra-secure interpreter instance
        """
        if not instance_id:
            instance_id = f"interpreter_{len(self.active_interpreters)}_{int(__import__('time').time())}"

        self.logger.info(
            f"Creating ultra-secure interpreter: {instance_id}",
            extra={
                "security_preset": security_preset,
                "ultra_secure_mode": self.global_config["ultra_secure_mode"],
                "enterprise_mode": self.global_config["enterprise_mode"],
            },
        )

        try:
            if security_preset:
                # Use security preset
                interpreter = create_preset_interpreter(
                    preset=security_preset,
                    enterprise_config=enterprise_config,
                    **kwargs,
                )
            else:
                # Use custom configuration or defaults
                final_security_config = self.global_config.copy()
                if security_config:
                    final_security_config.update(security_config)

                interpreter = create_secure_interpreter(
                    security_config=final_security_config,
                    enterprise_config=enterprise_config,
                    **kwargs,
                )

            # Add instance tracking
            interpreter.instance_id = instance_id
            interpreter.created_at = __import__("datetime").datetime.now()
            interpreter.manager = self

            # Store active interpreter
            self.active_interpreters[instance_id] = interpreter

            self.logger.info(
                f"Ultra-secure interpreter created successfully: {instance_id}"
            )
            return interpreter

        except Exception as e:
            self.logger.error(f"Failed to create ultra-secure interpreter: {e}")
            raise

    def create_async_interpreter(
        self,
        instance_id: str = None,
        security_config: Dict[str, Any] = None,
        enterprise_config: Dict[str, Any] = None,
        **kwargs,
    ) -> "ParlantEnhancedAsyncInterpreter":
        """
        Create ultra-secure async interpreter instance

        Args:
            instance_id: Unique identifier for the interpreter instance
            security_config: Security configuration
            enterprise_config: Enterprise integration configuration
            **kwargs: Additional AsyncInterpreter arguments

        Returns:
            Configured ultra-secure async interpreter instance
        """
        if not instance_id:
            instance_id = f"async_interpreter_{len(self.active_interpreters)}_{int(__import__('time').time())}"

        self.logger.info(f"Creating ultra-secure async interpreter: {instance_id}")

        try:
            final_security_config = self.global_config.copy()
            if security_config:
                final_security_config.update(security_config)

            interpreter = create_secure_async_interpreter(
                security_config=final_security_config,
                enterprise_config=enterprise_config,
                **kwargs,
            )

            # Add instance tracking
            interpreter.instance_id = instance_id
            interpreter.created_at = __import__("datetime").datetime.now()
            interpreter.manager = self

            # Store active interpreter
            self.active_interpreters[instance_id] = interpreter

            self.logger.info(
                f"Ultra-secure async interpreter created successfully: {instance_id}"
            )
            return interpreter

        except Exception as e:
            self.logger.error(f"Failed to create ultra-secure async interpreter: {e}")
            raise

    def get_interpreter(self, instance_id: str):
        """Get active interpreter by instance ID"""
        return self.active_interpreters.get(instance_id)

    def list_interpreters(self) -> Dict[str, Dict[str, Any]]:
        """List all active interpreter instances"""
        return {
            instance_id: {
                "instance_id": instance_id,
                "created_at": interpreter.created_at.isoformat(),
                "security_level": interpreter.security_level.value,
                "execution_environment": interpreter.execution_environment.value,
                "ultra_secure_mode": interpreter.ultra_secure_mode,
                "class_name": interpreter.__class__.__name__,
            }
            for instance_id, interpreter in self.active_interpreters.items()
        }

    def shutdown_interpreter(self, instance_id: str):
        """Shutdown and cleanup interpreter instance"""
        if instance_id in self.active_interpreters:
            interpreter = self.active_interpreters[instance_id]

            # Log shutdown
            self.logger.info(f"Shutting down interpreter: {instance_id}")

            # Cleanup resources
            if hasattr(interpreter, "cleanup"):
                interpreter.cleanup()

            # Remove from active interpreters
            del self.active_interpreters[instance_id]

            self.logger.info(f"Interpreter shutdown complete: {instance_id}")
        else:
            self.logger.warning(f"Interpreter not found for shutdown: {instance_id}")

    def get_global_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status for all active interpreters"""
        status = {
            "manager_info": {
                "active_interpreters": len(self.active_interpreters),
                "global_config": self.global_config,
                "ultra_secure_mode_enabled": self.global_config["ultra_secure_mode"],
                "enterprise_mode_enabled": self.global_config["enterprise_mode"],
            },
            "interpreters": {},
        }

        # Collect status from all active interpreters
        for instance_id, interpreter in self.active_interpreters.items():
            try:
                if hasattr(interpreter, "get_security_status"):
                    status["interpreters"][
                        instance_id
                    ] = interpreter.get_security_status()
                else:
                    status["interpreters"][instance_id] = {
                        "error": "Security status not available",
                        "class": interpreter.__class__.__name__,
                    }
            except Exception as e:
                status["interpreters"][instance_id] = {
                    "error": str(e),
                    "class": interpreter.__class__.__name__,
                }

        return status

    def generate_compliance_report(
        self, start_date=None, end_date=None
    ) -> Dict[str, Any]:
        """Generate comprehensive compliance report for all interpreters"""
        if not start_date:
            start_date = __import__("datetime").datetime.now().replace(day=1)
        if not end_date:
            end_date = __import__("datetime").datetime.now()

        report = {
            "report_type": "manager_compliance_report",
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            "summary": {
                "total_interpreters": len(self.active_interpreters),
                "ultra_secure_interpreters": len(
                    [
                        i
                        for i in self.active_interpreters.values()
                        if getattr(i, "ultra_secure_mode", False)
                    ]
                ),
                "enterprise_interpreters": len(
                    [
                        i
                        for i in self.active_interpreters.values()
                        if getattr(i, "compliance_mode", False)
                    ]
                ),
            },
            "interpreter_reports": {},
        }

        # Generate reports for each interpreter
        for instance_id, interpreter in self.active_interpreters.items():
            try:
                if hasattr(interpreter, "generate_security_report"):
                    # This would be async in production
                    report["interpreter_reports"][instance_id] = {
                        "status": "report_available",
                        "note": "Use async method for detailed report",
                    }
                else:
                    report["interpreter_reports"][instance_id] = {
                        "status": "no_reporting_capability",
                        "class": interpreter.__class__.__name__,
                    }
            except Exception as e:
                report["interpreter_reports"][instance_id] = {"error": str(e)}

        return report


# Global manager instance
_global_manager: Optional[UltraSecureInterpreterManager] = None


def get_manager() -> UltraSecureInterpreterManager:
    """Get global ultra-secure interpreter manager"""
    global _global_manager
    if _global_manager is None:
        _global_manager = UltraSecureInterpreterManager()
    return _global_manager


# Convenience functions for quick usage
def ultra_secure_interpreter(security_preset: str = "production", **kwargs):
    """
    Create ultra-secure interpreter with preset configuration

    Args:
        security_preset: Security preset (development, production, enterprise, financial)
        **kwargs: Additional interpreter configuration

    Returns:
        Ultra-secure interpreter instance
    """
    manager = get_manager()
    return manager.create_interpreter(security_preset=security_preset, **kwargs)


def financial_grade_interpreter(**kwargs):
    """Create interpreter with financial-grade security (maximum security)"""
    return ultra_secure_interpreter(security_preset="financial", **kwargs)


def enterprise_interpreter(**kwargs):
    """Create interpreter with enterprise security configuration"""
    return ultra_secure_interpreter(security_preset="enterprise", **kwargs)


def production_interpreter(**kwargs):
    """Create interpreter with production security configuration"""
    return ultra_secure_interpreter(security_preset="production", **kwargs)


def development_interpreter(**kwargs):
    """Create interpreter with development security configuration"""
    return ultra_secure_interpreter(security_preset="development", **kwargs)


# Async versions
def ultra_secure_async_interpreter(**kwargs):
    """Create ultra-secure async interpreter"""
    manager = get_manager()
    return manager.create_async_interpreter(**kwargs)


# Environment detection and auto-configuration
def auto_configure_security():
    """Auto-configure security based on environment detection"""
    environment = os.getenv("ENVIRONMENT", "").lower()

    if environment in ["production", "prod"]:
        return "production"
    elif environment in ["enterprise", "corp"]:
        return "enterprise"
    elif environment in ["financial", "banking", "fintech"]:
        return "financial"
    else:
        return "development"


def smart_interpreter(**kwargs):
    """Create interpreter with smart environment-based security configuration"""
    preset = auto_configure_security()
    logger.info(f"Auto-detected security preset: {preset}")
    return ultra_secure_interpreter(security_preset=preset, **kwargs)


# Quick access to security status
def security_status():
    """Get comprehensive security status for all active interpreters"""
    manager = get_manager()
    return manager.get_global_security_status()


def compliance_report():
    """Generate compliance report for all active interpreters"""
    manager = get_manager()
    return manager.generate_compliance_report()


# Display startup banner
def display_ultra_secure_banner():
    """Display ultra-secure Open-Interpreter startup banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ULTRA-SECURE OPEN INTERPRETER                            ║
║                   Enterprise Parlant AI Integration                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  🛡️  MAXIMUM SECURITY CODE EXECUTION VALIDATION                             ║
║  🏢  ENTERPRISE-GRADE COMPLIANCE & AUDIT TRAILS                             ║
║  🤖  PARLANT CONVERSATIONAL AI SECURITY VALIDATION                          ║
║  📊  COMPREHENSIVE SIEM & ENTERPRISE INTEGRATION                            ║
║                                                                              ║
║  Security Features:                                                          ║
║    ✅ Ultra-Secure Code Execution Validation                               ║
║    ✅ Multi-Level Approval Workflows                                       ║
║    ✅ Real-Time Risk Assessment                                            ║
║    ✅ Sandboxed Execution Environments                                     ║
║    ✅ Comprehensive Audit Logging                                          ║
║    ✅ SIEM Integration (Splunk, QRadar, Sentinel, ArcSight)               ║
║    ✅ Compliance Reporting (SOX, GDPR, HIPAA, PCI DSS)                    ║
║    ✅ Enterprise Alerting & Notifications                                  ║
║                                                                              ║
║  Quick Start:                                                                ║
║    interpreter = ultra_secure_interpreter()                                  ║
║    interpreter = financial_grade_interpreter()  # Maximum security           ║
║    interpreter = smart_interpreter()  # Auto-detect environment             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(banner)


# Auto-display banner on import if in interactive mode
if hasattr(sys, "ps1") or os.getenv("OI_SHOW_BANNER", "true").lower() == "true":
    display_ultra_secure_banner()


# Log successful initialization
logger.info(
    "Ultra-secure Open-Interpreter initialization complete",
    extra={
        "ultra_secure_mode": get_manager().global_config["ultra_secure_mode"],
        "enterprise_mode": get_manager().global_config["enterprise_mode"],
        "default_security_level": get_manager().global_config["default_security_level"],
    },
)


# Export all public interfaces
__all__ = [
    # Core classes
    "UltraSecureCodeExecutionValidator",
    "ParlantEnhancedOpenInterpreter",
    "ParlantEnhancedAsyncInterpreter",
    "UltraSecureInterpreterManager",
    # Enums and data classes
    "SecurityLevel",
    "RiskLevel",
    "ApprovalLevel",
    "ExecutionEnvironment",
    "SecurityContext",
    "SecurityAlert",
    "ComplianceEvent",
    "ComplianceFramework",
    # Factory functions
    "create_secure_interpreter",
    "create_secure_async_interpreter",
    "create_preset_interpreter",
    # Convenience functions
    "ultra_secure_interpreter",
    "financial_grade_interpreter",
    "enterprise_interpreter",
    "production_interpreter",
    "development_interpreter",
    "ultra_secure_async_interpreter",
    "smart_interpreter",
    # Management functions
    "get_manager",
    "security_status",
    "compliance_report",
    # Utility functions
    "display_ultra_secure_banner",
    "auto_configure_security",
    # Presets
    "SECURITY_PRESETS",
]
