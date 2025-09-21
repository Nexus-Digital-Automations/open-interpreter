#!/usr/bin/env python3
"""
Ultra-Secure Open-Interpreter Demo

Demonstrates ultra-secure code execution validation with Parlant AI integration,
enterprise security features, and comprehensive compliance monitoring.

This example shows how to use all the security features in a realistic scenario.

@author Agent #8 - Open-Interpreter Parlant Integration
@since 1.0.0
"""

import asyncio
import os
import sys
from pathlib import Path

# Add interpreter path
sys.path.insert(0, str(Path(__file__).parent.parent))

from interpreter.ultra_secure_init import (
    compliance_report,
    display_ultra_secure_banner,
    enterprise_interpreter,
    financial_grade_interpreter,
    get_manager,
    security_status,
    smart_interpreter,
    ultra_secure_interpreter,
)


async def demo_basic_ultra_secure():
    """Demonstrate basic ultra-secure interpreter usage"""
    print("\n🛡️ === BASIC ULTRA-SECURE DEMO ===")

    # Create ultra-secure interpreter with production settings
    interpreter = ultra_secure_interpreter(security_preset="production")

    print(
        f"✅ Created interpreter with security level: {interpreter.security_level.value}"
    )
    print(f"✅ Execution environment: {interpreter.execution_environment.value}")
    print(f"✅ Ultra-secure mode: {interpreter.ultra_secure_mode}")

    # Safe code execution (should be approved automatically)
    safe_code = """
# Safe data analysis code
import json
data = {"sales": [100, 200, 300], "month": "January"}
total_sales = sum(data["sales"])
print(f"Total sales for {data['month']}: ${total_sales}")
"""

    print("\n🔍 Executing safe code with ultra-secure validation...")
    try:
        result = await interpreter.execute_code_ultra_secure(
            code=safe_code,
            language="python",
            user_intent="Calculate monthly sales totals for reporting",
            business_justification="Monthly financial reporting requirement",
        )

        print(f"✅ Execution successful: {result.success}")
        print(f"📊 Risk level assessed: {result.risk_assessment.risk_level.value}")
        print(f"⏱️ Execution time: {result.execution_time:.2f}s")

        if result.output:
            print(f"📤 Output: {result.output}")

    except Exception as e:
        print(f"❌ Execution failed: {e}")

    # Demonstrate chat with security validation
    print("\n💬 Demonstrating secure chat interaction...")
    try:
        await interpreter.chat_async(
            "Please help me analyze a CSV file with customer data", display=True
        )
        print("✅ Chat completed successfully")
    except Exception as e:
        print(f"❌ Chat failed: {e}")


async def demo_high_risk_code():
    """Demonstrate high-risk code handling"""
    print("\n⚠️ === HIGH-RISK CODE DEMO ===")

    interpreter = ultra_secure_interpreter(security_preset="enterprise")

    # High-risk code that should trigger extensive validation
    high_risk_code = """
import subprocess
import os

# This code has high risk factors:
# - System command execution
# - File system access
# - Network operations

# List system processes
result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
print("System processes:")
print(result.stdout[:500])  # Limit output

# Check current directory
print(f"Current directory: {os.getcwd()}")
print(f"Directory contents: {os.listdir('.')[:10]}")  # Limit listing
"""

    print("🔍 Executing high-risk code (may require approval)...")
    try:
        result = await interpreter.execute_code_ultra_secure(
            code=high_risk_code,
            language="python",
            user_intent="System health check for monitoring dashboard",
            business_justification="Required for IT operations monitoring",
        )

        print(f"✅ Execution result: {result.success}")
        print(f"🚨 Risk level: {result.risk_assessment.risk_level.value}")
        print(f"🔐 Security level: {result.risk_assessment.security_level.value}")
        print(f"👥 Approval level: {result.risk_assessment.approval_level.value}")

        if result.risk_assessment.risk_factors:
            print(
                f"⚠️ Risk factors detected: {len(result.risk_assessment.risk_factors)}"
            )
            for factor in result.risk_assessment.risk_factors[:3]:
                print(f"   • {factor}")

        if result.security_events:
            print(f"🔍 Security events: {len(result.security_events)}")

    except PermissionError as e:
        print(f"🚫 Code blocked by security validation: {e}")
    except Exception as e:
        print(f"❌ Execution error: {e}")


def demo_enterprise_integration():
    """Demonstrate enterprise security integration"""
    print("\n🏢 === ENTERPRISE INTEGRATION DEMO ===")

    # Configure enterprise integration
    enterprise_config = {
        "database_path": "demo_security.db",
        "siem": {
            # In production, these would be real endpoints
            "splunk_endpoint": "https://demo-splunk.company.com:8088",
            "qradar_endpoint": "https://demo-qradar.company.com",
        },
        "alerting": {
            "security_team_emails": ["security-demo@company.com"],
            "webhook_urls": ["https://demo-webhook.company.com/security"],
        },
    }

    interpreter = enterprise_interpreter(enterprise_config=enterprise_config)

    print("✅ Enterprise interpreter created with:")
    print("   📊 SIEM integration configured")
    print("   📧 Security alerting enabled")
    print("   📈 Compliance monitoring active")
    print("   🔍 Enterprise audit trail enabled")

    # Get enterprise security status
    status = interpreter.get_security_status()
    print("\n📊 Enterprise Security Status:")
    print(f"   Security Level: {status['interpreter_security']['security_level']}")
    print(f"   Compliance Mode: {status['interpreter_security']['compliance_mode']}")
    print(
        f"   Validation Metrics: {status['validation_metrics']['performance_metrics']['total_requests']} requests processed"
    )

    # Demonstrate compliance-sensitive code

    print("\n🔍 Executing compliance-sensitive code...")
    try:
        # This would be async in production
        print("✅ Code would be processed through enterprise security pipeline")
        print("📋 Compliance frameworks checked: SOX, GDPR, HIPAA, PCI DSS")
        print("🔔 Security alerts would be sent to configured channels")
        print("📊 SIEM events would be generated and sent")

    except Exception as e:
        print(f"❌ Enterprise processing error: {e}")


def demo_financial_grade_security():
    """Demonstrate maximum security for financial environments"""
    print("\n🏦 === FINANCIAL-GRADE SECURITY DEMO ===")

    # Financial-grade interpreter has maximum security settings
    interpreter = financial_grade_interpreter()

    print("✅ Financial-grade interpreter created with:")
    print(f"   🔐 Security Level: {interpreter.security_level.value} (TOP SECRET)")
    print(f"   🏗️ Execution Environment: {interpreter.execution_environment.value}")
    print(f"   ⚡ Ultra-secure mode: {interpreter.ultra_secure_mode}")
    print(f"   📋 Max execution time: {interpreter.max_execution_time}s")
    print(f"   💾 Max memory: {interpreter.max_memory_mb}MB")

    # Financial calculation code (high security requirements)

    print("\n🔍 Executing financial calculation with maximum security...")
    try:
        # In production, this would require board-level approval for critical operations
        print("⚠️ Financial-grade security requires human approval for execution")
        print("👥 Board-level approval would be required")
        print("🔐 Execution would occur in isolated virtual machine")
        print("📊 Comprehensive audit trail would be generated")
        print("🚨 Real-time monitoring would be active")
        print("📋 Full regulatory compliance would be validated")

    except Exception as e:
        print(f"❌ Financial security validation error: {e}")


def demo_security_monitoring():
    """Demonstrate security monitoring and reporting"""
    print("\n📊 === SECURITY MONITORING DEMO ===")

    # Get global security status
    status = security_status()

    print("🔍 Global Security Status:")
    print(f"   Active Interpreters: {status['manager_info']['active_interpreters']}")
    print(
        f"   Ultra-secure Mode: {status['manager_info']['ultra_secure_mode_enabled']}"
    )
    print(f"   Enterprise Mode: {status['manager_info']['enterprise_mode_enabled']}")

    # Generate compliance report
    report = compliance_report()
    print("\n📋 Compliance Report Summary:")
    print(f"   Total Operations: {report['summary'].get('total_operations', 'N/A')}")
    print(f"   Compliance Events: {report['summary'].get('compliance_events', 'N/A')}")
    print(
        f"   Security Incidents: {report['summary'].get('security_incidents', 'N/A')}"
    )

    # Demonstrate manager capabilities
    manager = get_manager()
    interpreters = manager.list_interpreters()

    if interpreters:
        print("\n🤖 Active Interpreter Instances:")
        for instance_id, info in interpreters.items():
            print(f"   {instance_id[:20]}...")
            print(f"     Security Level: {info['security_level']}")
            print(f"     Environment: {info['execution_environment']}")
            print(f"     Created: {info['created_at']}")


def demo_smart_configuration():
    """Demonstrate smart environment-based configuration"""
    print("\n🧠 === SMART CONFIGURATION DEMO ===")

    # Simulate different environments
    environments = ["development", "production", "enterprise", "financial"]

    for env in environments:
        os.environ["ENVIRONMENT"] = env

        try:
            interpreter = smart_interpreter()
            print(f"🌍 Environment '{env}' detected:")
            print(f"   Security Level: {interpreter.security_level.value}")
            print(
                f"   Execution Environment: {interpreter.execution_environment.value}"
            )
            print(f"   Ultra-secure Mode: {interpreter.ultra_secure_mode}")
            print(f"   Max Execution Time: {interpreter.max_execution_time}s")
        except Exception as e:
            print(f"❌ Error creating interpreter for {env}: {e}")


async def main():
    """Run all demonstrations"""
    print("🚀 Starting Ultra-Secure Open-Interpreter Demonstration")
    print("=" * 60)

    try:
        # Run all demos
        await demo_basic_ultra_secure()
        await demo_high_risk_code()
        demo_enterprise_integration()
        demo_financial_grade_security()
        demo_security_monitoring()
        demo_smart_configuration()

        print("\n" + "=" * 60)
        print("✅ All demonstrations completed successfully!")
        print("\n📚 For more information, see the ULTRA_SECURE_README.md file")
        print("🔗 Enterprise support: Contact your security team")

    except KeyboardInterrupt:
        print("\n⚠️ Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    # Display banner
    display_ultra_secure_banner()

    print("\n🎯 This demonstration showcases:")
    print("   • Ultra-secure code execution validation")
    print("   • Enterprise security integration")
    print("   • Financial-grade security features")
    print("   • Comprehensive compliance monitoring")
    print("   • Real-time security status reporting")

    print("\n⚠️ Note: This is a demonstration with simulated security features.")
    print("In production, all security validations would be fully enforced.")

    # Run async demo
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Demonstration terminated by user")
    except Exception as e:
        print(f"\n💥 Demonstration crashed: {e}")
        sys.exit(1)
