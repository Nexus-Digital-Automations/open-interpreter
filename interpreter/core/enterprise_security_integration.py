"""
Enterprise Security Integration for Open-Interpreter

Provides enterprise-grade security integration with comprehensive audit trails,
compliance reporting, SIEM integration, and advanced threat correlation for
Open-Interpreter code execution with maximum security standards.

@author Agent #8 - Open-Interpreter Parlant Integration
@since 1.0.0
@security_level ENTERPRISE
"""

import asyncio
import hashlib
import json
import logging
import smtplib
import sqlite3
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MimeMultipart
from email.mime.text import MimeText
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .ultra_secure_code_execution import (
    ApprovalLevel,
    ExecutionRequest,
    ExecutionResult,
    RiskLevel,
)


class ComplianceFramework(Enum):
    """Regulatory compliance frameworks"""

    SOX = "sarbanes_oxley"  # Sarbanes-Oxley Act
    GDPR = "general_data_protection"  # General Data Protection Regulation
    HIPAA = "health_insurance_portability"  # Health Insurance Portability and Accountability Act
    PCI_DSS = "payment_card_industry"  # Payment Card Industry Data Security Standard
    ISO_27001 = "iso_27001"  # ISO/IEC 27001
    NIST = "nist_cybersecurity"  # NIST Cybersecurity Framework
    FISMA = (
        "federal_information_security"  # Federal Information Security Management Act
    )


class AlertSeverity(Enum):
    """Security alert severity levels"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class IntegrationProtocol(Enum):
    """Security integration protocols"""

    SYSLOG = "syslog"
    CEF = "common_event_format"
    LEEF = "log_event_extended_format"
    STIX_TAXII = "stix_taxii"
    REST_API = "rest_api"
    WEBHOOK = "webhook"


@dataclass
class SecurityAlert:
    """Security alert with comprehensive metadata"""

    alert_id: str
    severity: AlertSeverity
    title: str
    description: str
    source: str = "open_interpreter"
    category: str = "code_execution"
    subcategory: str = "security_validation"
    risk_score: float = 0.0
    confidence: float = 0.0
    threat_indicators: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    compliance_violations: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None


@dataclass
class ComplianceEvent:
    """Compliance event for regulatory reporting"""

    event_id: str
    framework: ComplianceFramework
    control_id: str
    control_description: str
    compliance_status: str  # COMPLIANT, NON_COMPLIANT, PARTIAL
    violation_details: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation_actions: List[str] = field(default_factory=list)
    responsible_party: str = ""
    due_date: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class SIEMEvent:
    """SIEM event with standardized format"""

    event_id: str
    timestamp: datetime
    source_ip: str = "127.0.0.1"
    source_host: str = "open_interpreter"
    destination_ip: str = "127.0.0.1"
    destination_host: str = "localhost"
    user_id: str = ""
    session_id: str = ""
    event_type: str = "security_validation"
    event_category: str = "code_execution"
    severity: AlertSeverity = AlertSeverity.INFO
    outcome: str = "success"  # success, failure, unknown
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class EnterpriseSecurityDatabase:
    """Enterprise security database for audit trails and compliance"""

    def __init__(self, db_path: str = "enterprise_security.db"):
        self.db_path = db_path
        self.logger = logging.getLogger("EnterpriseSecurityDatabase")
        self._init_database()

    def _init_database(self):
        """Initialize security database with required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Security alerts table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    source TEXT,
                    category TEXT,
                    subcategory TEXT,
                    risk_score REAL,
                    confidence REAL,
                    threat_indicators TEXT,
                    affected_assets TEXT,
                    compliance_violations TEXT,
                    recommended_actions TEXT,
                    raw_data TEXT,
                    created_at TIMESTAMP,
                    expires_at TIMESTAMP
                )
            """
            )

            # Compliance events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS compliance_events (
                    event_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    control_description TEXT,
                    compliance_status TEXT,
                    violation_details TEXT,
                    evidence TEXT,
                    remediation_actions TEXT,
                    responsible_party TEXT,
                    due_date TIMESTAMP,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            """
            )

            # SIEM events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS siem_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TIMESTAMP NOT NULL,
                    source_ip TEXT,
                    source_host TEXT,
                    destination_ip TEXT,
                    destination_host TEXT,
                    user_id TEXT,
                    session_id TEXT,
                    event_type TEXT,
                    event_category TEXT,
                    severity TEXT,
                    outcome TEXT,
                    message TEXT,
                    details TEXT,
                    tags TEXT
                )
            """
            )

            # Execution audit table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_audit (
                    request_id TEXT PRIMARY KEY,
                    user_id TEXT,
                    session_id TEXT,
                    timestamp TIMESTAMP,
                    code_hash TEXT,
                    language TEXT,
                    user_intent TEXT,
                    business_justification TEXT,
                    risk_level TEXT,
                    security_level TEXT,
                    approval_level TEXT,
                    approved BOOLEAN,
                    execution_success BOOLEAN,
                    execution_time REAL,
                    security_events_count INTEGER,
                    compliance_violations_count INTEGER,
                    files_created_count INTEGER,
                    files_modified_count INTEGER,
                    network_connections_count INTEGER
                )
            """
            )

            conn.commit()
            conn.close()

            self.logger.info(
                f"Enterprise security database initialized: {self.db_path}"
            )

        except Exception as e:
            self.logger.error(f"Failed to initialize security database: {e}")
            raise

    def store_security_alert(self, alert: SecurityAlert):
        """Store security alert in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO security_alerts
                (alert_id, severity, title, description, source, category, subcategory,
                 risk_score, confidence, threat_indicators, affected_assets,
                 compliance_violations, recommended_actions, raw_data, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    alert.alert_id,
                    alert.severity.value,
                    alert.title,
                    alert.description,
                    alert.source,
                    alert.category,
                    alert.subcategory,
                    alert.risk_score,
                    alert.confidence,
                    json.dumps(alert.threat_indicators),
                    json.dumps(alert.affected_assets),
                    json.dumps(alert.compliance_violations),
                    json.dumps(alert.recommended_actions),
                    json.dumps(alert.raw_data),
                    alert.created_at,
                    alert.expires_at,
                ),
            )

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store security alert: {e}")

    def store_compliance_event(self, event: ComplianceEvent):
        """Store compliance event in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT OR REPLACE INTO compliance_events
                (event_id, framework, control_id, control_description, compliance_status,
                 violation_details, evidence, remediation_actions, responsible_party,
                 due_date, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event.event_id,
                    event.framework.value,
                    event.control_id,
                    event.control_description,
                    event.compliance_status,
                    json.dumps(event.violation_details),
                    json.dumps(event.evidence),
                    json.dumps(event.remediation_actions),
                    event.responsible_party,
                    event.due_date,
                    event.created_at,
                    event.updated_at,
                ),
            )

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store compliance event: {e}")

    def store_siem_event(self, event: SIEMEvent):
        """Store SIEM event in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO siem_events
                (event_id, timestamp, source_ip, source_host, destination_ip,
                 destination_host, user_id, session_id, event_type, event_category,
                 severity, outcome, message, details, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event.event_id,
                    event.timestamp,
                    event.source_ip,
                    event.source_host,
                    event.destination_ip,
                    event.destination_host,
                    event.user_id,
                    event.session_id,
                    event.event_type,
                    event.event_category,
                    event.severity.value,
                    event.outcome,
                    event.message,
                    json.dumps(event.details),
                    json.dumps(event.tags),
                ),
            )

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store SIEM event: {e}")

    def store_execution_audit(
        self,
        request: ExecutionRequest,
        result: ExecutionResult,
        approved: bool,
        parlant_validation: Dict[str, Any],
    ):
        """Store execution audit trail"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO execution_audit
                (request_id, user_id, session_id, timestamp, code_hash, language,
                 user_intent, business_justification, risk_level, security_level,
                 approval_level, approved, execution_success, execution_time,
                 security_events_count, compliance_violations_count,
                 files_created_count, files_modified_count, network_connections_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    request.request_id,
                    request.security_context.user_id,
                    request.security_context.session_id,
                    result.executed_at,
                    hashlib.sha256(request.code.encode()).hexdigest(),
                    request.language,
                    request.user_intent,
                    request.business_justification,
                    request.risk_assessment.risk_level.value,
                    request.risk_assessment.security_level.value,
                    request.risk_assessment.approval_level.value,
                    approved,
                    result.success,
                    result.execution_time,
                    len(result.security_events),
                    len(result.compliance_log),
                    len(result.files_created),
                    len(result.files_modified),
                    len(result.network_connections),
                ),
            )

            conn.commit()
            conn.close()

        except Exception as e:
            self.logger.error(f"Failed to store execution audit: {e}")

    def get_compliance_report(
        self, framework: ComplianceFramework, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Generate compliance report for specific framework"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT * FROM compliance_events
                WHERE framework = ? AND created_at BETWEEN ? AND ?
                ORDER BY created_at DESC
            """,
                (framework.value, start_date, end_date),
            )

            events = cursor.fetchall()
            conn.close()

            # Process compliance data
            total_events = len(events)
            compliant_events = len([e for e in events if e[4] == "COMPLIANT"])
            non_compliant_events = len([e for e in events if e[4] == "NON_COMPLIANT"])
            partial_events = len([e for e in events if e[4] == "PARTIAL"])

            return {
                "framework": framework.value,
                "period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                },
                "summary": {
                    "total_events": total_events,
                    "compliant_events": compliant_events,
                    "non_compliant_events": non_compliant_events,
                    "partial_events": partial_events,
                    "compliance_rate": (compliant_events / max(total_events, 1)) * 100,
                },
                "events": [
                    {
                        "event_id": e[0],
                        "control_id": e[2],
                        "control_description": e[3],
                        "status": e[4],
                        "violation_details": json.loads(e[5]) if e[5] else [],
                        "created_at": e[10],
                    }
                    for e in events
                ],
            }

        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {e}")
            return {}


class SIEMIntegration:
    """SIEM integration for enterprise security monitoring"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger("SIEMIntegration")
        self.session = self._setup_http_session()

        # SIEM endpoints configuration
        self.splunk_endpoint = self.config.get("splunk_endpoint")
        self.qradar_endpoint = self.config.get("qradar_endpoint")
        self.sentinel_endpoint = self.config.get("sentinel_endpoint")
        self.arcsight_endpoint = self.config.get("arcsight_endpoint")

        self.logger.info("SIEM integration initialized")

    def _setup_http_session(self) -> requests.Session:
        """Setup HTTP session with retry strategy"""
        session = requests.Session()

        retry_strategy = Retry(
            total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    async def send_security_event(self, event: SIEMEvent) -> Dict[str, bool]:
        """Send security event to all configured SIEM systems"""
        results = {}

        # Send to Splunk
        if self.splunk_endpoint:
            results["splunk"] = await self._send_to_splunk(event)

        # Send to QRadar
        if self.qradar_endpoint:
            results["qradar"] = await self._send_to_qradar(event)

        # Send to Azure Sentinel
        if self.sentinel_endpoint:
            results["sentinel"] = await self._send_to_sentinel(event)

        # Send to ArcSight
        if self.arcsight_endpoint:
            results["arcsight"] = await self._send_to_arcsight(event)

        return results

    async def _send_to_splunk(self, event: SIEMEvent) -> bool:
        """Send event to Splunk via HTTP Event Collector"""
        try:
            splunk_event = {
                "time": event.timestamp.timestamp(),
                "host": event.source_host,
                "source": "open_interpreter",
                "sourcetype": "code_execution_security",
                "event": {
                    "event_id": event.event_id,
                    "user_id": event.user_id,
                    "session_id": event.session_id,
                    "event_type": event.event_type,
                    "category": event.event_category,
                    "severity": event.severity.value,
                    "outcome": event.outcome,
                    "message": event.message,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "details": event.details,
                    "tags": event.tags,
                },
            }

            headers = {
                "Authorization": f"Splunk {self.config.get('splunk_token')}",
                "Content-Type": "application/json",
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.splunk_endpoint}/services/collector/event",
                    json=splunk_event,
                    headers=headers,
                    timeout=30,
                ),
            )

            return response.status_code == 200

        except Exception as e:
            self.logger.error(f"Failed to send event to Splunk: {e}")
            return False

    async def _send_to_qradar(self, event: SIEMEvent) -> bool:
        """Send event to IBM QRadar via REST API"""
        try:
            qradar_event = {
                "event_id": event.event_id,
                "timestamp": int(event.timestamp.timestamp() * 1000),
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "username": event.user_id,
                "event_type": event.event_type,
                "severity": self._map_severity_to_qradar(event.severity),
                "message": event.message,
                "custom_properties": {
                    "session_id": event.session_id,
                    "category": event.event_category,
                    "outcome": event.outcome,
                    "details": json.dumps(event.details),
                    "tags": ",".join(event.tags),
                },
            }

            headers = {
                "SEC": self.config.get("qradar_token"),
                "Content-Type": "application/json",
                "Version": "12.0",
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.qradar_endpoint}/api/siem/events",
                    json=qradar_event,
                    headers=headers,
                    timeout=30,
                ),
            )

            return response.status_code in [200, 201]

        except Exception as e:
            self.logger.error(f"Failed to send event to QRadar: {e}")
            return False

    async def _send_to_sentinel(self, event: SIEMEvent) -> bool:
        """Send event to Azure Sentinel via Log Analytics API"""
        try:
            sentinel_event = {
                "TimeGenerated": event.timestamp.isoformat(),
                "EventId": event.event_id,
                "SourceIP": event.source_ip,
                "DestinationIP": event.destination_ip,
                "UserId": event.user_id,
                "SessionId": event.session_id,
                "EventType": event.event_type,
                "Category": event.event_category,
                "Severity": event.severity.value,
                "Outcome": event.outcome,
                "Message": event.message,
                "Details": json.dumps(event.details),
                "Tags": ",".join(event.tags),
            }

            headers = {
                "Authorization": f"Bearer {self.config.get('sentinel_token')}",
                "Content-Type": "application/json",
                "Log-Type": "OpenInterpreterSecurity",
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.sentinel_endpoint}/api/logs",
                    json=[sentinel_event],
                    headers=headers,
                    timeout=30,
                ),
            )

            return response.status_code == 200

        except Exception as e:
            self.logger.error(f"Failed to send event to Sentinel: {e}")
            return False

    async def _send_to_arcsight(self, event: SIEMEvent) -> bool:
        """Send event to ArcSight via CEF format"""
        try:
            # Create CEF (Common Event Format) message
            cef_message = self._create_cef_message(event)

            arcsight_event = {
                "cef_message": cef_message,
                "timestamp": event.timestamp.isoformat(),
                "source": "open_interpreter",
            }

            headers = {
                "Authorization": f"Bearer {self.config.get('arcsight_token')}",
                "Content-Type": "application/json",
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(
                    f"{self.arcsight_endpoint}/api/events",
                    json=arcsight_event,
                    headers=headers,
                    timeout=30,
                ),
            )

            return response.status_code in [200, 201]

        except Exception as e:
            self.logger.error(f"Failed to send event to ArcSight: {e}")
            return False

    def _create_cef_message(self, event: SIEMEvent) -> str:
        """Create CEF (Common Event Format) message"""
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
        cef_parts = [
            "CEF:0",
            "Anthropic",
            "Open Interpreter",
            "1.0",
            event.event_type,
            event.message.replace("|", "\\|"),
            str(self._map_severity_to_cef(event.severity)),
        ]

        # Extensions
        extensions = []
        if event.source_ip:
            extensions.append(f"src={event.source_ip}")
        if event.destination_ip:
            extensions.append(f"dst={event.destination_ip}")
        if event.user_id:
            extensions.append(f"suser={event.user_id}")
        if event.session_id:
            extensions.append(f"cs1={event.session_id}")
            extensions.append("cs1Label=SessionId")

        extensions.append(f"cat={event.event_category}")
        extensions.append(f"outcome={event.outcome}")

        cef_message = "|".join(cef_parts)
        if extensions:
            cef_message += "|" + " ".join(extensions)

        return cef_message

    def _map_severity_to_qradar(self, severity: AlertSeverity) -> int:
        """Map alert severity to QRadar severity scale (1-10)"""
        mapping = {
            AlertSeverity.INFO: 2,
            AlertSeverity.LOW: 3,
            AlertSeverity.MEDIUM: 5,
            AlertSeverity.HIGH: 7,
            AlertSeverity.CRITICAL: 9,
            AlertSeverity.EMERGENCY: 10,
        }
        return mapping.get(severity, 5)

    def _map_severity_to_cef(self, severity: AlertSeverity) -> int:
        """Map alert severity to CEF severity scale (0-10)"""
        mapping = {
            AlertSeverity.INFO: 2,
            AlertSeverity.LOW: 3,
            AlertSeverity.MEDIUM: 5,
            AlertSeverity.HIGH: 7,
            AlertSeverity.CRITICAL: 9,
            AlertSeverity.EMERGENCY: 10,
        }
        return mapping.get(severity, 5)


class ComplianceReportingEngine:
    """Enterprise compliance reporting and monitoring"""

    def __init__(self, database: EnterpriseSecurityDatabase):
        self.database = database
        self.logger = logging.getLogger("ComplianceReportingEngine")

        # Compliance control mappings
        self.sox_controls = self._init_sox_controls()
        self.gdpr_controls = self._init_gdpr_controls()
        self.hipaa_controls = self._init_hipaa_controls()
        self.pci_dss_controls = self._init_pci_dss_controls()

        self.logger.info("Compliance reporting engine initialized")

    def _init_sox_controls(self) -> Dict[str, str]:
        """Initialize SOX compliance controls mapping"""
        return {
            "SOX-302": "Management assessment of internal controls",
            "SOX-404": "Internal control over financial reporting",
            "SOX-409": "Real-time disclosure requirements",
            "ITGC-AC01": "Logical access controls",
            "ITGC-AC02": "Privileged access management",
            "ITGC-CM01": "Change management procedures",
            "ITGC-CM02": "Code execution controls",
            "ITGC-OP01": "Operations monitoring",
        }

    def _init_gdpr_controls(self) -> Dict[str, str]:
        """Initialize GDPR compliance controls mapping"""
        return {
            "GDPR-ART6": "Lawfulness of processing",
            "GDPR-ART7": "Conditions for consent",
            "GDPR-ART25": "Data protection by design and by default",
            "GDPR-ART32": "Security of processing",
            "GDPR-ART33": "Notification of personal data breach",
            "GDPR-ART35": "Data protection impact assessment",
            "GDPR-ART44": "General principle for transfers",
        }

    def _init_hipaa_controls(self) -> Dict[str, str]:
        """Initialize HIPAA compliance controls mapping"""
        return {
            "HIPAA-164.306": "Security standards - general rules",
            "HIPAA-164.308": "Administrative safeguards",
            "HIPAA-164.310": "Physical safeguards",
            "HIPAA-164.312": "Technical safeguards",
            "HIPAA-164.314": "Organizational requirements",
            "HIPAA-164.316": "Policies and procedures and documentation requirements",
        }

    def _init_pci_dss_controls(self) -> Dict[str, str]:
        """Initialize PCI DSS compliance controls mapping"""
        return {
            "PCI-REQ1": "Install and maintain firewall configuration",
            "PCI-REQ2": "Do not use vendor-supplied defaults",
            "PCI-REQ3": "Protect stored cardholder data",
            "PCI-REQ4": "Encrypt transmission of cardholder data",
            "PCI-REQ6": "Develop and maintain secure systems",
            "PCI-REQ7": "Restrict access by business need-to-know",
            "PCI-REQ8": "Identify and authenticate access",
            "PCI-REQ10": "Track and monitor all access",
        }

    async def assess_compliance(
        self, request: ExecutionRequest, result: ExecutionResult
    ) -> List[ComplianceEvent]:
        """Assess compliance violations for code execution request"""
        compliance_events = []

        # Assess SOX compliance
        sox_events = await self._assess_sox_compliance(request, result)
        compliance_events.extend(sox_events)

        # Assess GDPR compliance
        gdpr_events = await self._assess_gdpr_compliance(request, result)
        compliance_events.extend(gdpr_events)

        # Assess HIPAA compliance
        hipaa_events = await self._assess_hipaa_compliance(request, result)
        compliance_events.extend(hipaa_events)

        # Assess PCI DSS compliance
        pci_events = await self._assess_pci_dss_compliance(request, result)
        compliance_events.extend(pci_events)

        # Store compliance events
        for event in compliance_events:
            self.database.store_compliance_event(event)

        return compliance_events

    async def _assess_sox_compliance(
        self, request: ExecutionRequest, result: ExecutionResult
    ) -> List[ComplianceEvent]:
        """Assess SOX compliance requirements"""
        events = []

        # ITGC-CM02: Code execution controls
        if request.risk_assessment.risk_level in [
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
            RiskLevel.EXTREME,
        ]:
            if request.risk_assessment.approval_level == ApprovalLevel.AUTOMATIC:
                events.append(
                    ComplianceEvent(
                        event_id=f"sox_cm02_{request.request_id}",
                        framework=ComplianceFramework.SOX,
                        control_id="ITGC-CM02",
                        control_description=self.sox_controls["ITGC-CM02"],
                        compliance_status="NON_COMPLIANT",
                        violation_details=[
                            "High-risk code execution without proper approval controls",
                            f"Risk level: {request.risk_assessment.risk_level.value}",
                            f"Approval level: {request.risk_assessment.approval_level.value}",
                        ],
                        remediation_actions=[
                            "Implement multi-level approval for high-risk code execution",
                            "Enhance risk assessment procedures",
                            "Document approval workflows",
                        ],
                        responsible_party="IT Security Team",
                    )
                )

        # ITGC-AC01: Logical access controls
        if not request.security_context.audit_required:
            events.append(
                ComplianceEvent(
                    event_id=f"sox_ac01_{request.request_id}",
                    framework=ComplianceFramework.SOX,
                    control_id="ITGC-AC01",
                    control_description=self.sox_controls["ITGC-AC01"],
                    compliance_status="NON_COMPLIANT",
                    violation_details=[
                        "Code execution without proper audit trail",
                        f"User: {request.security_context.user_id}",
                        "Audit not required for execution",
                    ],
                    remediation_actions=[
                        "Enable audit requirements for all code execution",
                        "Implement comprehensive logging",
                        "Review access control policies",
                    ],
                    responsible_party="Compliance Team",
                )
            )

        return events

    async def _assess_gdpr_compliance(
        self, request: ExecutionRequest, result: ExecutionResult
    ) -> List[ComplianceEvent]:
        """Assess GDPR compliance requirements"""
        events = []

        # Check for personal data processing
        code_lower = request.code.lower()
        personal_data_indicators = [
            "email",
            "name",
            "address",
            "phone",
            "ssn",
            "personal",
            "user_data",
        ]

        if any(indicator in code_lower for indicator in personal_data_indicators):
            # GDPR-ART32: Security of processing
            if request.risk_assessment.security_level.value not in [
                "secret",
                "top_secret",
            ]:
                events.append(
                    ComplianceEvent(
                        event_id=f"gdpr_art32_{request.request_id}",
                        framework=ComplianceFramework.GDPR,
                        control_id="GDPR-ART32",
                        control_description=self.gdpr_controls["GDPR-ART32"],
                        compliance_status="NON_COMPLIANT",
                        violation_details=[
                            "Personal data processing without adequate security measures",
                            f"Security level: {request.risk_assessment.security_level.value}",
                            "Personal data indicators detected in code",
                        ],
                        remediation_actions=[
                            "Implement higher security controls for personal data processing",
                            "Conduct data protection impact assessment",
                            "Review data processing lawfulness",
                        ],
                        responsible_party="Data Protection Officer",
                    )
                )

        return events

    async def _assess_hipaa_compliance(
        self, request: ExecutionRequest, result: ExecutionResult
    ) -> List[ComplianceEvent]:
        """Assess HIPAA compliance requirements"""
        events = []

        # Check for healthcare data processing
        code_lower = request.code.lower()
        health_indicators = [
            "medical",
            "health",
            "patient",
            "diagnosis",
            "treatment",
            "hipaa",
            "phi",
        ]

        if any(indicator in code_lower for indicator in health_indicators):
            # HIPAA-164.312: Technical safeguards
            if request.execution_environment != ExecutionEnvironment.SANDBOXED:
                events.append(
                    ComplianceEvent(
                        event_id=f"hipaa_164312_{request.request_id}",
                        framework=ComplianceFramework.HIPAA,
                        control_id="HIPAA-164.312",
                        control_description=self.hipaa_controls["HIPAA-164.312"],
                        compliance_status="NON_COMPLIANT",
                        violation_details=[
                            "Healthcare data processing without proper technical safeguards",
                            f"Execution environment: {request.execution_environment.value}",
                            "Healthcare indicators detected in code",
                        ],
                        remediation_actions=[
                            "Use sandboxed execution environment for healthcare data",
                            "Implement encryption for PHI processing",
                            "Conduct HIPAA risk assessment",
                        ],
                        responsible_party="HIPAA Security Officer",
                    )
                )

        return events

    async def _assess_pci_dss_compliance(
        self, request: ExecutionRequest, result: ExecutionResult
    ) -> List[ComplianceEvent]:
        """Assess PCI DSS compliance requirements"""
        events = []

        # Check for payment card data processing
        code_lower = request.code.lower()
        payment_indicators = [
            "card",
            "credit",
            "payment",
            "cvv",
            "pan",
            "expiry",
            "cardholder",
        ]

        if any(indicator in code_lower for indicator in payment_indicators):
            # PCI-REQ6: Develop and maintain secure systems
            if request.risk_assessment.risk_level != RiskLevel.MINIMAL:
                events.append(
                    ComplianceEvent(
                        event_id=f"pci_req6_{request.request_id}",
                        framework=ComplianceFramework.PCI_DSS,
                        control_id="PCI-REQ6",
                        control_description=self.pci_dss_controls["PCI-REQ6"],
                        compliance_status="NON_COMPLIANT",
                        violation_details=[
                            "Payment card data processing with security risks",
                            f"Risk level: {request.risk_assessment.risk_level.value}",
                            "Payment indicators detected in code",
                        ],
                        remediation_actions=[
                            "Implement secure coding practices for payment processing",
                            "Conduct vulnerability assessment",
                            "Review PCI DSS compliance requirements",
                        ],
                        responsible_party="PCI DSS Compliance Manager",
                    )
                )

        return events


class EnterpriseAlertingSystem:
    """Enterprise alerting and notification system"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger("EnterpriseAlertingSystem")

        # Email configuration
        self.smtp_server = self.config.get("smtp_server", "localhost")
        self.smtp_port = self.config.get("smtp_port", 587)
        self.smtp_username = self.config.get("smtp_username")
        self.smtp_password = self.config.get("smtp_password")
        self.from_email = self.config.get("from_email", "security@company.com")

        # Alert recipients
        self.security_team = self.config.get("security_team_emails", [])
        self.compliance_team = self.config.get("compliance_team_emails", [])
        self.executive_team = self.config.get("executive_team_emails", [])

        # Webhook configuration
        self.webhook_urls = self.config.get("webhook_urls", [])

        self.session = requests.Session()
        self.logger.info("Enterprise alerting system initialized")

    async def send_security_alert(self, alert: SecurityAlert):
        """Send security alert through multiple channels"""
        # Send email alerts
        await self._send_email_alert(alert)

        # Send webhook notifications
        await self._send_webhook_alert(alert)

        # Send Slack/Teams notifications if configured
        if self.config.get("slack_webhook"):
            await self._send_slack_alert(alert)

        if self.config.get("teams_webhook"):
            await self._send_teams_alert(alert)

    async def _send_email_alert(self, alert: SecurityAlert):
        """Send security alert via email"""
        try:
            # Determine recipients based on severity
            recipients = []
            if alert.severity in [AlertSeverity.INFO, AlertSeverity.LOW]:
                recipients = self.security_team
            elif alert.severity in [AlertSeverity.MEDIUM, AlertSeverity.HIGH]:
                recipients = self.security_team + self.compliance_team
            elif alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]:
                recipients = (
                    self.security_team + self.compliance_team + self.executive_team
                )

            if not recipients:
                return

            # Create email message
            subject = f"[{alert.severity.value.upper()}] Security Alert: {alert.title}"

            html_body = f"""
            <html>
            <body>
                <h2 style="color: {'red' if alert.severity.value in ['critical', 'emergency'] else 'orange'};">
                    Security Alert: {alert.title}
                </h2>

                <h3>Alert Details</h3>
                <table border="1" style="border-collapse: collapse;">
                    <tr><td><strong>Alert ID</strong></td><td>{alert.alert_id}</td></tr>
                    <tr><td><strong>Severity</strong></td><td>{alert.severity.value.upper()}</td></tr>
                    <tr><td><strong>Category</strong></td><td>{alert.category} / {alert.subcategory}</td></tr>
                    <tr><td><strong>Risk Score</strong></td><td>{alert.risk_score}</td></tr>
                    <tr><td><strong>Confidence</strong></td><td>{alert.confidence * 100:.1f}%</td></tr>
                    <tr><td><strong>Created</strong></td><td>{alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
                </table>

                <h3>Description</h3>
                <p>{alert.description}</p>

                <h3>Threat Indicators</h3>
                <ul>
                {"".join(f"<li>{indicator}</li>" for indicator in alert.threat_indicators)}
                </ul>

                <h3>Affected Assets</h3>
                <ul>
                {"".join(f"<li>{asset}</li>" for asset in alert.affected_assets)}
                </ul>

                <h3>Compliance Violations</h3>
                <ul>
                {"".join(f"<li>{violation}</li>" for violation in alert.compliance_violations)}
                </ul>

                <h3>Recommended Actions</h3>
                <ol>
                {"".join(f"<li>{action}</li>" for action in alert.recommended_actions)}
                </ol>

                <p><em>This is an automated security alert from Open Interpreter Enterprise Security System.</em></p>
            </body>
            </html>
            """

            # Send email to all recipients
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._send_email(recipients, subject, html_body)
            )

            self.logger.info(
                f"Security alert email sent to {len(recipients)} recipients"
            )

        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")

    def _send_email(self, recipients: List[str], subject: str, html_body: str):
        """Send email using SMTP"""
        try:
            msg = MimeMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = ", ".join(recipients)

            html_part = MimeText(html_body, "html")
            msg.attach(html_part)

            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)

        except Exception as e:
            self.logger.error(f"SMTP send failed: {e}")

    async def _send_webhook_alert(self, alert: SecurityAlert):
        """Send alert via webhook"""
        webhook_payload = {
            "alert_id": alert.alert_id,
            "severity": alert.severity.value,
            "title": alert.title,
            "description": alert.description,
            "category": alert.category,
            "subcategory": alert.subcategory,
            "risk_score": alert.risk_score,
            "confidence": alert.confidence,
            "threat_indicators": alert.threat_indicators,
            "affected_assets": alert.affected_assets,
            "compliance_violations": alert.compliance_violations,
            "recommended_actions": alert.recommended_actions,
            "created_at": alert.created_at.isoformat(),
            "source": "open_interpreter_enterprise",
        }

        for webhook_url in self.webhook_urls:
            try:
                response = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.session.post(
                        webhook_url,
                        json=webhook_payload,
                        timeout=30,
                        headers={"Content-Type": "application/json"},
                    ),
                )

                if response.status_code == 200:
                    self.logger.info(
                        f"Webhook alert sent successfully to {webhook_url}"
                    )
                else:
                    self.logger.warning(f"Webhook alert failed: {response.status_code}")

            except Exception as e:
                self.logger.error(f"Webhook send failed for {webhook_url}: {e}")

    async def _send_slack_alert(self, alert: SecurityAlert):
        """Send alert to Slack"""
        try:
            color_map = {
                AlertSeverity.INFO: "good",
                AlertSeverity.LOW: "good",
                AlertSeverity.MEDIUM: "warning",
                AlertSeverity.HIGH: "danger",
                AlertSeverity.CRITICAL: "danger",
                AlertSeverity.EMERGENCY: "danger",
            }

            slack_payload = {
                "attachments": [
                    {
                        "color": color_map.get(alert.severity, "warning"),
                        "title": f"Security Alert: {alert.title}",
                        "fields": [
                            {
                                "title": "Severity",
                                "value": alert.severity.value.upper(),
                                "short": True,
                            },
                            {
                                "title": "Risk Score",
                                "value": str(alert.risk_score),
                                "short": True,
                            },
                            {
                                "title": "Category",
                                "value": f"{alert.category}/{alert.subcategory}",
                                "short": True,
                            },
                            {
                                "title": "Alert ID",
                                "value": alert.alert_id,
                                "short": True,
                            },
                            {
                                "title": "Description",
                                "value": alert.description,
                                "short": False,
                            },
                        ],
                        "footer": "Open Interpreter Enterprise Security",
                        "ts": int(alert.created_at.timestamp()),
                    }
                ]
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(
                    self.config.get("slack_webhook"), json=slack_payload, timeout=30
                ),
            )

            if response.status_code == 200:
                self.logger.info("Slack alert sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")

    async def _send_teams_alert(self, alert: SecurityAlert):
        """Send alert to Microsoft Teams"""
        try:
            teams_payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": f"Security Alert: {alert.title}",
                "themeColor": (
                    "FF0000"
                    if alert.severity.value in ["critical", "emergency"]
                    else "FFA500"
                ),
                "sections": [
                    {
                        "activityTitle": f"**Security Alert: {alert.title}**",
                        "activitySubtitle": f"Severity: {alert.severity.value.upper()}",
                        "facts": [
                            {"name": "Alert ID", "value": alert.alert_id},
                            {"name": "Risk Score", "value": str(alert.risk_score)},
                            {
                                "name": "Category",
                                "value": f"{alert.category}/{alert.subcategory}",
                            },
                            {
                                "name": "Created",
                                "value": alert.created_at.strftime(
                                    "%Y-%m-%d %H:%M:%S UTC"
                                ),
                            },
                        ],
                        "text": alert.description,
                    }
                ],
            }

            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.session.post(
                    self.config.get("teams_webhook"), json=teams_payload, timeout=30
                ),
            )

            if response.status_code == 200:
                self.logger.info("Teams alert sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send Teams alert: {e}")


class EnterpriseSecurityOrchestrator:
    """
    Main orchestrator for enterprise security integration

    Coordinates all enterprise security components including database,
    SIEM integration, compliance reporting, and alerting systems.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger("EnterpriseSecurityOrchestrator")

        # Initialize components
        self.database = EnterpriseSecurityDatabase(
            self.config.get("database_path", "enterprise_security.db")
        )

        self.siem_integration = SIEMIntegration(self.config.get("siem", {}))
        self.compliance_engine = ComplianceReportingEngine(self.database)
        self.alerting_system = EnterpriseAlertingSystem(self.config.get("alerting", {}))

        # Performance metrics
        self.metrics = {
            "alerts_generated": 0,
            "compliance_events": 0,
            "siem_events_sent": 0,
            "database_operations": 0,
        }

        self.logger.info("Enterprise Security Orchestrator initialized")

    async def process_security_event(
        self,
        request: ExecutionRequest,
        result: ExecutionResult,
        approval_result: Dict[str, Any],
        parlant_validation: Dict[str, Any],
    ):
        """
        Process comprehensive security event through enterprise security pipeline

        Args:
            request: Code execution request
            result: Execution result
            approval_result: Approval workflow result
            parlant_validation: Parlant validation result
        """
        try:
            # Step 1: Store execution audit in database
            self.database.store_execution_audit(
                request, result, approval_result["approved"], parlant_validation
            )
            self.metrics["database_operations"] += 1

            # Step 2: Assess compliance violations
            compliance_events = await self.compliance_engine.assess_compliance(
                request, result
            )
            self.metrics["compliance_events"] += len(compliance_events)

            # Step 3: Generate security alerts based on risk and compliance
            security_alerts = await self._generate_security_alerts(
                request, result, compliance_events, approval_result, parlant_validation
            )

            # Step 4: Send alerts through enterprise alerting system
            for alert in security_alerts:
                await self.alerting_system.send_security_alert(alert)
                self.database.store_security_alert(alert)
                self.metrics["alerts_generated"] += 1

            # Step 5: Send events to SIEM systems
            siem_events = self._create_siem_events(
                request, result, compliance_events, security_alerts
            )
            for siem_event in siem_events:
                await self.siem_integration.send_security_event(siem_event)
                self.database.store_siem_event(siem_event)
                self.metrics["siem_events_sent"] += 1

            self.logger.info(
                f"Security event processed: {request.request_id}",
                extra={
                    "alerts_generated": len(security_alerts),
                    "compliance_events": len(compliance_events),
                    "siem_events": len(siem_events),
                },
            )

        except Exception as e:
            self.logger.error(f"Failed to process security event: {e}")

            # Generate critical alert for processing failure
            failure_alert = SecurityAlert(
                alert_id=f"processing_failure_{int(time.time())}",
                severity=AlertSeverity.HIGH,
                title="Security Event Processing Failure",
                description=f"Failed to process security event for request {request.request_id}: {e}",
                threat_indicators=["security_system_failure"],
                recommended_actions=[
                    "Investigate security system health",
                    "Review system logs",
                ],
            )

            await self.alerting_system.send_security_alert(failure_alert)

    async def _generate_security_alerts(
        self,
        request: ExecutionRequest,
        result: ExecutionResult,
        compliance_events: List[ComplianceEvent],
        approval_result: Dict[str, Any],
        parlant_validation: Dict[str, Any],
    ) -> List[SecurityAlert]:
        """Generate security alerts based on execution analysis"""
        alerts = []

        # High-risk execution alert
        if request.risk_assessment.risk_level in [
            RiskLevel.CRITICAL,
            RiskLevel.EXTREME,
        ]:
            alerts.append(
                SecurityAlert(
                    alert_id=f"high_risk_execution_{request.request_id}",
                    severity=(
                        AlertSeverity.HIGH
                        if request.risk_assessment.risk_level == RiskLevel.CRITICAL
                        else AlertSeverity.CRITICAL
                    ),
                    title="High-Risk Code Execution Detected",
                    description=f"Code execution with {request.risk_assessment.risk_level.value} risk level detected",
                    risk_score=len(request.risk_assessment.risk_factors) * 10,
                    confidence=request.risk_assessment.confidence_score,
                    threat_indicators=request.risk_assessment.threat_indicators,
                    affected_assets=[request.security_context.user_id],
                    recommended_actions=[
                        "Review code execution approval process",
                        "Investigate user activity",
                        "Enhance monitoring for similar patterns",
                    ],
                    raw_data={
                        "request_id": request.request_id,
                        "user_id": request.security_context.user_id,
                        "risk_factors": request.risk_assessment.risk_factors,
                        "code_hash": hashlib.sha256(request.code.encode()).hexdigest(),
                    },
                )
            )

        # Execution failure alert
        if not result.success:
            alerts.append(
                SecurityAlert(
                    alert_id=f"execution_failure_{request.request_id}",
                    severity=AlertSeverity.MEDIUM,
                    title="Code Execution Failed",
                    description=f"Code execution failed: {result.error}",
                    risk_score=30,
                    confidence=0.9,
                    threat_indicators=["execution_failure"],
                    affected_assets=[request.security_context.user_id],
                    recommended_actions=[
                        "Investigate execution failure cause",
                        "Review system security status",
                        "Check for potential attack indicators",
                    ],
                    raw_data={
                        "request_id": request.request_id,
                        "error": result.error,
                        "exit_code": result.exit_code,
                    },
                )
            )

        # Security events alert
        if result.security_events:
            alerts.append(
                SecurityAlert(
                    alert_id=f"security_events_{request.request_id}",
                    severity=AlertSeverity.HIGH,
                    title="Security Events During Code Execution",
                    description=f"{len(result.security_events)} security events detected during execution",
                    risk_score=len(result.security_events) * 15,
                    confidence=0.8,
                    threat_indicators=[
                        event.get("type", "unknown") for event in result.security_events
                    ],
                    affected_assets=[request.security_context.user_id],
                    recommended_actions=[
                        "Investigate security events",
                        "Review execution environment integrity",
                        "Enhance security monitoring",
                    ],
                    raw_data={
                        "request_id": request.request_id,
                        "security_events": result.security_events,
                    },
                )
            )

        # Compliance violations alert
        if compliance_events:
            non_compliant_events = [
                e for e in compliance_events if e.compliance_status == "NON_COMPLIANT"
            ]
            if non_compliant_events:
                alerts.append(
                    SecurityAlert(
                        alert_id=f"compliance_violation_{request.request_id}",
                        severity=AlertSeverity.HIGH,
                        title="Compliance Violations Detected",
                        description=f"{len(non_compliant_events)} compliance violations detected",
                        risk_score=len(non_compliant_events) * 20,
                        confidence=0.9,
                        threat_indicators=["compliance_violation"],
                        compliance_violations=[
                            f"{e.framework.value}:{e.control_id}"
                            for e in non_compliant_events
                        ],
                        recommended_actions=[
                            "Address compliance violations immediately",
                            "Review compliance controls",
                            "Implement corrective measures",
                        ],
                        raw_data={
                            "request_id": request.request_id,
                            "violations": [
                                {
                                    "framework": e.framework.value,
                                    "control_id": e.control_id,
                                    "violation_details": e.violation_details,
                                }
                                for e in non_compliant_events
                            ],
                        },
                    )
                )

        # Parlant validation blocked alert
        if not parlant_validation.get("approved", True):
            alerts.append(
                SecurityAlert(
                    alert_id=f"parlant_blocked_{request.request_id}",
                    severity=AlertSeverity.MEDIUM,
                    title="Code Execution Blocked by AI Validation",
                    description=f"Parlant AI blocked code execution: {parlant_validation.get('reasoning', 'Unknown reason')}",
                    risk_score=40,
                    confidence=parlant_validation.get("confidence", 0.5),
                    threat_indicators=["ai_validation_blocked"],
                    recommended_actions=[
                        "Review blocked code for security risks",
                        "Validate AI reasoning accuracy",
                        "Update security policies if needed",
                    ],
                    raw_data={
                        "request_id": request.request_id,
                        "parlant_reasoning": parlant_validation.get("reasoning", ""),
                        "parlant_confidence": parlant_validation.get("confidence", 0.0),
                    },
                )
            )

        return alerts

    def _create_siem_events(
        self,
        request: ExecutionRequest,
        result: ExecutionResult,
        compliance_events: List[ComplianceEvent],
        security_alerts: List[SecurityAlert],
    ) -> List[SIEMEvent]:
        """Create SIEM events for security monitoring"""
        siem_events = []

        # Primary execution event
        siem_events.append(
            SIEMEvent(
                event_id=f"code_execution_{request.request_id}",
                timestamp=result.executed_at,
                user_id=request.security_context.user_id,
                session_id=request.security_context.session_id,
                event_type="code_execution",
                event_category="security_validation",
                severity=self._map_risk_to_alert_severity(
                    request.risk_assessment.risk_level
                ),
                outcome="success" if result.success else "failure",
                message=f"Code execution {('completed' if result.success else 'failed')} with {request.risk_assessment.risk_level.value} risk",
                details={
                    "request_id": request.request_id,
                    "language": request.language,
                    "risk_level": request.risk_assessment.risk_level.value,
                    "security_level": request.risk_assessment.security_level.value,
                    "approval_level": request.risk_assessment.approval_level.value,
                    "execution_time": result.execution_time,
                    "exit_code": result.exit_code,
                    "risk_factors_count": len(request.risk_assessment.risk_factors),
                    "threat_indicators_count": len(
                        request.risk_assessment.threat_indicators
                    ),
                    "files_created": len(result.files_created),
                    "files_modified": len(result.files_modified),
                    "network_connections": len(result.network_connections),
                    "security_events_count": len(result.security_events),
                },
                tags=[
                    "open_interpreter",
                    "code_execution",
                    "security_validation",
                    request.risk_assessment.risk_level.value,
                ],
            )
        )

        # Compliance events
        for compliance_event in compliance_events:
            if compliance_event.compliance_status == "NON_COMPLIANT":
                siem_events.append(
                    SIEMEvent(
                        event_id=f"compliance_violation_{compliance_event.event_id}",
                        timestamp=compliance_event.created_at,
                        user_id=request.security_context.user_id,
                        session_id=request.security_context.session_id,
                        event_type="compliance_violation",
                        event_category="compliance",
                        severity=AlertSeverity.HIGH,
                        outcome="failure",
                        message=f"Compliance violation: {compliance_event.framework.value} {compliance_event.control_id}",
                        details={
                            "framework": compliance_event.framework.value,
                            "control_id": compliance_event.control_id,
                            "control_description": compliance_event.control_description,
                            "violation_details": compliance_event.violation_details,
                            "responsible_party": compliance_event.responsible_party,
                        },
                        tags=[
                            "compliance",
                            "violation",
                            compliance_event.framework.value.lower(),
                        ],
                    )
                )

        # Security alert events
        for alert in security_alerts:
            siem_events.append(
                SIEMEvent(
                    event_id=f"security_alert_{alert.alert_id}",
                    timestamp=alert.created_at,
                    user_id=request.security_context.user_id,
                    session_id=request.security_context.session_id,
                    event_type="security_alert",
                    event_category="alert",
                    severity=alert.severity,
                    outcome="alert_generated",
                    message=alert.title,
                    details={
                        "alert_id": alert.alert_id,
                        "description": alert.description,
                        "risk_score": alert.risk_score,
                        "confidence": alert.confidence,
                        "threat_indicators": alert.threat_indicators,
                        "affected_assets": alert.affected_assets,
                        "compliance_violations": alert.compliance_violations,
                    },
                    tags=[
                        "security_alert",
                        alert.category,
                        alert.subcategory,
                        alert.severity.value,
                    ],
                )
            )

        return siem_events

    def _map_risk_to_alert_severity(self, risk_level: RiskLevel) -> AlertSeverity:
        """Map risk level to alert severity"""
        mapping = {
            RiskLevel.MINIMAL: AlertSeverity.INFO,
            RiskLevel.LOW: AlertSeverity.LOW,
            RiskLevel.MEDIUM: AlertSeverity.MEDIUM,
            RiskLevel.HIGH: AlertSeverity.HIGH,
            RiskLevel.CRITICAL: AlertSeverity.CRITICAL,
            RiskLevel.EXTREME: AlertSeverity.EMERGENCY,
        }
        return mapping.get(risk_level, AlertSeverity.MEDIUM)

    def get_enterprise_metrics(self) -> Dict[str, Any]:
        """Get comprehensive enterprise security metrics"""
        return {
            "orchestrator_metrics": self.metrics,
            "database_path": self.database.db_path,
            "siem_integrations": {
                "splunk": bool(self.siem_integration.splunk_endpoint),
                "qradar": bool(self.siem_integration.qradar_endpoint),
                "sentinel": bool(self.siem_integration.sentinel_endpoint),
                "arcsight": bool(self.siem_integration.arcsight_endpoint),
            },
            "alerting_channels": {
                "email": bool(self.alerting_system.security_team),
                "slack": bool(self.config.get("alerting", {}).get("slack_webhook")),
                "teams": bool(self.config.get("alerting", {}).get("teams_webhook")),
                "webhooks": len(self.alerting_system.webhook_urls),
            },
            "compliance_frameworks": ["SOX", "GDPR", "HIPAA", "PCI_DSS"],
            "timestamp": datetime.now().isoformat(),
        }

    async def generate_executive_report(
        self, start_date: datetime, end_date: datetime
    ) -> Dict[str, Any]:
        """Generate executive-level security report"""
        # Get compliance reports for all frameworks
        sox_report = self.database.get_compliance_report(
            ComplianceFramework.SOX, start_date, end_date
        )
        gdpr_report = self.database.get_compliance_report(
            ComplianceFramework.GDPR, start_date, end_date
        )
        hipaa_report = self.database.get_compliance_report(
            ComplianceFramework.HIPAA, start_date, end_date
        )
        pci_report = self.database.get_compliance_report(
            ComplianceFramework.PCI_DSS, start_date, end_date
        )

        return {
            "report_type": "executive_security_summary",
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
            },
            "executive_summary": {
                "total_code_executions": self.metrics["database_operations"],
                "security_alerts_generated": self.metrics["alerts_generated"],
                "compliance_events": self.metrics["compliance_events"],
                "siem_events_sent": self.metrics["siem_events_sent"],
            },
            "compliance_summary": {
                "sox_compliance_rate": sox_report.get("summary", {}).get(
                    "compliance_rate", 0
                ),
                "gdpr_compliance_rate": gdpr_report.get("summary", {}).get(
                    "compliance_rate", 0
                ),
                "hipaa_compliance_rate": hipaa_report.get("summary", {}).get(
                    "compliance_rate", 0
                ),
                "pci_dss_compliance_rate": pci_report.get("summary", {}).get(
                    "compliance_rate", 0
                ),
            },
            "detailed_compliance": {
                "sox": sox_report,
                "gdpr": gdpr_report,
                "hipaa": hipaa_report,
                "pci_dss": pci_report,
            },
            "recommendations": [
                "Continue monitoring for high-risk code execution patterns",
                "Review and update compliance control mappings quarterly",
                "Enhance SIEM integration for better threat visibility",
                "Conduct regular security awareness training for development teams",
            ],
            "generated_at": datetime.now().isoformat(),
            "generated_by": "Open Interpreter Enterprise Security Orchestrator",
        }


# Global enterprise security orchestrator instance
_enterprise_orchestrator: Optional[EnterpriseSecurityOrchestrator] = None


def get_enterprise_security_orchestrator(
    config: Dict[str, Any] = None
) -> EnterpriseSecurityOrchestrator:
    """Get global enterprise security orchestrator (singleton pattern)"""
    global _enterprise_orchestrator
    if _enterprise_orchestrator is None:
        _enterprise_orchestrator = EnterpriseSecurityOrchestrator(config)
    return _enterprise_orchestrator


# Export key classes and functions
__all__ = [
    "EnterpriseSecurityOrchestrator",
    "EnterpriseSecurityDatabase",
    "SIEMIntegration",
    "ComplianceReportingEngine",
    "EnterpriseAlertingSystem",
    "SecurityAlert",
    "ComplianceEvent",
    "SIEMEvent",
    "ComplianceFramework",
    "AlertSeverity",
    "IntegrationProtocol",
    "get_enterprise_security_orchestrator",
]
