import logging
import yaml
from pathlib import Path
from typing import List, Dict, Any

from app.core.config import settings

logger = logging.getLogger("pibroadguard.rule_engine")

QUESTION_CATALOG = {
    "auth": [
        {"key": "default_creds_exist", "question": "Gibt es Default-Credentials?"},
        {"key": "default_creds_changeable", "question": "Können Default-Credentials geändert werden?"},
        {"key": "individual_accounts", "question": "Können individuelle Benutzer erstellt werden?"},
        {"key": "roles_available", "question": "Gibt es ein Rollen-/Rechtekonzept?"},
        {"key": "mfa_possible", "question": "Ist MFA möglich?"},
        {"key": "central_auth_possible", "question": "Ist zentrale Authentisierung möglich (LDAP/AD)?"},
    ],
    "patch": [
        {"key": "firmware_updatable", "question": "Ist Firmware aktualisierbar?"},
        {"key": "security_updates_available", "question": "Gibt es separate Security-Updates?"},
        {"key": "security_advisories", "question": "Gibt es Security Advisories vom Hersteller?"},
        {"key": "lifecycle_documented", "question": "Ist das EOL/EOS-Datum dokumentiert?"},
        {"key": "update_without_downtime", "question": "Ist Update ohne grossen Produktionsunterbruch möglich?"},
    ],
    "hardening": [
        {"key": "unnecessary_services_disableable", "question": "Können unnötige Dienste deaktiviert werden?"},
        {"key": "web_interface_disableable", "question": "Kann das Webinterface deaktiviert/abgesichert werden?"},
        {"key": "insecure_protocols_disableable", "question": "Können unsichere Protokolle deaktiviert werden?"},
        {"key": "certificates_replaceable", "question": "Können Zertifikate ersetzt werden?"},
        {"key": "tls_configurable", "question": "Sind TLS-Version und Cipher konfigurierbar?"},
    ],
    "monitoring": [
        {"key": "syslog_supported", "question": "Unterstützt das Gerät Syslog-Export?"},
        {"key": "snmpv3_supported", "question": "Ist SNMPv3 verfügbar?"},
        {"key": "login_logging", "question": "Werden Logins protokolliert?"},
        {"key": "config_change_logging", "question": "Werden Konfigurationsänderungen protokolliert?"},
    ],
    "operational": [
        {"key": "production_critical", "question": "Ist das Gerät für Live-Produktion kritisch?"},
        {"key": "redundancy_available", "question": "Ist Redundanz vorhanden?"},
        {"key": "fallback_possible", "question": "Ist ein Fallback möglich?"},
        {"key": "management_vlan_possible", "question": "Kann das Gerät in ein Management-VLAN gestellt werden?"},
        {"key": "legacy_services_required", "question": "Gibt es betriebsnotwendige Legacy-Dienste?"},
    ],
    "vendor": [
        {"key": "psirt_available", "question": "Gibt es ein PSIRT oder Security-Kontakt?"},
        {"key": "hardening_guide_available", "question": "Gibt es ein Hardening-Guide?"},
        {"key": "security_roadmap", "question": "Gibt es eine nachvollziehbare Security-Roadmap?"},
    ],
}


def load_rules() -> List[Dict[str, Any]]:
    path = Path(settings.pibg_rules_path)
    if not path.exists():
        logger.warning(f"Rules file not found at {path}")
        return []
    with open(path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    logger.info(f"Loaded {len(rules)} rules from {path}")
    return rules or []


def apply_rules(
    rules: List[Dict[str, Any]],
    scan_results: List[Dict[str, Any]],
    manual_findings: Dict[str, str],
) -> List[Dict[str, Any]]:
    open_ports_tcp: set[int] = set()
    open_ports_udp: set[int] = set()

    for sr in scan_results:
        if sr.get("state") in ("open", "filtered"):
            port = sr.get("port")
            proto = sr.get("protocol", "tcp")
            if port:
                if proto == "udp":
                    open_ports_udp.add(port)
                else:
                    open_ports_tcp.add(port)

    triggered: List[Dict[str, Any]] = []

    for rule in rules:
        condition = rule.get("condition", {})
        ctype = condition.get("type")
        matched = False
        evidence = ""

        if ctype == "port_open":
            port = condition.get("port")
            proto = condition.get("protocol", "tcp")
            if proto == "udp":
                matched = port in open_ports_udp
            else:
                matched = port in open_ports_tcp
            if matched:
                evidence = f"Port {port}/{proto} open"

        elif ctype == "service_detected":
            service = condition.get("service", "").lower()
            for sr in scan_results:
                sn = (sr.get("service_name") or "").lower()
                sp = (sr.get("service_product") or "").lower()
                if service in sn or service in sp:
                    matched = True
                    evidence = f"Service '{service}' detected on port {sr.get('port')}/{sr.get('protocol')}"
                    break

        elif ctype == "manual_answer":
            qkey = condition.get("question_key")
            expected = condition.get("answer")
            actual = manual_findings.get(qkey)
            if actual is not None and actual.lower() == expected.lower():
                matched = True
                evidence = f"Manual answer: {qkey}={actual}"

        if matched:
            triggered.append({
                "rule_key": rule.get("rule_key"),
                "title": rule.get("title"),
                "severity": rule.get("severity", "medium"),
                "description": rule.get("description", ""),
                "evidence": evidence,
                "recommendation": rule.get("recommendation", ""),
                "broadcast_context": rule.get("broadcast_context", ""),
                "compensating_control_required": rule.get("ask_compensation", False),
                "affects_score": rule.get("affects_score", "technical"),
            })

    logger.info(f"Rule engine triggered {len(triggered)} findings")
    return triggered
