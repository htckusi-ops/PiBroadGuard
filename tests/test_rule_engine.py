"""Tests für den Rule Engine."""
import pytest
from app.services.rule_engine import apply_rules, load_rules


SAMPLE_RULES = [
    {
        "rule_key": "telnet_open",
        "title": "Telnet aktiv",
        "description": "Telnet unsicher",
        "condition": {"type": "port_open", "port": 23},
        "severity": "high",
        "broadcast_context": "Kontext",
        "recommendation": "Deaktivieren",
        "ask_compensation": True,
        "affects_score": "technical",
    },
    {
        "rule_key": "snmp_udp",
        "title": "SNMP UDP",
        "description": "SNMP unsicher",
        "condition": {"type": "port_open", "port": 161, "protocol": "udp"},
        "severity": "medium",
        "broadcast_context": "Kontext",
        "recommendation": "SNMPv3",
        "ask_compensation": True,
        "affects_score": "technical",
    },
    {
        "rule_key": "no_lifecycle",
        "title": "Kein Lifecycle",
        "description": "EOL unbekannt",
        "condition": {"type": "manual_answer", "question_key": "lifecycle_documented", "answer": "no"},
        "severity": "medium",
        "broadcast_context": "Kontext",
        "recommendation": "Anfragen",
        "ask_compensation": False,
        "affects_score": "lifecycle",
    },
]


def test_port_open_tcp():
    scan_results = [{"port": 23, "protocol": "tcp", "state": "open"}]
    triggered = apply_rules(SAMPLE_RULES, scan_results, {})
    assert len(triggered) == 1
    assert triggered[0]["rule_key"] == "telnet_open"


def test_port_open_udp():
    scan_results = [{"port": 161, "protocol": "udp", "state": "open"}]
    triggered = apply_rules(SAMPLE_RULES, scan_results, {})
    assert len(triggered) == 1
    assert triggered[0]["rule_key"] == "snmp_udp"


def test_no_match_closed_port():
    scan_results = [{"port": 23, "protocol": "tcp", "state": "closed"}]
    triggered = apply_rules(SAMPLE_RULES, scan_results, {})
    assert len(triggered) == 0


def test_manual_answer():
    triggered = apply_rules(SAMPLE_RULES, [], {"lifecycle_documented": "no"})
    assert len(triggered) == 1
    assert triggered[0]["rule_key"] == "no_lifecycle"


def test_manual_answer_no_match():
    triggered = apply_rules(SAMPLE_RULES, [], {"lifecycle_documented": "yes"})
    assert len(triggered) == 0


def test_multiple_findings():
    scan_results = [{"port": 23, "protocol": "tcp", "state": "open"}]
    triggered = apply_rules(SAMPLE_RULES, scan_results, {"lifecycle_documented": "no"})
    assert len(triggered) == 2


def test_load_rules():
    """Test that default rules load without error."""
    import os
    if not os.path.exists("./app/rules/default_rules.yaml"):
        pytest.skip("Rules file not found (run from project root)")
    rules = load_rules()
    assert len(rules) > 0
    for rule in rules:
        assert "rule_key" in rule
        assert "severity" in rule
        assert "condition" in rule
