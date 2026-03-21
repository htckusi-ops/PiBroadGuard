"""Tests für den Nmap Service (Parsing, IP-Validation)."""
import pytest
from app.services.nmap_service import _validate_ip, _parse_nmap_xml


def test_validate_valid_ip():
    assert _validate_ip("192.168.1.1") == "192.168.1.1"
    assert _validate_ip("10.0.0.1") == "10.0.0.1"
    assert _validate_ip("::1") == "::1"


def test_validate_invalid_ip():
    import ipaddress
    with pytest.raises(ValueError):
        _validate_ip("999.999.999.999")
    with pytest.raises(ValueError):
        _validate_ip("not-an-ip")
    with pytest.raises(ValueError):
        _validate_ip("192.168.1")


def test_parse_nmap_xml_open_port():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert len(results) == 2
    ports = {r["port"] for r in results}
    assert 22 in ports
    assert 80 in ports


def test_parse_nmap_xml_closed_port_excluded():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="closed"/>
        <service name="telnet"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert len(results) == 0


def test_parse_nmap_xml_service_details():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="udp" portid="161">
        <state state="open"/>
        <service name="snmp" product="net-snmp" version="5.9" extrainfo="v2c"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert len(results) == 1
    r = results[0]
    assert r["protocol"] == "udp"
    assert r["port"] == 161
    assert r["service_name"] == "snmp"
    assert r["service_product"] == "net-snmp"
    assert r["extra_info"] == "v2c"


def test_parse_nmap_xml_empty():
    xml = """<?xml version="1.0"?><nmaprun></nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert results == []


def test_parse_nmap_xml_filtered():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert len(results) == 1  # filtered is included
    assert results[0]["state"] == "filtered"
