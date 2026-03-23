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


def test_parser_finds_all_open_ports_including_open_filtered():
    """open|filtered state (common with firewalled hosts) must be included in results."""
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="8080">
        <state state="open|filtered"/>
        <service name="http-proxy"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed"/>
        <service name="abyss"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    ports = {r["port"] for r in results}
    assert 8080 in ports, "open|filtered port must be included"
    assert 22 in ports, "open port must be included"
    assert 9999 not in ports, "closed port must be excluded"


def test_parser_extracts_mac_address():
    """MAC address and vendor from nmap L2 scan must be extracted."""
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addrtype="ipv4" addr="192.168.1.10"/>
    <address addrtype="mac" addr="AA:BB:CC:DD:EE:FF" vendor="Grass Valley"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert len(results) == 1
    assert results[0]["mac_address"] == "AA:BB:CC:DD:EE:FF"
    assert results[0]["mac_vendor"] == "Grass Valley"


def test_parser_handles_host_down():
    """No results returned for a host that is down."""
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="down"/>
    <ports/>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert results == []


def test_parser_handles_empty_output_gracefully():
    """Empty or whitespace XML must return empty list without raising."""
    assert _parse_nmap_xml("") == []
    assert _parse_nmap_xml("   ") == []


def test_parser_handles_incomplete_vendor_data():
    """MAC address present but without vendor must still parse correctly."""
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addrtype="mac" addr="11:22:33:44:55:66"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
    results = _parse_nmap_xml(xml)
    assert len(results) == 1
    assert results[0]["mac_address"] == "11:22:33:44:55:66"
    assert results[0]["mac_vendor"] == ""  # no vendor attribute
