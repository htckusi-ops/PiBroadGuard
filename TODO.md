# PiBroadGuard – Geplante Erweiterungen / Roadmap

**Stand:** März 2026 | Basierend auf Fachexpertise zu EBU/AMWA/JT-NM/SMPTE-Standards und Vulnerability-Intelligence

---

## Priorität 1 – Kurzfristig (hoher Nutzen, überschaubarer Aufwand)

### 1.1 Regelwerk: Broadcast-spezifische Regeln erweitern (EBU R143/R148)

Neue Regeln in `app/rules/default_rules.yaml` auf Basis von EBU R143 (Hardening),
EBU R148 (Mindesttests), EBU R160 S1 (Schwachstellenprüfung) und AMWA BCP-003:

| rule_key | Port/Protokoll | Severity | Standard-Referenz |
|----------|----------------|----------|-------------------|
| `ptp_pdelay_open` | UDP 319 (PTP event) | medium | SMPTE ST 2059, JT-NM TR-1001-1 |
| `ptp_general_open` | UDP 320 (PTP general) | medium | SMPTE ST 2059 |
| `nmos_registry_http` | TCP 8080 (NMOS IS-04 ohne TLS) | medium | AMWA BCP-003 |
| `ssdp_open` | UDP 1900 (SSDP/UPnP) | low | EBU R143 §4.2 |
| `mdns_open` | UDP 5353 (mDNS) | info | JT-NM TR-1001-1 |
| `wsd_open` | TCP 5357 (WSD/WS-Discovery) | low | EBU R143 §4.2 |
| `bacnet_open` | UDP 47808 (BACnet) | high | IEC 62443 |

Neue manuelle Fragen (`QUESTION_CATALOG`) in neuen Kategorien:

**Kategorie `nmos`:**
- `nmos_is04_present` – Spricht das Gerät NMOS IS-04 (Discovery/Registration)?
- `nmos_is10_auth` – Ist NMOS IS-10 Authorization aktiviert?
- `nmos_tls_enabled` – Sind NMOS-Verbindungen via TLS/HTTPS gesichert (AMWA BCP-003)?
- `nmos_registry_address` – Welcher NMOS-Registry wird verwendet (Discovery-Risiko)?

**Kategorie `ptp_timing`:**
- `ptp_present` – Verwendet das Gerät PTP/IEEE 1588 oder ST 2059?
- `ptp_role` – Kann das Gerät als Grandmaster auftreten (Rogue-GM-Risiko)?
- `ptp_domain_locked` – Ist die PTP-Domain fixiert und validiert?
- `ptp_network_isolated` – Ist der PTP-Datenverkehr auf ein dediziertes Segment beschränkt?

**Kategorie `network_arch`:**
- `mgmt_media_separated` – Sind Management- und Media-Netz getrennt?
- `mgmt_vlan_enforced` – Wird Management-Zugang via VLAN/ACL erzwungen?
- `media_multicast_controlled` – Ist Multicast-Zugang kontrolliert (IGMPv3, IGMP-Snooping)?

### 1.2 NVD-Abfragen verbessern (CPE-basiert + hasKev-Filter)

In `app/services/cve_service.py`:

- **CPE-basierte Suche** statt nur `keywordSearch`: Präzisere Treffer durch strukturierte
  Produktidentifikation (`cpe:2.3:h:vendor:product:version:*`).
- **`hasKev=true`** als optionaler NVD-Filter: Direkt KEV-markierte CVEs priorisiert abfragen.
- **KEV-Zeitfilter**: `kevStartDate` / `kevEndDate` für zeitlich eingegrenzte KEV-Abfragen.
- **`isVulnerable=true`** mit CPE: Nur CVEs abfragen, für die das Gerät tatsächlich als
  verwundbar gilt.

Beispiel-URLs (dokumentiert in NVD API v2):
```
GET /cves/2.0?cpeName=cpe:2.3:h:lawo:mc2-56:*&isVulnerable
GET /cves/2.0?hasKev=true&keywordSearch=grass+valley
GET /cves/2.0?kevStartDate=2025-01-01T00:00:00.000Z&kevEndDate=2026-03-28T23:59:59.000Z
```

### 1.3 CISA ICS Advisories als zusätzliche Datenquelle

CISA publiziert ICS-spezifische Advisories (RSS + JSON) für industrielle Appliances –
Broadcast-Geräte passen oft in dieses Profil (embedded, appliance, web-managed).

- **RSS-URL:** `https://www.cisa.gov/uscert/ics/advisories`
- **Caching:** Täglich sync, lokal in neuer Tabelle `ics_advisory_cache`
- **Integration:** Bei CVE-Lookup prüfen ob eine ICS Advisory für Vendor/Product vorliegt
- **UI:** Neues Badge "⚠️ ICS Advisory" in Finding-Karten (ähnlich KEV-Badge)

### 1.4 Methodikreferenz im Report erweitern

In `app/templates/report.html.j2` und `report.md.j2` den Standards-Block erweitern:

| Standard | Relevanz |
|----------|----------|
| **EBU R143** | Security Requirements für vernetzte Broadcast-Geräte (Hardening-Katalog) |
| **EBU R148** | Mindesttests für Netzwerk-Sicherheit von Media Equipment |
| **EBU R160 S1** | Leitfaden für Basis- und vertiefte Schwachstellenprüfung an Broadcast-Geräten |
| **AMWA BCP-003-01** | TLS für NMOS APIs (Certificate Provisioning) |
| **AMWA BCP-003-02** | Authorization für NMOS APIs (OAuth2/JWT via IS-10) |
| **SMPTE ST 2110** | Professional Media over IP (Referenzrahmen) |
| **SMPTE ST 2059** | Synchronisation und PTP in Broadcast-Netzwerken |
| **JT-NM TR-1001-1** | Erwartetes Verhalten von ST-2110-Media-Nodes |

---

## Priorität 2 – Mittelfristig (signifikanter Mehrwert, grösserer Aufwand)

### 2.1 CSAF 2.0 Vendor Advisory Integration

CSAF (Common Security Advisory Framework) v2.0 ist ein maschinenlesbares Format
für Sicherheitshinweise. Einige Hersteller (Siemens, Bosch, Cisco) publizieren
bereits CSAF 2.0 Advisories.

- **Service:** `services/csaf_service.py`
- **Funktion:** URL eines CSAF-Dokuments einlesen, CVE-Zuordnungen extrahieren,
  Fixes und Workarounds als `remediation_sources` speichern
- **API:** `POST /api/v1/cve/csaf-import` – CSAF-URL oder Datei hochladen
- **Nutzen:** Strukturierte Herstellerempfehlungen direkt in Findings integrieren

### 2.2 Broadcast-spezifisches Risikogewichtungsmodell

Anpassung von `services/scoring_service.py` mit broadcast-spezifischen Überschreibungsregeln:

```python
BROADCAST_RISK_OVERRIDES = {
    # PTP/Timing-Risiken → erhöhte Kritikalität
    "ptp_role_grandmaster_possible": "critical_override",  # Rogue-GM-Risiko
    "ptp_domain_not_locked": "high_override",
    # Ungepatche Appliances mit langer Betriebsdauer
    "no_security_updates + lifecycle_score < 30": "lifecycle_penalty_extra",
    # Managementzugang ohne Segmentierung
    "mgmt_media_not_separated + telnet_open": "critical_override",
}
```

Begründung: In Broadcast-Umgebungen sind Timing-Angriffe (Rogue PTP Grandmaster),
direkte Media-Zugriffe und Management-Zugang zu produktiven Geräten kritischer als
in klassischer IT.

### 2.3 NMOS IS-04 Discovery als Alternative zu Nmap

Wenn ein Gerät NMOS IS-04 spricht (Discovery/Registration), kann es passiver und
präziser über die NMOS Query API inventarisiert werden als via Nmap:

- **Service:** `services/nmos_service.py`
- **Funktion:** `query_registry(registry_url)` → liefert Nodes, Devices, Senders, Receivers
- **Nutzen:** Exakte Device-Typ-Erkennung, Media-Interfaces, Sender/Receiver-Konfiguration
  ohne aktiven Scan
- **API:** `POST /api/v1/devices/{id}/nmos-discovery` – NMOS Registry URL angeben,
  Gerätedaten importieren
- **Integration:** Ergebnisse werden in `scan_results` gespeichert mit `source=nmos`

### 2.4 NMOS Passive Security Checks (ohne nmos-testing)

Diese Checks sind **ohne** nmos-testing-Sidecar umsetzbar und produktionssicher:

```python
# services/nmos_service.py – passive Checks
async def check_nmos_tls(host: str, port: int) -> NmosSecurityResult:
    """
    Prüft per HTTP-Request ob NMOS IS-04 Registry ohne TLS erreichbar ist.
    Kein mDNS, kein Seiteneffekt.
    """
    # GET http://host:port/x-nmos/query/v1.3/nodes → wenn 200: HTTP (unsicher)
    # GET https://host:port/x-nmos/query/v1.3/nodes → wenn 200: HTTPS (ok)

async def check_nmos_auth_required(host: str, port: int) -> NmosSecurityResult:
    """
    Prüft ob IS-04 APIs ohne Bearer Token zugänglich sind (IS-10 fehlt).
    GET /x-nmos/query/v1.3/nodes ohne Authorization-Header.
    Erwartet 401 → IS-10 aktiv; 200 → kein Schutz.
    """

async def discover_nmos_services(host: str) -> list[NmosService]:
    """
    Fragt NMOS IS-04 Registry ab (falls bekannte Registry-URL in Settings).
    Listet Nodes, Devices, Senders – kein Portscan nötig.
    """
```

Findings aus diesen Checks werden als reguläre `rule_type: nmos_check` Findings gespeichert.

---

## Priorität 3 – Langfristig / Optional

### 3.1 AMWA NMOS Testing Tool Integration (nmos-testing Sidecar)

**Quelle:** `github.com/AMWA-TV/nmos-testing` | Apache 2.0 | Python/Flask
**Docker:** `amwa/nmos-testing:latest` (amd64; auf ARM64/Pi: native Python-Installation nötig)

**Was das Tool abdeckt (sicherheitsrelevant):**

| Suite | Tests | Security-Relevanz |
|-------|-------|-------------------|
| BCP-003-01 | 9 Tests | TLS-Version, Ciphers, HSTS, Zertifikat-Chain, OCSP |
| IS-10-01 | 10 Tests | OAuth2/JWT Token-Ausstellung, Scopes, Revocation (Auth Server) |
| IS-04-01 | HTTPS-Modus | IS-04 Node/Registry nur via HTTPS erreichbar |

**API-Aufruf (HTTP POST /api):**
```python
# services/nmos_service.py
async def run_nmos_compliance_test(host: str, port: int, suite: str) -> dict:
    async with httpx.AsyncClient(timeout=120.0) as client:
        r = await client.post("http://localhost:5000/api", json={
            "suite": suite,      # "BCP-003-01", "IS-04-01", "IS-10-01"
            "host": [host],
            "port": [port],
            "version": ["v1.3"]
        })
        return r.json()
        # Statuswerte: PASS | FAIL | WARNING | DISABLED | UNCLEAR | OPTIONAL | MANUAL
```

**⚠️ Kritischer Vorbehalt – Produktionsnetz-Blocker:**
Das Tool erstellt eigene **mDNS-Announcements** auf dem Netzwerk. Die AMWA-Dokumentation
schreibt explizit vor: nur in **isolierten Testsegmenten** betreiben – **nie** gegen produktive
Nodes oder Registries. Das ist ein fundamentaler Einschränkung für den Einsatz auf dem Pi
im produktiven Broadcast-Netz.

**Bekannte Lücken:**
- IS-10 **Resource Server**-Tests (ob NMOS-APIs unauthentifizierte Requests ablehnen) sind
  laut GitHub Issue #544 unvollständig – genau das wäre der praktisch wichtigste Security-Check
- BCP-003-01 erfordert vorab installiertes Test-CA-Zertifikat auf dem Zielgerät → kein passiver Check
- `ENABLE_HTTPS` nur per Neustart umschaltbar, nicht per API

**Empfohlene Integration (Zwei-Stufen-Ansatz):**
- **Stufe 1** (bereits umsetzbar): Nmap-Regeln für NMOS-Ports + manuelle Fragen (TLS aktiv? IS-10?)
- **Stufe 2** (optionaler Sidecar): nmos-testing Docker-Container, opt-in pro Gerät,
  mit expliziter Warnung "Nur in isolierter Testumgebung – nicht gegen Produktionsgeräte"

**Assessment-UI:** Neuer Button "NMOS Compliance Scan" nur sichtbar wenn Gerät `device_type`
relevant (encoder, decoder, matrix) und `pibg_nmos_testing_url` in Settings konfiguriert ist.

### 3.2 Externe Scanner-Integration (Modul D)

Optionale Anbindung bestehender Vulnerability-Scanner für konsolidierte Berichte:

| Scanner | API | Protokoll |
|---------|-----|-----------|
| **Greenbone OpenVAS/GVM** | Greenbone Management Protocol (GMP) | XML-basiert |
| **Tenable.io / Nessus** | Tenable REST API | JSON/REST |
| **Rapid7 InsightVM** | InsightVM API | JSON/REST |

Ziel: Scanner-Ergebnisse nicht duplizieren, sondern in PiBroadGuard-Assessment
konsolidieren. `scan_mode = "external_scanner"` als neuer Typ.

### 3.3 Vollständiger Broadcast Risk Layer (Modul E)

Gewichtungsmodell speziell für Studio-/Produktionsumgebungen:

| Risikofaktor | Gewicht (Broadcast) | Gewicht (klassische IT) |
|---|---|---|
| PTP/Timing-Angriff (Rogue GM) | 🔴 Kritisch | 🟡 Medium |
| Unsicherer Managementzugang | 🔴 Kritisch | 🔴 Kritisch |
| Unpatchbare Appliance | 🟠 Hoch | 🟡 Medium |
| Bekannte CVE ohne Exponierung | 🟡 Medium | 🟡 Medium |
| KEV-gelistet | 🔴 Kritisch | 🔴 Kritisch |
| EPSS > 90. Perzentile | 🟠 Hoch | 🟠 Hoch |
| Fehlende Netz-Segmentierung bei Real-Time Media | 🔴 Kritisch | 🟠 Hoch |

---

## Architektur-Übersicht (Zielzustand)

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Modul A – Discovery                                                    │
│  Nmap (passiv/standard/extended) + NMOS IS-04 Query + rDNS + MAC OUI  │
├─────────────────────────────────────────────────────────────────────────┤
│  Modul B – Broadcast Compliance Checks                                  │
│  EBU R143/R148/R160 · AMWA BCP-003 · SMPTE ST 2059 · JT-NM TR-1001-1 │
│  Regelwerk-Engine (YAML + DB) mit broadcast-spezifischen Prüfpunkten   │
├─────────────────────────────────────────────────────────────────────────┤
│  Modul C – Vulnerability Enrichment                                     │
│  NVD CVE API v2 (CPE-basiert + hasKev) · CISA KEV · CISA ICS Advisories│
│  EPSS (FIRST.org) · CSAF 2.0 Vendor Advisories · CWE-Empfehlungen     │
├─────────────────────────────────────────────────────────────────────────┤
│  Modul D – Externe Scanner (optional)                                   │
│  Greenbone GMP · Tenable API · Rapid7 InsightVM API                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Modul E – Broadcast Risk Model                                         │
│  Broadcast-Gewichtung · PTP-Kritikalität · Timing-Risiken              │
│  Lifestyle-Penalty · Real-Time-Media-Segmentierung                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Datenquellen-Übersicht (Zielzustand)

| Quelle | URL | Typ | Prio |
|--------|-----|-----|------|
| NIST NVD CVE API v2 | `services.nvd.nist.gov/rest/json/cves/2.0` | REST | ✅ implementiert |
| NVD CPE API v2 | `services.nvd.nist.gov/rest/json/cpes/2.0` | REST | 📋 Prio 1 |
| CISA KEV JSON | `cisa.gov/.../known_exploited_vulnerabilities.json` | JSON-DL | ✅ implementiert |
| FIRST EPSS API | `api.first.org/data/v1/epss` | REST | ✅ implementiert |
| CISA ICS Advisories | `cisa.gov/uscert/ics/advisories` (RSS) | RSS | 📋 Prio 1 |
| CSAF 2.0 Vendor | hersteller-spezifisch | JSON | 📋 Prio 2 |
| AMWA NMOS IS-04 | gerätespezifisch (interne Infra) | REST | 📋 Prio 2 |
| Greenbone GMP | eigene Instanz | XML | 📋 Prio 3 |
| Tenable API | tenable.io oder On-Prem | REST | 📋 Prio 3 |
| Rapid7 InsightVM | eigene Instanz | REST | 📋 Prio 3 |

---

*TODO.md – PiBroadGuard Roadmap | März 2026*
