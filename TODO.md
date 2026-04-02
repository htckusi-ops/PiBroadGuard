# PiBroadGuard – Geplante Erweiterungen / Roadmap

**Stand:** April 2026 | Basierend auf Fachexpertise zu EBU/AMWA/JT-NM/SMPTE-Standards und Vulnerability-Intelligence

---

## ✅ Implementiert (Prio 1 + 2 abgeschlossen)

### 1.1 Regelwerk: Broadcast-spezifische Regeln (EBU R143/R148) ✅

Implementiert in `app/rules/default_rules.yaml`:

| rule_key | Port/Protokoll | Severity | Standard-Referenz |
|----------|----------------|----------|-------------------|
| `ptp_pdelay_open` | UDP 319 (PTP event) | medium | SMPTE ST 2059, JT-NM TR-1001-1 |
| `ptp_general_open` | UDP 320 (PTP general) | medium | SMPTE ST 2059 |
| `nmos_registry_http` | TCP 8080 (NMOS IS-04 ohne TLS) | medium | AMWA BCP-003 |
| `ssdp_open` | UDP 1900 (SSDP/UPnP) | low | EBU R143 §4.2 |
| `mdns_open` | UDP 5353 (mDNS) | info | JT-NM TR-1001-1 |
| `wsd_open` | TCP 5357 (WSD/WS-Discovery) | low | EBU R143 §4.2 |
| `bacnet_open` | UDP 47808 (BACnet) | high | IEC 62443 |

Fragenkateg. `nmos`, `ptp_timing`, `network_arch` implementiert in `rule_engine.py`.

### 1.2 NVD CPE-basierte Abfragen + hasKev-Filter ✅

Implementiert in `app/services/cve_service.py` (`resolve_cpe`, `hasKev`/`isVulnerable` Filter).

### 1.3 CISA ICS Advisories ✅

Implementiert: `app/services/ics_service.py`, `app/models/ics_advisory_cache.py`,
Migration 013. Badge in `assessment.html` und Reports (`report.html.j2`, `report.md.j2`).

### 1.4 Methodikreferenz im Report ✅

Standards-Block in beiden Report-Templates auf kompaktes Format umgestellt.
EBU R143/R148/R160, AMWA BCP-003, SMPTE ST 2110/2059, JT-NM TR-1001-1 enthalten.

### 2.1 CSAF 2.0 Vendor Advisory Integration ✅

Implementiert: `app/services/csaf_service.py`, `POST /api/v1/cve/csaf-import`.

### 2.2 Broadcast-spezifisches Risikogewichtungsmodell ✅

Implementiert in `app/services/scoring_service.py` (`BROADCAST_RISK_OVERRIDES`).

### 2.3 NMOS IS-04 Discovery + Passive Security Checks ✅

Implementiert: `app/services/nmos_service.py`, `POST /api/v1/devices/{id}/nmos-check`.
UI-Integration in `device_form.html` (Tab "📡 NMOS Check").

### 2.4 FIRST EPSS Integration ✅

Implementiert in `cve_service.get_epss_scores()`. Badges in `assessment.html` und Reports.

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

**⚠️ Kritischer Vorbehalt – Produktionsnetz-Blocker:**
Das Tool erstellt eigene **mDNS-Announcements** auf dem Netzwerk. Die AMWA-Dokumentation
schreibt explizit vor: nur in **isolierten Testsegmenten** betreiben – **nie** gegen produktive
Nodes oder Registries. Das ist ein fundamentaler Einschränkung für den Einsatz auf dem Pi
im produktiven Broadcast-Netz.

**Bekannte Lücken:**
- IS-10 **Resource Server**-Tests sind laut GitHub Issue #544 unvollständig
- BCP-003-01 erfordert vorab installiertes Test-CA-Zertifikat auf dem Zielgerät
- `ENABLE_HTTPS` nur per Neustart umschaltbar, nicht per API

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

### 3.4 CSAF 2.0 automatischer Vendor-Feed-Sync

Periodischer Sync bekannter Broadcast-Hersteller-CSAF-Feeds (Grass Valley, Lawo, Riedel, Evertz, Ross Video).
Automatische Zuordnung zu Findings beim Scan.

### 3.5 CMDB / Ticketsystem-Integration

- Jira/ServiceNow: Finding → Ticket mit POA&M-Massnahmen
- Wiki: Report automatisch in Confluence/Notion exportieren
- CMDB: Geräte-Sync bidirektional

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
│  Modul D – Externe Scanner (optional, Prio 3)                           │
│  Greenbone GMP · Tenable API · Rapid7 InsightVM API                    │
├─────────────────────────────────────────────────────────────────────────┤
│  Modul E – Broadcast Risk Model (Prio 3)                                │
│  Broadcast-Gewichtung · PTP-Kritikalität · Timing-Risiken              │
│  Lifecycle-Penalty · Real-Time-Media-Segmentierung                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Datenquellen-Übersicht (aktueller Stand)

| Quelle | URL | Typ | Status |
|--------|-----|-----|--------|
| NIST NVD CVE API v2 | `services.nvd.nist.gov/rest/json/cves/2.0` | REST | ✅ implementiert |
| NVD CPE API v2 | `services.nvd.nist.gov/rest/json/cpes/2.0` | REST | ✅ implementiert |
| CISA KEV JSON | `cisa.gov/.../known_exploited_vulnerabilities.json` | JSON-DL | ✅ implementiert |
| FIRST EPSS API | `api.first.org/data/v1/epss` | REST | ✅ implementiert |
| CISA ICS Advisories | `cisa.gov/uscert/ics/advisories` (RSS) | RSS | ✅ implementiert |
| CSAF 2.0 Vendor | hersteller-spezifisch | JSON | ✅ implementiert |
| AMWA NMOS IS-04 | gerätespezifisch (interne Infra) | REST | ✅ implementiert |
| Greenbone GMP | eigene Instanz | XML | 📋 Prio 3 |
| Tenable API | tenable.io oder On-Prem | REST | 📋 Prio 3 |
| Rapid7 InsightVM | eigene Instanz | REST | 📋 Prio 3 |

---

*TODO.md – PiBroadGuard Roadmap | April 2026*
