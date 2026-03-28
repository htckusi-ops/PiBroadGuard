# CLAUDE.md – PiBroadGuard
## Vollständige Projektspezifikation für Claude Code

**Projektname:** PiBroadGuard – Broadcast Device Security Assessment
**GitHub-Repository:** `pibroadguard`
**Version:** 1.8 (konsolidiert)
**Stand:** März 2026

---

## Wichtige Hinweise für Claude Code

- Alle API-Pfade beginnen mit `/api/v1/`
- Umgebungsvariablen-Präfix: `PIBG_`
- Python-Package-Name: `pibroadguard`
- Dateiendung für Scan-Pakete: `.bdsa` (unverschlüsselt) / `.bdsa.enc` (verschlüsselt)
- Frontend: Vue 3 via CDN, Tailwind via CDN – **kein Build-Prozess, kein npm**
- Zielplattform: Raspberry Pi 4 (ARM64) + Standard Linux (x86_64)
- Deployment: Docker Compose **und** direkt via Python/systemd (beide unterstützt)
- Sprache UI: Deutsch | Code, Kommentare, API: Englisch

---

## Inhaltsübersicht

Die Spec besteht aus der Basis (v1.0) und 9 kumulativen Updates:

| Abschnitt | Inhalt |
|-----------|--------|
| **Basis v1.0** | Projektziel, Tech Stack, Projektstruktur, Datenmodell, Scan-Profile, Regelwerk (YAML), Scoring, CVE-Lookup, Auth, API-Endpunkte, Frontend, Report-Templates, Fragenkataloge, Deployment, requirements.txt |
| **Update v1.1** | Scan-Autorisierungsformular, KEV/NVD/CWE-Lösungsvorschläge, `remediation_service`, POA&M, Methodikreferenz im Report |
| **Update v1.2** | Zweiphasiger Workflow (Scan-System → Report-System), `.bdsa`-Paketformat mit SHA256-Checksummen, Assessment-Status-Erweiterung, Import-Seite |
| **Update v1.2 Patch** | Manueller Online/Offline-Schalter (3-Stufen-Modell), `system_settings`-Tabelle, Settings-Seite Konnektivität |
| **Update v1.3** | USB-Export/-Import, AES-256-GCM-Verschlüsselung (Shared Secret), USB-Wizard (3 Schritte), `crypto_service`, `usb_service` |
| **Update v1.4** | Projektname PiBroadGuard, SQLite-Backup, App-Logging, Nmap setcap, API-Versionierung `/api/v1/`, Rate Limiting Basic Auth, konsolidierte `.env`, finale Projektstruktur, finale requirements.txt |
| **Update v1.5** | rDNS-Lookup, MAC-Adress-Erkennung aus Nmap, phpIPAM-Integration, konfigurierbare Gerätetypen (`device_types`-Tabelle), `remediation_sources` JSON-Feld in Findings, Scan-Metadaten (Dauer, Exit-Code, Nmap-Version) |
| **Update v1.6** | Assessment-Historie in Geräteansicht, Scan-Profil-Persistenz, i18n (EN/DE via `i18n.js`), Tooltips, CVE-Cache-Alter-Anzeige, klickbare NVD/KEV-Badges, korrigierte Scan-Profil-Beschreibungen |
| **Update v1.7** | Scan-Queue Service (`asyncio.Queue` + Semaphore), Queue-Status-Widget im UI, Duplikat-Schutz (gleiche Device-ID nicht doppelt), 50-Job-History, Cancel-Support |
| **Update v1.8** | Geplante Scans (APScheduler 3.x), Trigger-Typen: Einmalig/Intervall/Cron, Uhrzeit-Auswahl (HH:MM UTC) für Tages-/Wochen-/Monats-Intervalle, Schedules-Seite (`schedules.html`), nächste Schedules-Widget auf Dashboard |
| **Update v1.9** | Netzwerk-Konfiguration über UI (IP/Gateway/DNS via nmcli), Paginierung in allen Listen, Port-Scan-Resultate in Findings-Tab, Befund-Speichern-Button, Logging-Fix, Auth-Log-Deduplication |

**Bei Widersprüchen zwischen Abschnitten gilt immer das neuere Update.**

---

# Broadcast Device Security Assessment (BDSA) Tool
## Spezifikation für Claude Code – MVP v1.0

---

## 1. Projektziel

Ein internes Webbasiertes Assessment-Tool zur standardisierten Sicherheitsbewertung von Broadcast-Geräten in einem Medienhaus. Das Tool erfasst Geräte, führt Nmap-Scans durch, bewertet die Resultate anhand eines YAML-Regelwerks, erlaubt manuelle Zusatzeingaben und generiert strukturierte Reports.

**Zielplattform:** Raspberry Pi 4 (ARM64) und Standard-Linux (x86_64)
**Deployment:** Docker Compose **und** direkt via Python/systemd

---

## 2. Tech Stack

| Komponente       | Technologie                                      |
|------------------|--------------------------------------------------|
| Backend          | Python 3.11+, FastAPI                            |
| Frontend         | Vue 3 via CDN (kein Build-Step), Tailwind CSS via CDN |
| Datenbank        | SQLite (via SQLAlchemy + Alembic)                |
| Scan-Engine      | Nmap via subprocess (kein python-nmap Binding)   |
| Hintergrundtasks | FastAPI BackgroundTasks (kein Celery/Redis)      |
| Report-Engine    | Jinja2 Templates (.md + .html), JSON-Serialisierung |
| CVE-Lookup       | NIST NVD API v2 (passiv, optional per Scan)      |
| Auth             | HTTP Basic Auth via FastAPI HTTPBasic             |
| ORM              | SQLAlchemy 2.x mit Alembic für Migrationen       |

**Wichtig:** Kein Node.js, kein Build-Prozess. Vue 3 und Tailwind werden via CDN eingebunden. Das gesamte Frontend besteht aus statischen HTML-Dateien mit eingebettetem Vue.

---

## 3. Projektstruktur

```
bdsa/
├── app/
│   ├── main.py                  # FastAPI App, Auth-Middleware, Router-Registrierung
│   ├── config.py                # Settings via pydantic-settings (.env Support)
│   ├── database.py              # SQLAlchemy Engine, Session, Base
│   │
│   ├── api/
│   │   ├── devices.py           # CRUD Geräte
│   │   ├── assessments.py       # Assessment erstellen, Status, Reviewer-Input
│   │   ├── scans.py             # Scan starten, Status abfragen, Resultate
│   │   ├── reports.py           # Report generieren und herunterladen
│   │   └── cve.py               # CVE-Lookup Endpunkt
│   │
│   ├── models/
│   │   ├── device.py
│   │   ├── assessment.py
│   │   ├── scan_result.py
│   │   ├── finding.py
│   │   ├── manual_finding.py
│   │   ├── vendor_info.py
│   │   └── audit_log.py
│   │
│   ├── schemas/                 # Pydantic v2 Schemas (Request/Response)
│   │   ├── device.py
│   │   ├── assessment.py
│   │   ├── scan.py
│   │   ├── finding.py
│   │   └── report.py
│   │
│   ├── services/
│   │   ├── nmap_service.py      # Nmap subprocess, XML-Parsing
│   │   ├── rule_engine.py       # YAML-Regelwerk laden und auswerten
│   │   ├── report_service.py    # Report-Generierung (MD, HTML, JSON)
│   │   ├── cve_service.py       # NVD API v2 Abfragen mit Caching
│   │   └── scoring_service.py   # Scoring-Logik (5 Dimensionen)
│   │
│   ├── rules/
│   │   └── default_rules.yaml   # Initiales Regelwerk (15+ Regeln)
│   │
│   └── templates/
│       ├── report.md.j2
│       └── report.html.j2
│
├── frontend/
│   ├── index.html               # Dashboard / Geräteliste
│   ├── device_form.html         # Gerät erfassen / bearbeiten
│   ├── assessment.html          # Assessment-Ansicht mit allen Dimensionen
│   ├── scan_monitor.html        # Live-Scan-Fortschritt (Polling)
│   └── report_preview.html      # Report-Vorschau im Browser
│
├── migrations/                  # Alembic Migrationen
│   └── versions/
│
├── tests/
│   ├── test_nmap_service.py
│   ├── test_rule_engine.py
│   └── test_scoring.py
│
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── alembic.ini
└── README.md
```

---

## 4. Datenmodell

### 4.1 `devices`
```
id                    INTEGER PK
manufacturer          TEXT NOT NULL
model                 TEXT NOT NULL
device_type           TEXT NOT NULL        -- Enum: encoder, decoder, matrix, intercom, ...
serial_number         TEXT
asset_tag             TEXT
hostname              TEXT
ip_address            TEXT NOT NULL
firmware_version      TEXT
location              TEXT
network_segment       TEXT
production_criticality TEXT               -- Enum: critical, high, medium, low
owner_team            TEXT
notes                 TEXT
created_at            DATETIME
updated_at            DATETIME
```

### 4.2 `assessments`
```
id                    INTEGER PK
device_id             INTEGER FK -> devices.id
status                TEXT                 -- Enum: draft, in_progress, review, completed
scan_profile          TEXT                 -- Enum: passive, standard, extended
overall_rating        TEXT                 -- Enum: green, yellow, orange, red
technical_score       INTEGER              -- 0-100
operational_score     INTEGER              -- 0-100
compensation_score    INTEGER              -- 0-100
lifecycle_score       INTEGER              -- 0-100
vendor_score          INTEGER              -- 0-100
reviewer              TEXT
summary               TEXT
decision              TEXT                 -- Enum: approved, approved_with_conditions, deferred, rejected
decision_notes        TEXT
reassessment_due      DATE
created_at            DATETIME
updated_at            DATETIME
```

### 4.3 `scan_results`
```
id                    INTEGER PK
assessment_id         INTEGER FK
port                  INTEGER
protocol              TEXT                 -- tcp / udp
service_name          TEXT
service_product       TEXT
service_version       TEXT
state                 TEXT                 -- open / filtered / closed
extra_info            TEXT
raw_nmap_output       TEXT                 -- vollständiges XML für Audit
scanned_at            DATETIME
```

### 4.4 `findings`
```
id                    INTEGER PK
assessment_id         INTEGER FK
rule_key              TEXT
title                 TEXT
severity              TEXT                 -- Enum: critical, high, medium, low, info
description           TEXT
evidence              TEXT                 -- z.B. "Port 23/tcp open telnet"
recommendation        TEXT
broadcast_context     TEXT                 -- Broadcast-spezifische Einordnung
compensating_control_required BOOLEAN
compensating_control_description TEXT
status                TEXT                 -- Enum: open, compensated, accepted, false_positive
created_at            DATETIME
```

### 4.5 `manual_findings`
```
id                    INTEGER PK
assessment_id         INTEGER FK
category              TEXT                 -- Enum: auth, patch, hardening, monitoring, operational, vendor
question_key          TEXT
answer_value          TEXT                 -- yes / no / partial / unknown
comment               TEXT
source                TEXT                 -- z.B. "Herstellerdoku v2.3", "Hersteller-E-Mail"
```

### 4.6 `vendor_information`
```
id                    INTEGER PK
assessment_id         INTEGER FK
support_end_date      DATE
security_update_policy TEXT
psirt_available       BOOLEAN
advisory_process      TEXT
hardening_guide       BOOLEAN
security_contact      TEXT
notes                 TEXT
source_reference      TEXT
```

### 4.7 `audit_log`
```
id                    INTEGER PK
assessment_id         INTEGER FK
user                  TEXT
action                TEXT                 -- z.B. "finding_status_changed", "score_updated"
field_name            TEXT
old_value             TEXT
new_value             TEXT
timestamp             DATETIME
```

### 4.8 `cve_cache`
```
id                    INTEGER PK
vendor                TEXT
product               TEXT
version               TEXT
cve_id                TEXT
cvss_score            REAL
description           TEXT
published_date        DATE
fetched_at            DATETIME
```

---

## 5. Scan-Profile

Drei vordefinierte Profile, auswählbar beim Assessment-Start:

| Profil       | Nmap-Flags                                                  | Zweck                              |
|--------------|-------------------------------------------------------------|------------------------------------|
| `passive`    | `-sV --version-light -T2 -p 21,22,23,25,80,161,443,502,554,8080,8443,9100` | Schonend, nur bekannte Ports       |
| `standard`   | `-sV -T3 --top-ports 1000 --version-intensity 5`            | Normaler Assessment-Scan           |
| `extended`   | `-sV -sU --top-ports 500 -T3 --version-intensity 7`         | Inkl. UDP (SNMP, RTP, Discovery)   |

**Wichtig:** Jeder Scan muss vor Ausführung eine Bestätigungsabfrage im UI zeigen mit Hinweis auf erforderliche Betriebsfreigabe.

Nmap-Output wird als XML gespeichert (`-oX`), dann via `xml.etree.ElementTree` geparst – keine externe Abhängigkeit.

---

## 6. Regelwerk (YAML)

Datei: `app/rules/default_rules.yaml`

Jede Regel hat folgendes Schema:

```yaml
- rule_key: string          # eindeutiger Bezeichner
  title: string             # Kurztitel
  description: string       # Erklärung des Risikos
  condition:
    type: port_open | service_detected | no_service | manual_answer
    port: int               # bei port_open
    protocol: tcp|udp       # optional, default tcp
    service: string         # bei service_detected
    question_key: string    # bei manual_answer
    answer: string          # erwarteter Wert
  severity: critical|high|medium|low|info
  broadcast_context: string # Broadcast-spezifische Einordnung
  recommendation: string
  ask_compensation: bool    # true = Kompensationsfeld im UI anzeigen
  affects_score: string     # technical|operational|lifecycle|vendor|compensation
```

### Initiales Regelwerk (Mindestumfang MVP)

```yaml
# Unsichere Protokolle
- rule_key: telnet_open
  title: "Telnet aktiv (Port 23)"
  condition: { type: port_open, port: 23 }
  severity: high
  broadcast_context: "Bei Broadcast-Geräten gelegentlich betriebsnotwendig – Kompensation prüfen"
  recommendation: "Deaktivieren oder auf Management-VLAN mit ACL beschränken"
  ask_compensation: true
  affects_score: technical

- rule_key: ftp_open
  title: "FTP aktiv (Port 21)"
  condition: { type: port_open, port: 21 }
  severity: high
  broadcast_context: "Teils für Firmware-Updates genutzt – Alternativprozess prüfen"
  recommendation: "Deaktivieren oder auf SFTP migrieren"
  ask_compensation: true
  affects_score: technical

- rule_key: http_no_https
  title: "HTTP ohne HTTPS verfügbar"
  condition: { type: port_open, port: 80 }
  severity: medium
  broadcast_context: "Management-Interface unverschlüsselt – kritisch bei Credentials-Übertragung"
  recommendation: "HTTPS aktivieren oder HTTP deaktivieren; bei Nicht-Härtbarkeit: Management-VLAN"
  ask_compensation: true
  affects_score: technical

- rule_key: snmp_v1_v2
  title: "SNMP v1/v2c aktiv (Port 161 UDP)"
  condition: { type: port_open, port: 161, protocol: udp }
  severity: medium
  broadcast_context: "SNMP v1/v2c häufig in Broadcast-Monitoring – Community String prüfen"
  recommendation: "SNMPv3 bevorzugen; falls nicht möglich: Read-only Community, IP-ACL"
  ask_compensation: true
  affects_score: technical

- rule_key: ssh_open
  title: "SSH aktiv (Port 22)"
  condition: { type: port_open, port: 22 }
  severity: info
  broadcast_context: "SSH ist grundsätzlich akzeptabel – Version und Auth-Methode prüfen"
  recommendation: "Sicherstellen: SSHv2, keine Root-Logins, keine Passwort-Auth falls möglich"
  ask_compensation: false
  affects_score: technical

- rule_key: smb_open
  title: "SMB aktiv (Port 445)"
  condition: { type: port_open, port: 445 }
  severity: high
  broadcast_context: "SMB auf Broadcast-Geräten ungewöhnlich – Notwendigkeit klären"
  recommendation: "Deaktivieren falls nicht betriebsnotwendig; SMBv1 zwingend deaktivieren"
  ask_compensation: true
  affects_score: technical

- rule_key: rdp_open
  title: "RDP aktiv (Port 3389)"
  condition: { type: port_open, port: 3389 }
  severity: high
  broadcast_context: "Fernwartung via RDP – Netzwerkzugang prüfen"
  recommendation: "Auf Management-VLAN beschränken; NLA erzwingen; MFA prüfen"
  ask_compensation: true
  affects_score: technical

# Lifecycle / Vendor
- rule_key: no_lifecycle_info
  title: "Kein dokumentierter Lifecycle / EOL-Datum"
  condition: { type: manual_answer, question_key: lifecycle_documented, answer: "no" }
  severity: medium
  broadcast_context: "Langfristiger Betrieb ohne Sicherheitsgarantie – Risikoakzeptanz dokumentieren"
  recommendation: "Hersteller anfragen; befristete Einsatzgenehmigung mit Nachfolgerplanung"
  ask_compensation: false
  affects_score: lifecycle

- rule_key: no_security_updates
  title: "Keine separaten Security-Updates verfügbar"
  condition: { type: manual_answer, question_key: security_updates_available, answer: "no" }
  severity: medium
  broadcast_context: "Sicherheitslücken nur via Firmware-Upgrade behebbar – Aufwand erhöht"
  recommendation: "Update-Aufwand in Betriebsplanung einbeziehen; Monitoring verstärken"
  ask_compensation: false
  affects_score: lifecycle

- rule_key: default_credentials
  title: "Default-Credentials vorhanden und nicht änderbar"
  condition: { type: manual_answer, question_key: default_creds_changeable, answer: "no" }
  severity: critical
  broadcast_context: "Bekannte Default-Passwörter bei Broadcast-Geräten weit verbreitet"
  recommendation: "Gerät nur in vollständig isoliertem Segment betreiben; Freigabe nur mit starker Kompensation"
  ask_compensation: true
  affects_score: technical

# Monitoring
- rule_key: no_syslog
  title: "Kein Syslog-Export möglich"
  condition: { type: manual_answer, question_key: syslog_supported, answer: "no" }
  severity: low
  broadcast_context: "Eingeschränkte Detection-Fähigkeit – kompensierendes Netzwerk-Monitoring prüfen"
  recommendation: "Netzwerkbasiertes Logging als Kompensation (Netflow, IDS)"
  ask_compensation: false
  affects_score: operational

- rule_key: no_psirt
  title: "Kein PSIRT / Security-Kontakt beim Hersteller"
  condition: { type: manual_answer, question_key: psirt_available, answer: "no" }
  severity: low
  broadcast_context: "Sicherheitsmeldungen nicht strukturiert möglich – erhöhtes Reaktionsrisiko"
  recommendation: "Allgemeinen Support-Kanal dokumentieren; externe Quellen (NVD, CERT) überwachen"
  ask_compensation: false
  affects_score: vendor
```

---

## 7. Scoring-Logik

### 7.1 Fünf Score-Dimensionen (je 0–100)

| Dimension          | Basis                                                |
|--------------------|------------------------------------------------------|
| `technical_score`  | Findings mit `affects_score: technical`              |
| `operational_score`| Findings mit `affects_score: operational` + Betriebskontext-Felder |
| `compensation_score`| Kompensationsfelder ausgefüllt und bewertet         |
| `lifecycle_score`  | Lifecycle/Vendor-Felder in `manual_findings`         |
| `vendor_score`     | Vendor-Informationen in `vendor_information`         |

### 7.2 Scoring-Formel

Jeder Finding reduziert den Score basierend auf Severity:

```python
SEVERITY_PENALTY = {
    "critical": 30,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0
}
# Kompensierte Findings: halbe Penalty
# Basis: 100, Minimum: 0
```

### 7.3 Gesamtbewertung (Overall Rating)

```python
def calculate_overall_rating(scores: dict) -> str:
    # Gewichteter Durchschnitt
    weighted = (
        scores["technical"]    * 0.35 +
        scores["operational"]  * 0.20 +
        scores["compensation"] * 0.20 +
        scores["lifecycle"]    * 0.15 +
        scores["vendor"]       * 0.10
    )
    if weighted >= 75:   return "green"
    if weighted >= 55:   return "yellow"
    if weighted >= 35:   return "orange"
    return "red"

# Überschreibungsregeln:
# - 1x critical finding ohne Kompensation -> max. orange
# - 2x critical findings -> automatisch rot
# - Lifecycle-Score < 20 -> max. yellow (langfristiges Risiko)
```

---

## 8. CVE-Lookup (NVD API v2)

**Service:** `app/services/cve_service.py`

- Abfrage: `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={vendor}+{product}&resultsPerPage=10`
- Ergebnisse werden in `cve_cache` gespeichert (TTL: 7 Tage)
- Lookup wird **nicht** automatisch beim Scan ausgelöst, sondern als separater Button im UI
- Bei Offline-Betrieb (Pi ohne Internet): graceful fallback mit Hinweis "CVE-Lookup nicht verfügbar"
- Rate Limiting beachten: max. 5 Requests/30s ohne API-Key; mit API-Key (konfigurierbar in `.env`) 50 Requests/30s

---

## 9. HTTP Basic Auth

Konfiguration in `.env`:
```
BDSA_USERNAME=admin
BDSA_PASSWORD=changeme
BDSA_SECRET_KEY=generate-random-key-here
```

Implementation in `app/main.py`:
```python
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

security = HTTPBasic()

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, settings.username)
    correct_pass = secrets.compare_digest(credentials.password, settings.password)
    if not (correct_user and correct_pass):
        raise HTTPException(status_code=401, headers={"WWW-Authenticate": "Basic"})
```

Alle API-Endpunkte und das Frontend erfordern Auth. Static Files werden ebenfalls geschützt (via Middleware, nicht via StaticFiles-Mount ohne Auth).

---

## 10. API-Endpunkte

### Devices
```
GET    /api/devices                  # Liste aller Geräte
POST   /api/devices                  # Neues Gerät
GET    /api/devices/{id}             # Gerät details
PUT    /api/devices/{id}             # Gerät bearbeiten
DELETE /api/devices/{id}             # Gerät löschen (soft delete)
```

### Assessments
```
POST   /api/devices/{id}/assessments         # Neues Assessment starten
GET    /api/assessments/{id}                  # Assessment abrufen
PUT    /api/assessments/{id}                  # Assessment aktualisieren (Reviewer-Input)
GET    /api/assessments/{id}/manual-findings  # Manuelle Fragen abrufen
POST   /api/assessments/{id}/manual-findings  # Manuelle Antworten speichern
PUT    /api/assessments/{id}/findings/{fid}   # Finding-Status aktualisieren
POST   /api/assessments/{id}/recalculate      # Score neu berechnen
```

### Scans
```
POST   /api/assessments/{id}/scan    # Scan starten (BackgroundTask)
GET    /api/assessments/{id}/scan/status  # Scan-Status abfragen (Polling)
GET    /api/assessments/{id}/scan/results # Scan-Resultate abrufen
```

### Reports
```
GET    /api/assessments/{id}/report/md    # Markdown-Report
GET    /api/assessments/{id}/report/html  # HTML-Report
GET    /api/assessments/{id}/report/json  # JSON-Report
```

### CVE
```
GET    /api/cve/lookup?vendor={v}&product={p}&version={ver}  # CVE-Lookup
```

### System
```
GET    /api/health                   # Health check (kein Auth)
GET    /api/version                  # App-Version
```

---

## 11. Frontend (Vue 3 via CDN)

### Struktur
Alle HTML-Dateien liegen in `frontend/` und werden von FastAPI als StaticFiles serviert. Vue 3 und Tailwind CSS werden via CDN eingebunden – **kein npm, kein Build**.

```html
<!-- In jedem HTML-File im <head> -->
<script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
<script src="https://cdn.tailwindcss.com"></script>
```

### Seiten

**`index.html` – Dashboard**
- Geräteliste mit Status der letzten Assessments
- Schnellfilter: Rating (grün/gelb/orange/rot), Gerätetyp
- Button: "Neues Gerät erfassen"
- Statistik-Übersicht (Anzahl Geräte, offene Findings, kritische Geräte)

**`device_form.html` – Gerät erfassen/bearbeiten**
- Formular für alle Stammdaten (Section 4.1)
- Validierung: IP-Adresse, Pflichtfelder

**`assessment.html` – Haupt-Assessment-View**
- Tab-Navigation: Übersicht | Scan | Manuelle Fragen | Findings | Report
- Score-Visualisierung: 5 Balken (Dimensionen) + Gesamtrating als farbiger Badge
- Scan-Profil-Auswahl mit Bestätigungsdialog
- Manuelle Fragen als kategorisiertes Formular (Accordion per Kategorie)
- Findings-Tabelle mit Status-Dropdown und Kompensationsfeld

**`scan_monitor.html` (eingebettet in assessment.html)**
- Polling alle 2 Sekunden auf `/api/assessments/{id}/scan/status`
- Live-Anzeige: "Scan läuft... Port X/Y"
- Nach Abschluss: automatische Anzeige der Resultate

**`report_preview.html` – Report im Browser**
- Rendert den HTML-Report inline
- Download-Buttons: Markdown, HTML, JSON
- Drucken-Button (Browser-Print)

### Design-Richtlinien
- Tailwind CSS für alle Styles
- Farbschema: Grau/Slate als Basis, Statusfarben: grün=#22c55e, gelb=#eab308, orange=#f97316, rot=#ef4444
- Responsiv (funktioniert auch auf Tablet für Vor-Ort-Assessments)
- Keine externen Icon-Libraries – nur Unicode-Symbole oder einfache SVG-Inline-Icons

---

## 12. Report-Templates

### Markdown-Template (`report.md.j2`)

```markdown
# Broadcast Device Security Assessment Report
**Gerät:** {{ device.manufacturer }} {{ device.model }}  
**Assessment-ID:** {{ assessment.id }}  
**Datum:** {{ assessment.created_at | date }}  
**Reviewer:** {{ assessment.reviewer or "ausstehend" }}  
**Status:** {{ assessment.decision | upper }}

---

## Executive Summary
{{ assessment.summary }}

**Gesamtbewertung:** {{ assessment.overall_rating | rating_label }}

| Dimension | Score |
|-----------|-------|
| Technisch | {{ assessment.technical_score }}/100 |
| Betrieb | {{ assessment.operational_score }}/100 |
| Kompensation | {{ assessment.compensation_score }}/100 |
| Lifecycle | {{ assessment.lifecycle_score }}/100 |
| Hersteller | {{ assessment.vendor_score }}/100 |

---

## Gerätestammdaten
...

## Scan-Resultate ({{ scan_results | length }} offene Ports)
...

## Findings ({{ findings | length }} total)
{% for f in findings | sort(attribute='severity') %}
### [{{ f.severity | upper }}] {{ f.title }}
{{ f.description }}
**Broadcast-Kontext:** {{ f.broadcast_context }}
**Empfehlung:** {{ f.recommendation }}
{% if f.compensating_control_description %}
**Kompensation:** {{ f.compensating_control_description }}
{% endif %}
{% endfor %}

## Entscheid
**{{ assessment.decision | decision_label }}**
{{ assessment.decision_notes }}
```

---

## 13. Manuelle Fragenkataloge

Kategorisiert, gespeichert als strukturierte Liste in `app/services/rule_engine.py` oder separates YAML:

### Kategorie: `auth` – Authentisierung
| `question_key`              | Frage                                              |
|-----------------------------|----------------------------------------------------|
| `default_creds_exist`       | Gibt es Default-Credentials?                       |
| `default_creds_changeable`  | Können Default-Credentials geändert werden?        |
| `individual_accounts`       | Können individuelle Benutzer erstellt werden?      |
| `roles_available`           | Gibt es ein Rollen-/Rechtekonzept?                 |
| `mfa_possible`              | Ist MFA möglich?                                   |
| `central_auth_possible`     | Ist zentrale Authentisierung möglich (LDAP/AD)?    |

### Kategorie: `patch` – Updates / Lifecycle
| `question_key`              | Frage                                              |
|-----------------------------|----------------------------------------------------|
| `firmware_updatable`        | Ist Firmware aktualisierbar?                       |
| `security_updates_available`| Gibt es separate Security-Updates?                 |
| `security_advisories`       | Gibt es Security Advisories vom Hersteller?        |
| `lifecycle_documented`      | Ist das EOL/EOS-Datum dokumentiert?                |
| `update_without_downtime`   | Ist Update ohne grossen Produktionsunterbruch möglich? |

### Kategorie: `hardening` – Härtung
| `question_key`              | Frage                                              |
|-----------------------------|----------------------------------------------------|
| `unnecessary_services_disableable` | Können unnötige Dienste deaktiviert werden?  |
| `web_interface_disableable` | Kann das Webinterface deaktiviert/abgesichert werden? |
| `insecure_protocols_disableable` | Können unsichere Protokolle deaktiviert werden? |
| `certificates_replaceable`  | Können Zertifikate ersetzt werden?                 |
| `tls_configurable`          | Sind TLS-Version und Cipher konfigurierbar?        |

### Kategorie: `monitoring` – Logging / Monitoring
| `question_key`              | Frage                                              |
|-----------------------------|----------------------------------------------------|
| `syslog_supported`          | Unterstützt das Gerät Syslog-Export?               |
| `snmpv3_supported`          | Ist SNMPv3 verfügbar?                              |
| `login_logging`             | Werden Logins protokolliert?                       |
| `config_change_logging`     | Werden Konfigurationsänderungen protokolliert?     |

### Kategorie: `operational` – Betriebskontext
| `question_key`              | Frage                                              |
|-----------------------------|----------------------------------------------------|
| `production_critical`       | Ist das Gerät für Live-Produktion kritisch?        |
| `redundancy_available`      | Ist Redundanz vorhanden?                           |
| `fallback_possible`         | Ist ein Fallback möglich?                          |
| `management_vlan_possible`  | Kann das Gerät in ein Management-VLAN gestellt werden? |
| `legacy_services_required`  | Gibt es betriebsnotwendige Legacy-Dienste?         |

### Kategorie: `vendor` – Herstellerreife
| `question_key`              | Frage                                              |
|-----------------------------|----------------------------------------------------|
| `psirt_available`           | Gibt es ein PSIRT oder Security-Kontakt?           |
| `hardening_guide_available` | Gibt es ein Hardening-Guide?                       |
| `security_roadmap`          | Gibt es eine nachvollziehbare Security-Roadmap?    |

---

## 14. Deployment

### Docker Compose (`docker-compose.yml`)

```yaml
version: '3.8'
services:
  bdsa:
    build: .
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data          # SQLite-Datei
      - ./app/rules:/app/rules    # YAML-Regelwerk (editierbar ohne Rebuild)
    environment:
      - BDSA_USERNAME=${BDSA_USERNAME:-admin}
      - BDSA_PASSWORD=${BDSA_PASSWORD:-changeme}
      - BDSA_DB_PATH=/app/data/bdsa.db
      - BDSA_NVD_API_KEY=${BDSA_NVD_API_KEY:-}
    cap_add:
      - NET_RAW                   # Für Nmap (raw sockets)
      - NET_ADMIN
    restart: unless-stopped
```

```dockerfile
# Dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN alembic upgrade head

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Direktes Deployment (systemd)

```bash
# Setup
git clone ... && cd bdsa
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && nano .env
alembic upgrade head

# Starten
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

`/etc/systemd/system/bdsa.service`:
```ini
[Unit]
Description=BDSA - Broadcast Device Security Assessment
After=network.target

[Service]
Type=simple
User=bdsa
WorkingDirectory=/opt/bdsa
EnvironmentFile=/opt/bdsa/.env
ExecStart=/opt/bdsa/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## 15. requirements.txt

```
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
sqlalchemy>=2.0.0
alembic>=1.13.0
pydantic>=2.7.0
pydantic-settings>=2.3.0
jinja2>=3.1.0
httpx>=0.27.0          # Für NVD API
python-multipart>=0.0.9
```

---

## 16. `.env.example`

```env
BDSA_USERNAME=admin
BDSA_PASSWORD=changeme
BDSA_SECRET_KEY=replace-with-random-32-char-string
BDSA_DB_PATH=./data/bdsa.db
BDSA_NVD_API_KEY=
BDSA_RULES_PATH=./app/rules/default_rules.yaml
BDSA_LOG_LEVEL=INFO
```

---

## 17. Raspberry Pi Besonderheiten

- **ARM64 kompatibel:** Alle Dependencies sind Pi-kompatibel (getestet auf Pi 4, Raspberry Pi OS 64-bit)
- **Nmap:** Ist in den Raspbian/Pi OS Repos verfügbar (`apt install nmap`)
- **Ressourcen:** SQLite + FastAPI + Vue via CDN benötigt <200MB RAM im Betrieb
- **Performance:** Nmap-Scans laufen langsamer auf Pi – Timeouts in `nmap_service.py` entsprechend setzen (`--host-timeout 60s`)
- **Docker auf Pi:** `docker-compose` via `apt install docker-compose` oder pip; Dockerfile nutzt `python:3.11-slim` (multi-arch)

---

## 18. Sicherheitshinweise für den Code

- Nmap-Argumente **niemals** direkt aus User-Input zusammenbauen – IP-Adresse via `ipaddress.ip_address()` validieren
- SQLite-Datei in separatem Volume ausserhalb des App-Containers
- Kein Debug-Mode in Produktion (`--reload` nur in Dev)
- Audit-Log bei jeder Assessment-Änderung schreiben
- CVE-Service mit Timeout (5s) und Fehlerbehandlung – kein blocking bei Netzwerkproblemen

---

## 19. MVP-Abgrenzung (was NICHT implementiert wird)

- Kein Mehrbenutzer-Rollenmodell (ein Shared-Login via Basic Auth)
- Kein PDF-Export (nur MD, HTML, JSON)
- Kein SSO/LDAP
- Kein Freigabe-Workflow mit digitalem Sign-off
- Keine automatische Re-Assessment-Benachrichtigung
- Keine CMDB/Jira/Wiki-Integration
- Kein automatisches TLS-Zertifikat-Scanning (Phase 4)

---

## 20. Empfohlene Implementierungsreihenfolge für Claude Code

1. **Projektstruktur + DB-Modell** – `database.py`, alle Models, Alembic-Migration
2. **Config + Auth** – `config.py`, Basic-Auth-Middleware in `main.py`
3. **Device CRUD API + Frontend** – `api/devices.py` + `frontend/index.html` + `frontend/device_form.html`
4. **Nmap Service + Scan API** – `services/nmap_service.py`, `api/scans.py`
5. **Rule Engine** – `services/rule_engine.py`, `app/rules/default_rules.yaml`
6. **Scoring Service** – `services/scoring_service.py`
7. **Assessment API + Frontend** – vollständige Assessment-View
8. **Manuelle Fragen** – Fragenkatalog + API + UI
9. **Report Service + Templates** – MD, HTML, JSON
10. **CVE Service** – NVD API mit Caching
11. **Docker + systemd** – Deployment-Files
12. **Tests** – Rule Engine, Scoring, Nmap-Parser

---

*Dokument erstellt als Grundlage für die Implementierung mit Claude Code. Version 1.0 – MVP.*
# BDSA_SPEC.md – Update v1.1
## Ergänzungen aus der Standardreferenz

Dieses Dokument beschreibt alle Änderungen und Ergänzungen gegenüber BDSA_SPEC.md v1.0.
Die Nummerierung orientiert sich an den Sektionen der ursprünglichen Spec.

---

## ÄNDERUNG 1: Scan-Autorisierungsformular (neu)
*Betrifft: Abschnitt 5 (Scan-Profile), Abschnitt 10 (API), Abschnitt 11 (Frontend)*

### Hintergrund
Nmap-Scans dürfen rechtlich und methodisch (NIST SP 800-115, IEC 62443-2-1) nur mit
schriftlicher, dokumentierter Genehmigung durchgeführt werden. Das BDSA-Tool muss
diesen Autorisierungsschritt im Prozess verankern und im Audit-Log festhalten.

### Neue DB-Tabelle: `scan_authorizations`

```
id                    INTEGER PK
assessment_id         INTEGER FK -> assessments.id
authorized_by_name    TEXT NOT NULL      -- Vollständiger Name der autorisierenden Person
authorized_by_role    TEXT NOT NULL      -- Rolle (z.B. "Broadcast Engineering Lead")
authorized_by_contact TEXT              -- E-Mail oder Telefon
authorization_date    DATETIME NOT NULL
scan_profile          TEXT NOT NULL      -- passive / standard / extended
target_ip             TEXT NOT NULL      -- IP zum Zeitpunkt der Genehmigung
time_window_start     DATETIME          -- geplantes Scan-Zeitfenster (optional)
time_window_end       DATETIME
notes                 TEXT              -- z.B. "Scan nur im Wartungsfenster"
confirmed_by_user     TEXT NOT NULL      -- BDSA-Login, der den Scan gestartet hat
created_at            DATETIME
```

### Neuer API-Endpunkt

```
POST /api/assessments/{id}/scan/authorize   # Autorisierung erfassen
GET  /api/assessments/{id}/scan/authorize   # Aktuelle Autorisierung abrufen
```

### UI-Flow im Frontend (assessment.html, Tab "Scan")

**Schritt 1 – Scan-Profil wählen:**
Dropdown mit den drei Profilen (passive / standard / extended) inkl. kurzer Beschreibung
und Hinweis auf Scan-Aggressivität.

**Schritt 2 – Autorisierungsdialog (Modal, Pflichtfelder):**

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⚠️  Scan-Autorisierung erforderlich                                │
│                                                                     │
│  Vor dem Start eines Nmap-Scans muss eine Betriebsfreigabe          │
│  dokumentiert sein (gemäss NIST SP 800-115 / IEC 62443-2-1).        │
│                                                                     │
│  Freigabe erteilt durch:                                            │
│  Name*        [________________________________]                    │
│  Rolle*        [________________________________]                    │
│  Kontakt       [________________________________]                    │
│                                                                     │
│  Zeitfenster (optional):                                            │
│  Von           [Datum/Uhrzeit]   Bis  [Datum/Uhrzeit]              │
│                                                                     │
│  Hinweise      [________________________________]                    │
│                                                                     │
│  ☑  Ich bestätige, dass eine Betriebsfreigabe für diesen Scan       │
│     eingeholt wurde und das Scan-Risiko bekannt ist.                │
│                                                                     │
│  Hinweis: Broadcast-Geräte können empfindlich auf Netzwerkscans     │
│  reagieren. Das Profil "passive" ist für produktive Geräte          │
│  empfohlen.                                                         │
│                                                                     │
│           [Abbrechen]          [Scan starten →]                     │
└─────────────────────────────────────────────────────────────────────┘
```

Der "Scan starten"-Button ist **deaktiviert**, bis:
- Name und Rolle ausgefüllt sind
- Die Bestätigungs-Checkbox aktiviert ist

**Schritt 3 – Scan läuft:**
Nach dem Klick wird die Autorisierung in `scan_authorizations` gespeichert,
dann erst der Scan-BackgroundTask gestartet.

**Im Report:** Die Autorisierungsdaten erscheinen im Abschnitt "Assessment Scope und Methodik":
```
Scan-Autorisierung: [Name], [Rolle] – [Datum]
Scan-Profil: passive | standard | extended
Zeitfenster: [falls angegeben]
```

---

## ÄNDERUNG 2: Externe Datenquellen für Lösungsvorschläge (neu)
*Betrifft: Abschnitt 8 (CVE-Lookup), neuer Abschnitt "Remediation Intelligence"*

### Übersicht der nutzbaren Quellen

Es gibt drei kostenfreie, öffentlich zugängliche Datenquellen, die automatische
Lösungsvorschläge ermöglichen:

---

#### Quelle A: NIST NVD API v2 – CVE-Details inkl. Lösungshinweise

**URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`

**Was geliefert wird:**
- CVSS-Score (v3.1 und v4.0) → direkt als Severity nutzbar
- `evaluatorSolution`: Falls vorhanden, ein offizieller Lösungshinweis des NVD-Analysten
- `references`: Links zu Herstelleradvisories, Patches, Workarounds
- CWE-Klassifikation (Common Weakness Enumeration) → ergibt strukturierte Lösungskategorie

**Beispiel-Response-Feld (relevant):**
```json
{
  "cve": {
    "id": "CVE-2023-12345",
    "descriptions": [{"lang": "en", "value": "..."}],
    "metrics": {
      "cvssMetricV31": [{
        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
      }]
    },
    "evaluatorSolution": "Update to firmware version 3.2.1 or later.",
    "references": [
      {"url": "https://vendor.com/security/advisory-2023-001", "tags": ["Vendor Advisory"]}
    ],
    "weaknesses": [{"description": [{"value": "CWE-287"}]}]
  }
}
```

**Nutzung im BDSA-Tool:**
- `evaluatorSolution` → direkt als "Empfehlung (NVD)" in Finding anzeigen
- `references` mit Tag `Vendor Advisory` → als "Hersteller-Advisory" verlinken
- CVSS-Score → Finding-Severity automatisch setzen

**API-Key:** Kostenlos registrierbar unter https://nvd.nist.gov/developers/request-an-api-key
Rate Limit: 50 Req/30s mit Key, 5 Req/30s ohne Key.

---

#### Quelle B: CISA KEV – Known Exploited Vulnerabilities Catalog

**URL (JSON-Feed):** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

**Was geliefert wird:**
- Liste aller CVEs, die aktiv in der Praxis ausgenutzt werden
- `requiredAction`: Die von CISA empfohlene Massnahme (z.B. "Apply vendor patch", "Disconnect from internet")
- `dueDate`: Frist für US-Bundesbehörden (für uns: Indikator für Dringlichkeit)
- `knownRansomwareCampaignUse`: Hinweis ob in Ransomware-Kampagnen verwendet

**Besonderheit:** Der KEV-Feed ist **kein API**, sondern ein statisches JSON, das täglich aktualisiert wird. Es kann lokal gecacht werden (täglich sync reicht) – ideal für Offline-Betrieb auf dem Pi.

**Beispiel-Eintrag:**
```json
{
  "cveID": "CVE-2021-44228",
  "vendorProject": "Apache",
  "product": "Log4j2",
  "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
  "dateAdded": "2021-12-10",
  "shortDescription": "Apache Log4j2 contains a remote code execution vulnerability...",
  "requiredAction": "Apply updates per vendor instructions.",
  "dueDate": "2021-12-24",
  "knownRansomwareCampaignUse": "Known"
}
```

**Nutzung im BDSA-Tool:**
- Beim CVE-Lookup prüfen: Ist die CVE im KEV? → Badge "⚠️ Aktiv ausgenutzt" im Finding
- `requiredAction` → als prominente Massnahmenempfehlung anzeigen
- `knownRansomwareCampaignUse == "Known"` → Finding-Severity auf minimum HIGH setzen

**Download-URL für lokalen Cache:**
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

---

#### Quelle C: NIST NVD CPE API – Geräte-/Produktsuche

**URL:** `https://services.nvd.nist.gov/rest/json/cpes/2.0`

**Was es ist:** Die CPE-Datenbank (Common Platform Enumeration) enthält standardisierte
Produktnamen. Damit lassen sich CVEs präzise auf Hersteller+Produkt+Version mappen.

**Nutzung im BDSA-Tool:**
- Beim Erfassen eines Geräts (Hersteller + Modell + Firmware) → CPE-Suche im Hintergrund
- CPE-Name als strukturierten Identifier speichern (`cpe:2.3:h:vendor:model:version:...`)
- CVE-Suche dann via CPE statt Keyword → deutlich präzisere Treffer

**Beispiel-Query:**
```
GET /rest/json/cpes/2.0?keywordSearch=bosch+camera&resultsPerPage=5
→ gibt CPE-Namen zurück wie "cpe:2.3:h:bosch:flexidome_5100i:*:*:*:*:*:*:*:*"
```

---

### Neue Service-Schicht: `services/remediation_service.py`

```python
"""
Aggregiert Lösungsvorschläge aus NVD, KEV und dem YAML-Regelwerk.
"""

class RemediationService:

    def get_remediation_for_finding(self, finding: Finding) -> RemediationResult:
        """
        Gibt strukturierte Lösungsvorschläge für ein Finding zurück.
        Quellen (in Priorität):
        1. YAML-Regelwerk (broadcast-spezifisch, immer vorhanden)
        2. KEV-Cache (aktiv ausgenutzt? requiredAction?)
        3. NVD evaluatorSolution (falls CVE bekannt)
        4. NVD references mit Tag "Vendor Advisory"
        5. CWE-basierte generische Empfehlung
        """

    def check_kev(self, cve_id: str) -> Optional[KevEntry]:
        """Prüft lokalen KEV-Cache. Kein HTTP-Call."""

    def get_nvd_remediation(self, cve_id: str) -> Optional[NvdRemediation]:
        """Ruft NVD-Details ab (mit Cache, TTL 7 Tage)."""

    def get_cwe_recommendation(self, cwe_id: str) -> str:
        """Gibt generische Empfehlung basierend auf CWE-Klasse zurück."""

    def sync_kev_cache(self):
        """Lädt KEV-JSON herunter und aktualisiert lokalen Cache (täglich)."""
```

### Neue DB-Tabelle: `kev_cache`

```
id                    INTEGER PK
cve_id                TEXT UNIQUE
vendor_project        TEXT
product               TEXT
vulnerability_name    TEXT
required_action       TEXT
due_date              DATE
known_ransomware      BOOLEAN
date_added_to_kev     DATE
fetched_at            DATETIME
```

### Neuer API-Endpunkt

```
POST /api/system/kev-sync        # KEV-Cache manuell aktualisieren (Admin)
GET  /api/findings/{id}/remediation   # Lösungsvorschläge für ein Finding
```

### CWE → Generische Empfehlung (eingebaut, offline verfügbar)

Für häufige CWE-Klassen soll das Tool offline generische Empfehlungen liefern:

```python
CWE_RECOMMENDATIONS = {
    "CWE-287": "Authentifizierung prüfen/verstärken; Default-Credentials ändern",
    "CWE-306": "Fehlende Authentifizierung – Zugangskontrolle implementieren",
    "CWE-319": "Klartextübertragung – Verschlüsselung aktivieren (TLS/SSH)",
    "CWE-321": "Hardcoded Credentials entfernen; Key-Management einführen",
    "CWE-326": "Schwache Kryptografie – auf TLS 1.2+ und starke Cipher upgraden",
    "CWE-522": "Schwache Passwörter – Passwortpolicy und -komplexität erzwingen",
    "CWE-693": "Fehlende Schutzebenen – Defense-in-Depth und Netzwerksegmentierung",
    "CWE-862": "Fehlende Autorisierungsprüfung – RBAC implementieren",
}
```

---

## ÄNDERUNG 3: Finding-Darstellung mit Lösungsvorschlägen (UI + Report)
*Betrifft: Abschnitt 11 (Frontend), Abschnitt 12 (Report-Templates)*

### UI: Finding-Detail-View (assessment.html, Tab "Findings")

Pro Finding wird ein erweiterter Informationsblock angezeigt:

```
┌─────────────────────────────────────────────────────────────────────┐
│  [HIGH] Telnet aktiv (Port 23/tcp)             BDSA-2025-001        │
├─────────────────────────────────────────────────────────────────────┤
│  Befund: Port 23/tcp open telnet (Nmap, 2025-11-15)                │
│  Risiko:  Klartext-Credentials; Session-Hijacking                  │
│  Broadcast-Kontext: Gelegentlich betriebsnotwendig...              │
├─────────────────────────────────────────────────────────────────────┤
│  📋 LÖSUNGSVORSCHLÄGE                                               │
│                                                                     │
│  ✅ Broadcast-Regelwerk (empfohlen):                                │
│     1. Telnet deaktivieren, falls SSH als Alternative verfügbar    │
│     2. Falls nicht deaktivierbar: Management-VLAN mit ACL           │
│     3. Netzwerkbasiertes Monitoring auf Port 23 aktivieren          │
│                                                                     │
│  🔗 Hersteller-Advisory: [Link falls vorhanden]                    │
│  📊 CVE-Referenz: CVE-XXXX-YYYY (CVSS 7.5 HIGH)                   │
│  ⚠️  Im CISA KEV: NEIN / JA (falls ja: roter Badge + Aktion)      │
├─────────────────────────────────────────────────────────────────────┤
│  Status:  [Offen ▼]    Kompensation: [_________________________]   │
└─────────────────────────────────────────────────────────────────────┘
```

### Report-Template: Erweiterter Finding-Block

In `report.md.j2` und `report.html.j2` wird pro Finding ergänzt:

```markdown
### [{{ f.severity | upper }}] {{ f.title }}

**Befund:** {{ f.evidence }}
**Risiko:** {{ f.description }}
**Broadcast-Kontext:** {{ f.broadcast_context }}

#### Lösungsvorschläge

**Empfehlung (BDSA-Regelwerk):**
{{ f.recommendation }}

{% if f.kev_entry %}
> ⚠️ **Aktiv ausgenutzt (CISA KEV):** Diese Schwachstelle ist im CISA Known
> Exploited Vulnerabilities Catalog gelistet. Empfohlene Massnahme: {{ f.kev_entry.required_action }}
{% endif %}

{% if f.nvd_solution %}
**Empfehlung (NIST NVD):** {{ f.nvd_solution }}
{% endif %}

{% if f.vendor_advisory_url %}
**Hersteller-Advisory:** {{ f.vendor_advisory_url }}
{% endif %}

{% if f.cwe_recommendation %}
**Generelle Massnahme (CWE-{{ f.cwe_id }}):** {{ f.cwe_recommendation }}
{% endif %}

**Status:** {{ f.status | status_label }}
{% if f.compensating_control_description %}
**Kompensation:** {{ f.compensating_control_description }}
{% endif %}
```

---

## ÄNDERUNG 4: Methodikreferenz im Report (neu)
*Betrifft: Abschnitt 12 (Report-Templates)*

Jeder generierte Report erhält einen neuen Abschnitt **"Angewandte Methodik"** (nach dem Executive Summary, vor den Gerätestammdaten):

```markdown
## Angewandte Methodik und Standards

Dieses Assessment wurde durchgeführt nach folgenden anerkannten Standards:

| Standard | Relevanz |
|----------|----------|
| IEC 62443-3-2 | Security Risk Assessment für OT/ICS-Systeme (Risikobewertung, Zonen) |
| IEC 62443-4-2 | Component Security Requirements (Gerätebewertung) |
| NIST SP 800-82r3 | Guide to OT Security (OT-Risikomanagement) |
| NIST SP 800-115 | Technical Guide to Security Testing (Scan-Methodik) |
| NIST SP 800-30r1 | Risk Assessment Methodology (Impact × Likelihood) |

**Scan-Tool:** Nmap {{ nmap_version }}, Profil: {{ assessment.scan_profile }}
**Scan-Autorisierung:** {{ auth.authorized_by_name }} ({{ auth.authorized_by_role }}),
erteilt am {{ auth.authorization_date | date }}
**CVE-Datenquellen:** NIST NVD API v2, CISA KEV Catalog
**Bewertungsdatum:** {{ assessment.created_at | date }}
```

---

## ÄNDERUNG 5: Bewertungsdimensionen mit Standard-Referenz (Ergänzung)
*Betrifft: Abschnitt 7 (Scoring-Logik)*

In der Spec wird die Herkunft jedes Scores neu explizit dokumentiert.
Das Scoring-Modul soll pro Dimension die relevante Norm-Referenz mitführen:

```python
SCORE_DIMENSIONS = {
    "technical": {
        "label": "Technisch",
        "standard_ref": "IEC 62443-4-2 / NIST SP 800-82",
        "weight": 0.35,
    },
    "operational": {
        "label": "Betrieb",
        "standard_ref": "IEC 62443-3-2 / NIST SP 800-82 Ch.4",
        "weight": 0.20,
    },
    "compensation": {
        "label": "Kompensation",
        "standard_ref": "IEC 62443: Compensating Countermeasures",
        "weight": 0.20,
    },
    "lifecycle": {
        "label": "Lifecycle",
        "standard_ref": "IEC 62443-4-1 / NIST SP 800-30",
        "weight": 0.15,
    },
    "vendor": {
        "label": "Hersteller",
        "standard_ref": "IEC 62443-4-1 PSIRT / SDL",
        "weight": 0.10,
    },
}
```

---

## ÄNDERUNG 6: Neue Hintergrundaufgabe – KEV-Sync
*Betrifft: Abschnitt 2 (Tech Stack), Abschnitt 14 (Deployment)*

### KEV-Sync als Startup-Task

Beim Start der Applikation (und täglich via APScheduler oder einfachem Cron) soll der
KEV-Cache automatisch aktualisiert werden, sofern eine Internetverbindung besteht.

**In `app/main.py`:**
```python
@app.on_event("startup")
async def startup_event():
    # KEV-Cache aktualisieren (async, kein Blocking)
    asyncio.create_task(remediation_service.sync_kev_if_stale(max_age_hours=24))
```

Für den Raspberry Pi ohne dauerhaften Internet-Zugang: Bei fehlschlagendem Download
wird der vorhandene Cache verwendet. Erster Sync kann manuell über `/api/system/kev-sync`
ausgelöst werden.

**Neue Dependency in `requirements.txt`:**
```
# Kein neues Paket nötig – httpx ist bereits enthalten
```

---

## ÄNDERUNG 7: POA&M – Plan of Action and Milestones (neu im Report)
*Betrifft: Abschnitt 12 (Report-Templates), Abschnitt 4 (Datenmodell)*

NIST SP 800-37 sieht neben dem SAR immer auch einen **POA&M** vor.
Im BDSA-Tool wird dieser als letzter Report-Abschnitt generiert.

### Neue DB-Tabelle: `action_items`

```
id                    INTEGER PK
assessment_id         INTEGER FK
finding_id            INTEGER FK (optional)
title                 TEXT
description           TEXT
responsible_team      TEXT          -- z.B. "Broadcast Engineering", "IT Security"
priority              TEXT          -- Enum: immediate, short_term, long_term
due_date              DATE
status                TEXT          -- Enum: open, in_progress, done
created_at            DATETIME
updated_at            DATETIME
```

### Im Report-Template (letzter Abschnitt):

```markdown
## Plan of Action and Milestones (POA&M)

| Priorität | Massnahme | Verantwortlich | Fällig | Status |
|-----------|-----------|----------------|--------|--------|
{% for item in action_items | sort(attribute='priority') %}
| {{ item.priority | prio_label }} | {{ item.title }} | {{ item.responsible_team }} | {{ item.due_date }} | {{ item.status | status_label }} |
{% endfor %}
```

### UI-Element (assessment.html, Tab "Massnahmen"):

Einfaches Formular zum Erfassen von Massnahmen mit Verantwortlichen, Priorität und
Fälligkeitsdatum. Diese erscheinen dann automatisch im Report.

---

## ÄNDERUNG 8: Re-Assessment-Datum als Pflichtfeld (Ergänzung)
*Betrifft: Abschnitt 4.2 (assessments-Tabelle), Abschnitt 11 (Frontend)*

Das Re-Assessment-Datum soll beim Abschluss eines Assessments ein **Pflichtfeld** sein
(bisher nur "empfohlen"). Empfohlene Standardwerte als Vorbefüllung im UI:

| Gesamtbewertung | Empfohlenes Re-Assessment |
|-----------------|--------------------------|
| Grün            | +24 Monate               |
| Gelb            | +18 Monate               |
| Orange          | +12 Monate               |
| Rot             | Nicht freigegeben – kein Datum, stattdessen Massnahmenplan |

---

## ZUSAMMENFASSUNG DER ÄNDERUNGEN

| Bereich | Änderung | Priorität für MVP |
|---------|----------|------------------|
| DB | Neue Tabelle `scan_authorizations` | ✅ MVP |
| DB | Neue Tabelle `kev_cache` | ✅ MVP |
| DB | Neue Tabelle `action_items` | 🔶 Phase 2 |
| Service | `remediation_service.py` mit NVD + KEV + CWE | ✅ MVP (minimal) |
| Service | KEV-Sync beim Startup | ✅ MVP |
| API | `POST/GET /scan/authorize` | ✅ MVP |
| API | `GET /findings/{id}/remediation` | ✅ MVP |
| API | `POST /system/kev-sync` | ✅ MVP |
| Frontend | Scan-Autorisierungsmodal | ✅ MVP |
| Frontend | Finding-Block mit Lösungsvorschlägen | ✅ MVP |
| Frontend | POA&M-Tab | 🔶 Phase 2 |
| Report | Methodikabschnitt mit Normenreferenz | ✅ MVP |
| Report | Lösungsvorschläge pro Finding (YAML + KEV + NVD) | ✅ MVP |
| Report | POA&M-Tabelle | 🔶 Phase 2 |
| Scoring | Standard-Referenz pro Dimension | ✅ MVP |

---

## NEUE EXTERNE ABHÄNGIGKEITEN / DATENQUELLEN

| Quelle | URL | Typ | Offline-fähig | Kostenlos |
|--------|-----|-----|---------------|-----------|
| NIST NVD CVE API v2 | `services.nvd.nist.gov/rest/json/cves/2.0` | REST API | Nein (Cache) | Ja |
| NIST NVD CPE API v2 | `services.nvd.nist.gov/rest/json/cpes/2.0` | REST API | Nein (Cache) | Ja |
| CISA KEV JSON Feed | `cisa.gov/.../known_exploited_vulnerabilities.json` | JSON-Download | Ja (lokaler Cache) | Ja |

Alle drei Quellen sind ohne Registrierung nutzbar. Ein NVD API-Key (kostenlos registrierbar)
erhöht das Rate-Limit von 5 auf 50 Requests/30 Sekunden.

**Für Pi-Betrieb ohne Internet:** KEV-Cache aus letztem Download, NVD-Cache (7 Tage TTL).
Beides graceful degradiert bei fehlender Verbindung.

---

*Update-Dokument zu BDSA_SPEC.md v1.0 | März 2026*
# BDSA_SPEC.md – Update v1.2
## Offline-Betrieb: Zweiphasiger Workflow (Scan → Export → Report)

Ergänzung zu v1.0 und v1.1 | Stand: März 2026

---

## Kontext und Problemstellung

Der Raspberry Pi wird im Produktionsnetz eingesetzt und hat **keinen Internetzugang**
(Air-Gap-Betrieb). CVE-Lookups, KEV-Sync und NVD-Abfragen sind dort nicht möglich.

Die Lösung ist ein **zweiphasiger Workflow**:

```
┌─────────────────────────────────────────┐     ┌──────────────────────────────────────┐
│  PHASE 1: Scan-System (Pi, offline)     │     │  PHASE 2: Report-System (online)     │
│                                         │     │                                      │
│  • Gerät erfassen                       │     │  • Scan-Paket importieren            │
│  • Scan-Autorisierung dokumentieren     │  →  │  • CVE / KEV Lookup durchführen      │
│  • Nmap-Scan ausführen                  │ USB │  • Manuelle Fragen beantworten       │
│  • Regelwerk anwenden                   │     │  • Review / Scoring                  │
│  • Scan-Paket exportieren (.bdsa)       │     │  • Report generieren (MD/HTML/JSON)  │
└─────────────────────────────────────────┘     └──────────────────────────────────────┘
```

Beide Systeme laufen mit **derselben BDSA-Softwareinstallation**. Das Format für den
Datenaustausch ist ein portables `.bdsa`-Paket (JSON, signiert, mit Prüfsumme).

---

## 1. Das `.bdsa`-Paketformat

Ein `.bdsa`-Paket ist ein **ZIP-Archiv** mit der Dateiendung `.bdsa` und folgendem Inhalt:

```
assessment-20251115-gerät-xyz.bdsa  (ZIP)
├── manifest.json          # Metadaten, Versionierung, Checksummen
├── device.json            # Gerätestammdaten
├── assessment.json        # Assessment-Status, Scores, manuelle Findings
├── scan_results.json      # Alle Scan-Resultate (geparste Nmap-Daten)
├── scan_raw.xml           # Roher Nmap-XML-Output (für Audit)
├── findings.json          # Vom Regelwerk erzeugte Findings
├── authorization.json     # Scan-Autorisierung (Name, Rolle, Datum)
└── rules_snapshot.json    # Snapshot der verwendeten Regelwerk-Version
```

### `manifest.json` – Struktur

```json
{
  "bdsa_version": "1.0",
  "package_id": "uuid4-hier",
  "created_at": "2025-11-15T14:32:00Z",
  "created_on_host": "pi-broadcast-scan-01",
  "phase": "scan_complete",
  "device_id": 42,
  "assessment_id": 17,
  "checksums": {
    "device.json": "sha256:abc123...",
    "scan_results.json": "sha256:def456...",
    "scan_raw.xml": "sha256:ghi789...",
    "findings.json": "sha256:jkl012..."
  },
  "nmap_version": "7.94",
  "scan_profile": "passive",
  "rules_version": "2025-11-01"
}
```

Die SHA256-Checksummen aller Dateien werden beim Export berechnet und beim Import
verifiziert. Das stellt die **Integrität der Scan-Daten** sicher und ist für die
Nachvollziehbarkeit im Sinne von NIST SP 800-115 wichtig.

---

## 2. Neuer Service: `services/package_service.py`

```python
class PackageService:

    def export_package(self, assessment_id: int) -> bytes:
        """
        Erstellt ein .bdsa-Paket aus einem abgeschlossenen Scan.
        Berechnet SHA256-Checksummen aller enthaltenen Dateien.
        Gibt ZIP-Bytes zurück (für HTTP-Download oder Datei-Export).
        Voraussetzung: Assessment muss Status 'scan_complete' haben.
        """

    def import_package(self, package_bytes: bytes) -> ImportResult:
        """
        Importiert ein .bdsa-Paket auf dem Report-System.
        Prüft:
        - bdsa_version kompatibel?
        - Alle Checksummen gültig?
        - Assessment-ID bereits vorhanden? (Duplikat-Handling)
        Erstellt Device + Assessment + ScanResults in der lokalen DB.
        Setzt Assessment-Status auf 'imported_awaiting_enrichment'.
        """

    def verify_package(self, package_bytes: bytes) -> VerificationResult:
        """
        Nur Verifikation ohne Import – für Vorab-Check im UI.
        Gibt zurück: valid=True/False, fehler=[], warnings=[]
        """
```

---

## 3. Neue API-Endpunkte

```
# Scan-System (Phase 1)
GET  /api/assessments/{id}/export          # .bdsa-Paket herunterladen
GET  /api/assessments/{id}/export/verify   # Paket-Metadaten vorab anzeigen

# Report-System (Phase 2)
POST /api/import                           # .bdsa-Paket hochladen und importieren
POST /api/import/verify                    # Paket prüfen ohne Import
GET  /api/import/history                   # Liste importierter Assessments
```

---

## 4. Assessment-Status-Erweiterung

Das `status`-Feld in der `assessments`-Tabelle erhält neue Werte für den
zweiphasigen Workflow:

```python
class AssessmentStatus(str, Enum):
    # Phase 1 (Scan-System)
    DRAFT                      = "draft"
    IN_PROGRESS                = "in_progress"
    SCAN_RUNNING               = "scan_running"
    SCAN_COMPLETE              = "scan_complete"       # → Export möglich
    EXPORTED                   = "exported"            # Paket wurde erstellt

    # Phase 2 (Report-System)
    IMPORTED                   = "imported"            # Paket erfolgreich importiert
    ENRICHMENT_PENDING         = "enrichment_pending"  # CVE/KEV-Lookup läuft
    ENRICHMENT_DONE            = "enrichment_done"     # Bereit für manuelle Ergänzung
    MANUAL_INPUT               = "manual_input"        # Manuelle Fragen werden beantwortet
    REVIEW                     = "review"              # Reviewer prüft
    COMPLETED                  = "completed"           # Report generiert
```

---

## 5. UI-Erweiterungen

### 5.1 Phase-1-Ansicht: Export-Button (assessment.html)

Nach erfolgreichem Scan erscheint im Tab "Übersicht":

```
┌─────────────────────────────────────────────────────────────────────┐
│  ✅ Scan abgeschlossen (15.11.2025, 14:32)                          │
│                                                                     │
│  📦 Scan-Paket exportieren                                          │
│  Exportiert alle Scan-Resultate, Findings und Autorisierungsdaten   │
│  in ein portables .bdsa-Paket für die Weiterverarbeitung auf einem  │
│  System mit Internetzugang.                                         │
│                                                                     │
│  Enthaltene Daten:                                                  │
│  ✓ Gerätestammdaten       ✓ Nmap-Rohdaten (XML)                    │
│  ✓ Geparste Scan-Resultate ✓ Regelwerk-Findings                    │
│  ✓ Scan-Autorisierung      ✓ Regelwerk-Snapshot                    │
│                                                                     │
│  ⚠️  Das Paket enthält möglicherweise vertrauliche Infrastruktur-  │
│     informationen. Sicher transportieren (verschlüsselter USB).     │
│                                                                     │
│  [ 📥 assessment-20251115-geraet-xyz.bdsa herunterladen ]           │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Phase-2-Ansicht: Import-Seite (neue Seite `import.html`)

```
┌─────────────────────────────────────────────────────────────────────┐
│  📤 Scan-Paket importieren                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  [ .bdsa-Datei auswählen oder hier ablegen ]                        │
│                                                                     │
│  Nach dem Import:                                                   │
│  → CVE/KEV-Lookup wird automatisch gestartet                        │
│  → Manuelle Fragen können ausgefüllt werden                         │
│  → Report kann generiert werden                                     │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  PAKET-VORSCHAU (nach Upload, vor Import)                           │
│                                                                     │
│  Gerät:          Grass Valley AMPP Node 2.1.4                      │
│  Assessment:     #17 vom 15.11.2025                                 │
│  Scan-Profil:    passive                                            │
│  Autorisiert:    Max Muster (Broadcast Engineering)                 │
│  Findings:       3 High, 2 Medium, 1 Low                           │
│  Integrität:     ✅ Alle Checksummen gültig                         │
│  BDSA-Version:   1.0 (kompatibel)                                  │
│                                                                     │
│         [Abbrechen]           [Importieren und anreichern →]        │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.3 Statusanzeige im Dashboard (index.html)

Auf dem Dashboard wird der Betriebsmodus des aktuellen Systems angezeigt:

```
┌────────────────────────────────────────────────────────┐
│  BDSA v1.0  │  🔴 Offline-Modus (kein Internet)        │
│             │  Scan-Betrieb aktiv | CVE-Lookup deaktiviert │
└────────────────────────────────────────────────────────┘
```

Alternativ im Online-Modus:
```
┌────────────────────────────────────────────────────────┐
│  BDSA v1.0  │  🟢 Online  │  KEV-Cache: 15.11.2025      │
└────────────────────────────────────────────────────────┘
```

Der Modus wird beim Start automatisch erkannt (Ping-Check auf `nvd.nist.gov`).

---

## 6. Offline-Modus: Automatische Erkennung und Verhalten

```python
# In config.py
class Settings(BaseSettings):
    # ...
    BDSA_OFFLINE_MODE: bool = False   # Kann manuell erzwungen werden
    BDSA_CONNECTIVITY_CHECK_URL: str = "https://nvd.nist.gov"
    BDSA_CONNECTIVITY_TIMEOUT: int = 5  # Sekunden
```

```python
# In services/connectivity_service.py
async def check_internet() -> bool:
    """
    Prüft beim Start und danach stündlich.
    Ergebnis wird gecacht, kein Blocking bei Requests.
    """
```

**Verhalten je nach Modus:**

| Feature | Online | Offline |
|---------|--------|---------|
| Nmap-Scan | ✅ | ✅ |
| Regelwerk-Findings | ✅ | ✅ |
| Report generieren (ohne CVE) | ✅ | ✅ |
| CVE-Lookup (NVD API) | ✅ | ❌ (Hinweis im UI) |
| KEV-Check | ✅ (Cache) | ✅ (lokaler Cache, falls vorhanden) |
| KEV-Sync | ✅ | ❌ |
| .bdsa-Export | ✅ | ✅ |
| .bdsa-Import | ✅ | ✅ |
| NVD-Lösungsvorschläge | ✅ | ❌ (CWE-Empfehlung als Fallback) |

---

## 7. Änderungen an der Projektstruktur

Neue Dateien ergänzen die bestehende Struktur aus BDSA_SPEC.md v1.0:

```
app/
  api/
    import_export.py       # NEU: Export + Import Endpunkte
  services/
    package_service.py     # NEU: .bdsa-Paket erstellen/lesen/verifizieren
    connectivity_service.py # NEU: Internet-Check, Modus-Erkennung
  models/
    import_log.py          # NEU: Protokoll importierter Pakete
```

### Neue DB-Tabelle: `import_log`

```
id                    INTEGER PK
package_id            TEXT              -- UUID aus manifest.json
assessment_id         INTEGER FK
imported_at           DATETIME
imported_by           TEXT              -- BDSA-Username
source_host           TEXT              -- created_on_host aus manifest
package_checksum      TEXT              -- SHA256 des gesamten .bdsa-Archivs
status                TEXT              -- success / failed
error_message         TEXT
```

---

## 8. Aktualisierte Implementierungsreihenfolge

Die ursprüngliche Reihenfolge (Abschnitt 20 in v1.0) wird um zwei Schritte ergänzt:

```
1.  Projektstruktur + DB-Modell + Alembic
2.  Config + Auth + Connectivity-Check (Offline-Erkennung)
3.  Device CRUD API + Frontend
4.  Nmap Service + Scan API
5.  Scan-Autorisierung (v1.1)
6.  Rule Engine + YAML-Regelwerk
7.  Scoring Service
8.  Assessment API + Frontend
9.  Manuelle Fragen
10. Package Service: Export (.bdsa erstellen)         ← NEU
11. Package Service: Import (.bdsa lesen/verifizieren) ← NEU
12. Import-Seite im Frontend                          ← NEU
13. Report Service + Templates (inkl. Methodikblock)
14. CVE/KEV Service + Remediation Service (v1.1)
15. Dashboard-Statusanzeige (Online/Offline)          ← NEU
16. Docker + systemd Deployment-Files
17. Tests (Rule Engine, Scoring, Package-Integrität, Import/Export)
```

---

## 9. Sicherheitshinweis zum Paket-Transport

Der Hinweis im UI (Abschnitt 5.1) ist wichtig: Ein `.bdsa`-Paket enthält
Infrastrukturinformationen (IP-Adressen, offene Ports, Firmware-Versionen).

**Empfehlung für die Dokumentation / README:**
- Transport auf verschlüsseltem USB-Stick (z.B. VeraCrypt-Container)
- Alternativ: SFTP-Übertragung ins interne Netz falls ein sicherer Kanal existiert
- Paket nach Import auf dem Report-System sicher löschen
- Keine Ablage auf freigegebenen Netzwerklaufwerken ohne Zugriffskontrolle

---

*Update-Dokument zu BDSA_SPEC.md v1.0 und v1.1 | März 2026*
# BDSA_SPEC.md – Update v1.2 Patch: Manueller Online/Offline-Modus

Ergänzung zu v1.2 | Stand: März 2026

---

## Problem

In v1.2 ist der Offline-Modus nur über die `.env`-Variable `BDSA_OFFLINE_MODE`
steuerbar, was einen App-Neustart erfordert. Das ist im Betrieb unpraktisch –
insbesondere wenn der Pi temporär an einen Hotspot angeschlossen wird,
oder wenn der automatische Check ein falsches Ergebnis liefert.

---

## Lösung: Drei-Stufen-Modell

```
┌──────────────────────────────────────────────────────────────────┐
│  Modus-Priorität (höher = gewinnt)                               │
│                                                                  │
│  3. Manuell OFFLINE erzwungen  (UI-Schalter, persistent in DB)  │
│  2. Manuell ONLINE erzwungen   (UI-Schalter, persistent in DB)  │
│  1. Automatisch erkannt        (Ping-Check, stündlich)          │
└──────────────────────────────────────────────────────────────────┘
```

Der manuelle Override wird in der DB gespeichert und überlebt einen Neustart.
Er kann jederzeit auf "Auto" zurückgestellt werden.

---

## Neue DB-Tabelle: `system_settings`

Eine einfache Key-Value-Tabelle für persistente Laufzeit-Einstellungen:

```
key           TEXT PRIMARY KEY
value         TEXT
updated_at    DATETIME
updated_by    TEXT
```

Initialer Eintrag beim ersten Start:
```
key="connectivity_mode"  value="auto"  (auto | force_online | force_offline)
```

---

## Neuer API-Endpunkt

```
GET  /api/system/settings                        # Alle Settings abrufen
GET  /api/system/connectivity                    # Aktuellen Modus + Status abrufen
POST /api/system/connectivity/mode               # Modus manuell setzen
POST /api/system/connectivity/check              # Sofortigen Check auslösen
```

**POST `/api/system/connectivity/mode` Body:**
```json
{ "mode": "auto" }          // Automatik (Standard)
{ "mode": "force_online" }  // Online erzwingen
{ "mode": "force_offline" } // Offline erzwingen
```

**GET `/api/system/connectivity` Response:**
```json
{
  "mode_setting": "force_offline",
  "auto_detected": true,
  "effective_mode": "offline",
  "last_check": "2025-11-15T14:30:00Z",
  "nvd_reachable": false,
  "kev_cache_age_hours": 48,
  "override_active": true
}
```

---

## UI: Settings-Seite (neue Seite `settings.html`)

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⚙️  System-Einstellungen                                           │
├─────────────────────────────────────────────────────────────────────┤
│  KONNEKTIVITÄT                                                      │
│                                                                     │
│  Aktueller Status:  🔴 Offline  (manuell erzwungen)                │
│  Automatische Erkennung:  ✅ Erreichbar (nvd.nist.gov)             │
│  Letzter Check:     15.11.2025, 14:30                              │
│                                                                     │
│  Modus:                                                             │
│  ◉ Automatisch erkennen   (empfohlen)                              │
│  ○ Online erzwingen       (CVE/KEV immer aktiv)                    │
│  ○ Offline erzwingen      (kein externer Zugriff, z.B. Pi im Netz) │
│                                                                     │
│  [ Jetzt prüfen ]                   [ Speichern ]                  │
├─────────────────────────────────────────────────────────────────────┤
│  KEV-CACHE                                                          │
│                                                                     │
│  Letzter Sync:   13.11.2025  (vor 48 Stunden)   ⚠️ Veraltet        │
│  Einträge:       1'247 CVEs                                         │
│                                                                     │
│  [ KEV jetzt synchronisieren ]                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Anpassung: Statusanzeige im Dashboard (index.html)

Der Modus-Badge im Header zeigt neu auch den Override-Zustand:

| Situation | Badge |
|-----------|-------|
| Auto, online erkannt | 🟢 Online (Auto) |
| Auto, offline erkannt | 🔴 Offline (Auto) |
| Manuell online erzwungen | 🟢 Online (Manuell) |
| Manuell offline erzwungen | 🔴 Offline (Manuell) |

Klick auf den Badge öffnet direkt die Settings-Seite.

---

## Anpassung: `.env`-Variable entfällt

`BDSA_OFFLINE_MODE` aus der `.env` wird **entfernt**. Der initiale Modus ist
immer "auto". Wer beim Start einen festen Modus braucht, kann das entweder:

- über die Settings-Seite nach dem ersten Start setzen (wird persistent gespeichert), oder
- via `BDSA_INITIAL_CONNECTIVITY_MODE=force_offline` in der `.env` vorgeben
  (wird nur beim **allerersten Start** in die DB geschrieben, danach ignoriert).

---

*Patch zu BDSA_SPEC.md v1.2 | März 2026*
# BDSA_SPEC.md – Update v1.3
## USB-Export mit optionaler Verschlüsselung

Ergänzung zu v1.0–v1.2 | Stand: März 2026

---

## Übersicht

Der Pi hat keinen Internetzugang und keine Sicht auf andere Netze. Scan-Pakete
müssen physisch via USB transportiert werden. Das BDSA-Webinterface steuert
den gesamten Vorgang: USB-Stick erkennen, Exportinhalt wählen, optional
verschlüsseln, auf Stick schreiben – und auf dem Online-System wieder importieren.

```
[Pi, offline]                              [Workstation, online]
     │                                              │
     │  1. USB eingesteckt                          │
     │  2. Stick im UI auswählen                    │
     │  3. Exportinhalt wählen                      │
     │  4. Optional: Verschlüsselung                │
     │  5. Auf Stick schreiben                      │
     │         │                                    │
     │        USB ──────────────────────────────►  │
     │                                              │  6. Stick im UI auswählen
     │                                              │  7. Paket(e) importieren
     │                                              │  8. Entschlüsseln (falls nötig)
     │                                              │  9. CVE/KEV-Anreicherung
```

---

## 1. Verschlüsselung: Shared Secret (AES-256-GCM)

### Funktionsweise

Beide Systeme teilen denselben **Shared Secret Key**, der in den System-Settings
hinterlegt ist. Beim Export wird die `.bdsa`-Datei (oder das Backup) damit
verschlüsselt. Beim Import erkennt das Tool automatisch verschlüsselte Dateien
und entschlüsselt sie mit dem lokal gespeicherten Key.

**Algorithmus:** AES-256-GCM
- Authenticated Encryption: Integrität und Vertraulichkeit in einem Schritt
- Kein separater HMAC nötig
- Pi-kompatibel: läuft mit Python `cryptography`-Library ohne Hardware-Anforderungen

**Key-Derivation:** Der Shared Secret (beliebiger String aus den Settings) wird via
PBKDF2-HMAC-SHA256 mit einem zufälligen Salt in einen 256-Bit-AES-Key umgewandelt.
Salt und IV werden im verschlüsselten Container mitgeliefert.

### Dateiformat verschlüsselter Pakete

```
verschlüsselte Datei: assessment-20251115.bdsa.enc

Aufbau (binär):
┌──────────────────────────────────────────┐
│  Magic Bytes: "BDSA" (4 Bytes)           │  ← Erkennung ob verschlüsselt
│  Version: 0x01 (1 Byte)                  │
│  Salt: 16 Bytes (zufällig)               │  ← für PBKDF2
│  IV/Nonce: 12 Bytes (zufällig)           │  ← für AES-GCM
│  Encrypted Payload (variable Länge)      │  ← ZIP-Archiv (.bdsa)
│  GCM Auth Tag: 16 Bytes                  │  ← Integritätsnachweis
└──────────────────────────────────────────┘
```

Nicht verschlüsselte Dateien behalten die Endung `.bdsa`.
Verschlüsselte Dateien erhalten die Endung `.bdsa.enc`.

Das Tool erkennt beim Import automatisch anhand der Magic Bytes, ob eine Datei
verschlüsselt ist, und versucht sie mit dem gespeicherten Key zu entschlüsseln.

### Key-Verwaltung in den Settings

**In `system_settings`-Tabelle** (neu):
```
key="encryption_enabled"        value="true" / "false"
key="encryption_key_hash"       value="sha256(shared_secret)"  ← nur zur Verifikation
```

Der Shared Secret selbst wird **nicht** in der DB gespeichert – nur ein SHA256-Hash
zur Verifikation, dass beide Systeme denselben Key haben.

**In `.env` / `BDSA_SHARED_SECRET`:**
```env
BDSA_SHARED_SECRET=mein-sicheres-passwort-hier
```

Alternativ: Eingabe über die Settings-Seite im UI (wird in `.env` persistiert,
erfordert keinen Neustart dank `python-dotenv` write-back).

### Settings-Seite: Verschlüsselung

```
┌─────────────────────────────────────────────────────────────────────┐
│  🔐 VERSCHLÜSSELUNG (USB-Export)                                    │
│                                                                     │
│  Status:  ✅ Aktiv  │  Key gesetzt: Ja  │  Algorithmus: AES-256-GCM │
│                                                                     │
│  Shared Secret:  [••••••••••••••••••]  [Anzeigen]  [Ändern]        │
│  Key-Fingerprint: sha256:3a7f...e291  (zur Verifikation)           │
│                                                                     │
│  ☑ Verschlüsselung beim USB-Export aktivieren                      │
│                                                                     │
│  ⚠️  Derselbe Shared Secret muss auf dem Import-System             │
│     hinterlegt sein. Ohne passenden Key sind die Daten             │
│     auf dem USB-Stick nicht lesbar.                                │
│                                                                     │
│  [ Key-Fingerprint in Zwischenablage kopieren ]                    │
└─────────────────────────────────────────────────────────────────────┘
```

Der **Key-Fingerprint** (SHA256 des Shared Secret, erste 8 Zeichen) kann auf
beiden Systemen verglichen werden, um sicherzustellen, dass sie denselben Key
verwenden – ohne den Key selbst preiszugeben.

---

## 2. USB-Erkennung: Auto mit manuellem Fallback

### Auto-Erkennung

```python
# services/usb_service.py

def detect_usb_devices() -> list[UsbDevice]:
    """
    Sucht nach gemounteten Wechselmedien.
    Prüft folgende Pfade:
    - /media/*           (Raspberry Pi OS Standard)
    - /media/<user>/*    (Desktop-Variante)
    - /mnt/*             (manuelle Mounts)
    Filtert:
    - Nur beschreibbare Partitionen
    - Mindestens 1 MB freier Speicher
    - Keine System-Mounts (/, /boot, /home, etc.)
    Gibt zurück: Label, Pfad, freier Speicher, Dateisystem
    """

def get_device_info(path: str) -> UsbDevice:
    """Liest Metadaten eines Pfads via os.statvfs()"""

def write_to_usb(path: str, filename: str, data: bytes) -> WriteResult:
    """Schreibt Datei auf USB, prüft freien Speicher vorher."""

def safe_eject(path: str) -> bool:
    """Sync + optional udisksctl power-off für sicheres Auswerfen."""
```

**`UsbDevice`-Schema:**
```python
class UsbDevice(BaseModel):
    path: str           # z.B. "/media/pi/STICK01"
    label: str          # z.B. "STICK01" oder "Untitled"
    filesystem: str     # z.B. "vfat", "exfat", "ext4"
    free_bytes: int
    total_bytes: int
    writable: bool
```

### API-Endpunkte: USB

```
GET  /api/usb/devices              # Alle erkannten USB-Medien auflisten
POST /api/usb/eject                # USB sicher auswerfen (body: {"path": "..."})
```

### Manueller Fallback

Falls kein USB-Stick automatisch erkannt wird, erscheint im UI ein Textfeld:
```
Pfad manuell eingeben:  [ /mnt/usb  ]  [ Prüfen ]
```
Das Backend validiert den Pfad (existiert, beschreibbar, kein System-Mount)
und gibt Rückmeldung.

---

## 3. USB-Export-Seite im UI (neue Seite `usb_export.html`)

Die Seite ist in drei Schritte aufgeteilt, die sequenziell durchlaufen werden.

### Schritt 1: USB-Stick auswählen

```
┌─────────────────────────────────────────────────────────────────────┐
│  💾 USB-Export                                          Schritt 1/3 │
├─────────────────────────────────────────────────────────────────────┤
│  USB-MEDIEN                                  [ 🔄 Aktualisieren ]   │
│                                                                     │
│  ◉  BDSA-EXPORT  │ /media/pi/BDSA-EXPORT │ FAT32 │ 14.2 GB frei   │
│  ○  UNTITLED     │ /media/pi/UNTITLED    │ exFAT │  3.1 GB frei   │
│                                                                     │
│  Kein Stick gefunden?                                               │
│  Pfad manuell:  [_______________________]  [ Prüfen ]              │
│                                                                     │
│                                          [ Weiter → ]              │
└─────────────────────────────────────────────────────────────────────┘
```

### Schritt 2: Exportinhalt wählen

```
┌─────────────────────────────────────────────────────────────────────┐
│  💾 USB-Export                                          Schritt 2/3 │
│  Ziel: BDSA-EXPORT (/media/pi/BDSA-EXPORT) │ 14.2 GB frei         │
├─────────────────────────────────────────────────────────────────────┤
│  WAS SOLL EXPORTIERT WERDEN?                                        │
│                                                                     │
│  ○  Einzelnes Assessment                                            │
│     [ Assessment auswählen ▼ ]                                      │
│     Assessment #17 – Grass Valley AMPP (15.11.2025) [scan_complete] │
│     Assessment #16 – Riedel MediorNet (08.11.2025)  [scan_complete] │
│     Assessment #14 – Evertz 7767DEC   (01.11.2025)  [exported]     │
│                                                                     │
│  ○  Mehrere Assessments (Batch)                                     │
│     ☑ #17 Grass Valley AMPP      ☑ #16 Riedel MediorNet           │
│     ☐ #14 Evertz 7767DEC (bereits exportiert)                      │
│                                                                     │
│  ○  Nur Reports (MD/HTML/JSON, ohne Scan-Rohdaten)                  │
│     [ Assessment auswählen ▼ ]                                      │
│                                                                     │
│  ○  Komplettes DB-Backup (alle Geräte, Assessments, Reports)        │
│     Geschätzte Grösse: ~4.2 MB                                      │
│                                                                     │
│                               [ ← Zurück ]  [ Weiter → ]           │
└─────────────────────────────────────────────────────────────────────┘
```

### Schritt 3: Verschlüsselung und Bestätigung

```
┌─────────────────────────────────────────────────────────────────────┐
│  💾 USB-Export                                          Schritt 3/3 │
│  Ziel: BDSA-EXPORT │ Inhalt: 2 Assessments (#17, #16)              │
├─────────────────────────────────────────────────────────────────────┤
│  VERSCHLÜSSELUNG                                                    │
│                                                                     │
│  ☑ Verschlüsseln (AES-256-GCM)                                     │
│    Key-Fingerprint: sha256:3a7f...e291                              │
│    ⚠️  Stellen Sie sicher, dass das Import-System denselben Key     │
│       hat (Fingerprint vergleichen).                               │
│                                                                     │
│  ☐ Unverschlüsselt exportieren                                     │
│    Die .bdsa-Pakete sind ohne Key lesbar (z.B. für Weitergabe      │
│    an externe Stellen oder andere Tools).                          │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  ZUSAMMENFASSUNG                                                    │
│                                                                     │
│  Dateien:   assessment-20251115-ampp.bdsa.enc                      │
│             assessment-20251108-mediornet.bdsa.enc                 │
│  Grösse:    ~2.8 MB (verschlüsselt)                                │
│  Freier Speicher nach Export: 14.2 GB                              │
│                                                                     │
│  ☑ Ich bestätige, dass der USB-Stick sicher transportiert wird.    │
│    (Vertrauliche Infrastrukturinformationen)                        │
│                                                                     │
│             [ ← Zurück ]        [ 💾 Jetzt auf USB schreiben ]     │
└─────────────────────────────────────────────────────────────────────┘
```

### Nach dem Export: Bestätigung + Auswerfen

```
┌─────────────────────────────────────────────────────────────────────┐
│  ✅ Export erfolgreich                                               │
│                                                                     │
│  Geschrieben nach: /media/pi/BDSA-EXPORT/                          │
│  assessment-20251115-ampp.bdsa.enc          ✅  1.4 MB             │
│  assessment-20251108-mediornet.bdsa.enc     ✅  1.4 MB             │
│                                                                     │
│  SHA256-Prüfsummen:                                                 │
│  3a7f...e291  assessment-20251115-ampp.bdsa.enc                    │
│  9b2c...f104  assessment-20251108-mediornet.bdsa.enc               │
│                                                                     │
│  [ 🔌 USB sicher auswerfen ]          [ Zurück zum Dashboard ]     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 4. USB-Import-Seite im UI (Erweiterung von `import.html`)

Das Import-System (online) erhält dieselbe USB-Erkennung.
Zusätzlich zu "Datei hochladen" gibt es neu die Option "Vom USB-Stick importieren":

```
┌─────────────────────────────────────────────────────────────────────┐
│  📤 Scan-Paket importieren                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ○  Datei hochladen  [ .bdsa oder .bdsa.enc auswählen ]            │
│                                                                     │
│  ◉  Vom USB-Stick lesen                                             │
│     Stick: BDSA-EXPORT (/media/.../BDSA-EXPORT) [ Aktualisieren ]  │
│                                                                     │
│     Gefundene Pakete:                                               │
│     ☑  assessment-20251115-ampp.bdsa.enc      🔐 1.4 MB  ✅ gültig │
│     ☑  assessment-20251108-mediornet.bdsa.enc 🔐 1.4 MB  ✅ gültig │
│     ☐  assessment-20251101-evertz.bdsa.enc    🔐 1.4 MB  ✅ gültig │
│                                                                     │
│     🔐 Verschlüsselt – Key-Fingerprint: sha256:3a7f...e291         │
│     ✅ Fingerprint stimmt mit lokalem Key überein                   │
│                                                                     │
│     [ Ausgewählte importieren und anreichern → ]                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 5. Neue API-Endpunkte: USB-Export/-Import

```
# USB-Geräteverwaltung
GET  /api/usb/devices                        # USB-Sticks auflisten
POST /api/usb/eject                          # Sicher auswerfen

# Export
POST /api/usb/export                         # Export starten
GET  /api/usb/export/{job_id}/status         # Export-Fortschritt abfragen

# Import vom USB
GET  /api/usb/import/scan                    # Pakete auf Stick auflisten
POST /api/usb/import                         # Pakete vom Stick importieren
```

**POST `/api/usb/export` Body:**
```json
{
  "target_path": "/media/pi/BDSA-EXPORT",
  "export_type": "batch",
  "assessment_ids": [17, 16],
  "encrypt": true,
  "include_raw": true
}
```

`export_type` Werte: `single` | `batch` | `reports_only` | `full_backup`

---

## 6. Neuer Service: `services/usb_service.py`

Ergänzung zu den in Abschnitt 2 bereits beschriebenen Methoden:

```python
class UsbService:

    def detect_usb_devices(self) -> list[UsbDevice]: ...

    def validate_path(self, path: str) -> ValidationResult:
        """
        Prüft ob Pfad:
        - existiert und ein Verzeichnis ist
        - beschreibbar ist
        - kein System-Mount ist (/proc, /sys, /boot, /, /home, etc.)
        - genug freien Speicher hat
        """

    def write_export(
        self,
        target_path: str,
        filename: str,
        data: bytes,
        encrypt: bool
    ) -> WriteResult:
        """
        Schreibt Daten auf USB.
        Falls encrypt=True: AES-256-GCM mit Shared Secret.
        Gibt Pfad, Grösse und SHA256-Prüfsumme zurück.
        """

    def read_package_from_usb(
        self,
        source_path: str
    ) -> bytes:
        """
        Liest .bdsa oder .bdsa.enc vom USB.
        Erkennt Verschlüsselung automatisch via Magic Bytes.
        Entschlüsselt falls nötig.
        """

    def list_packages_on_usb(
        self,
        usb_path: str
    ) -> list[UsbPackageInfo]:
        """
        Listet alle .bdsa und .bdsa.enc Dateien auf einem USB-Stick.
        Prüft pro Datei: Checksummen, BDSA-Version, verschlüsselt ja/nein,
        Key-Fingerprint-Match.
        """

    def safe_eject(self, path: str) -> bool: ...
```

---

## 7. Neuer Service: `services/crypto_service.py`

```python
class CryptoService:

    def encrypt(self, data: bytes, shared_secret: str) -> bytes:
        """
        Verschlüsselt Bytes mit AES-256-GCM.
        Generiert zufälligen Salt (16 Bytes) und IV (12 Bytes).
        Leitet Key via PBKDF2-HMAC-SHA256 ab (100'000 Iterationen).
        Gibt: Magic(4) + Version(1) + Salt(16) + IV(12) +
               Ciphertext(var) + AuthTag(16) zurück.
        """

    def decrypt(self, data: bytes, shared_secret: str) -> bytes:
        """
        Entschlüsselt AES-256-GCM-Daten.
        Wirft DecryptionError bei falschem Key oder manipulierten Daten.
        """

    def is_encrypted(self, data: bytes) -> bool:
        """Prüft Magic Bytes: b'BDSA' am Anfang."""

    def get_key_fingerprint(self, shared_secret: str) -> str:
        """
        Gibt ersten 16 Zeichen des SHA256(shared_secret) zurück.
        Format: "sha256:3a7fe291..."
        Dient dem Abgleich zwischen zwei Systemen ohne Key-Offenlegung.
        """
```

---

## 8. Neue Abhängigkeiten

```
# requirements.txt – Ergänzungen
cryptography>=42.0.0    # AES-256-GCM, PBKDF2 (bereits weit verbreitet, Pi-kompatibel)
```

`cryptography` ist die einzige neue Abhängigkeit. Sie ist auf ARM64/Pi4 ohne
Compilation verfügbar (`pip install cryptography` läuft out-of-the-box).

---

## 9. Sicherheitsaspekte

**Shared Secret Stärke:**
Die Settings-Seite zeigt beim Eingeben des Shared Secret eine Stärkeindikation
(Länge, Entropie). Empfehlung: mind. 20 zufällige Zeichen. Ein Generator-Button
erzeugt einen sicheren Zufalls-Key.

**PBKDF2-Iterationen:**
100'000 Iterationen sind ein guter Kompromiss zwischen Sicherheit und
Performance auf dem Pi 4 (ca. 0.3 Sekunden pro Key-Derivation).

**Unverschlüsselter Export:**
Wenn Verschlüsselung deaktiviert ist, erscheint ein klarer Warnhinweis im UI.
Es gibt keine versteckte Deaktivierung – der Nutzer muss explizit bestätigen.

**Kein Key im Speicher halten:**
Der Shared Secret wird nach der Key-Derivation nicht im RAM gehalten.
Jeder Encrypt/Decrypt-Vorgang liest ihn neu aus der Konfiguration.

---

## 10. Aktualisierte Projektstruktur

```
app/
  api/
    usb.py                  # NEU: USB-Geräte, Export, Import vom Stick
  services/
    usb_service.py          # NEU: USB-Erkennung, Lesen/Schreiben
    crypto_service.py       # NEU: AES-256-GCM Encrypt/Decrypt
frontend/
  usb_export.html           # NEU: 3-Schritt-Export-Wizard
  settings.html             # ERWEITERT: Verschlüsselungs-Sektion
  import.html               # ERWEITERT: USB-Import-Option
```

---

## 11. Aktualisierte Implementierungsreihenfolge

```
...
10. Package Service: Export (.bdsa erstellen)
11. Crypto Service (AES-256-GCM)               ← NEU, vor USB
12. USB Service (Erkennung, Lesen, Schreiben)  ← NEU
13. USB-Export-Seite (3-Schritt-Wizard)        ← NEU
14. USB-Import-Option (Erweiterung import.html)← NEU
15. Package Service: Import (.bdsa lesen/verifizieren)
16. Report Service + Templates
17. CVE/KEV/Remediation Service
18. Settings-Seite (inkl. Verschlüsselung, Modus)
19. Dashboard-Statusanzeige
20. Docker + systemd
21. Tests (Crypto round-trip, USB-Mock, Package-Integrität)
```

---

*Update-Dokument zu BDSA_SPEC.md v1.0–v1.2 | März 2026*
# PiBroadGuard – BDSA_SPEC.md Update v1.4
## Finale Ergänzungen vor Konsolidierung

Ergänzung zu v1.0–v1.3 | Stand: März 2026

---

## Projektname: PiBroadGuard

**Vollständiger Name:** PiBroadGuard – Broadcast Device Security Assessment
**Kurzname:** PiBroadGuard
**GitHub-Repository:** `pibroadguard`
**GitHub-Topics:** `broadcast`, `security-assessment`, `nmap`, `ot-security`,
                   `iec-62443`, `raspberry-pi`, `python`, `fastapi`

Der Name ersetzt überall in der Codebase das Präfix `BDSA`:
- App-Titel im UI: "PiBroadGuard"
- Python-Package: `pibroadguard`
- Docker-Image: `pibroadguard`
- Dateiendung bleibt: `.bdsa` (etabliertes Format, nicht umbenennen)
- Umgebungsvariablen-Präfix: `PIBG_` (statt `BDSA_`)
- systemd-Service: `pibroadguard.service`

---

## 1. SQLite-Backup-Mechanismus

### Konsistentes Backup via VACUUM INTO

SQLite bietet den Befehl `VACUUM INTO '<pfad>'` für einen konsistenten
Hot-Backup ohne App-Stop. Das ist die einzige korrekte Methode –
ein simples `cp` der `.db`-Datei kann bei laufenden Writes inkonsistent sein.

### Neuer API-Endpunkt

```
POST /api/v1/system/backup              # Backup erstellen (lokal oder auf USB)
GET  /api/v1/system/backup/list         # Vorhandene Backups auflisten
GET  /api/v1/system/backup/{filename}   # Backup herunterladen
```

**POST `/api/v1/system/backup` Body:**
```json
{
  "destination": "local",       // "local" | "usb"
  "usb_path": "/media/pi/...",  // nur wenn destination=usb
  "encrypt": true               // optional, nutzt Shared Secret
}
```

### Backup-Dateiformat

```
pibroadguard-backup-20251115-143200.db          # unverschlüsselt
pibroadguard-backup-20251115-143200.db.enc      # verschlüsselt (AES-256-GCM)
```

Lokale Backups werden unter `./data/backups/` gespeichert.
Maximale Anzahl lokaler Backups: 5 (älteste werden automatisch gelöscht,
konfigurierbar via `PIBG_BACKUP_MAX_COUNT`).

### Backup-Eintrag in `system_settings`

```
key="last_backup_at"        value="2025-11-15T14:32:00Z"
key="last_backup_path"      value="./data/backups/pibroadguard-backup-..."
```

### UI: Backup-Sektion auf der Settings-Seite

```
┌─────────────────────────────────────────────────────────────────────┐
│  🗄️  DATENBANK-BACKUP                                               │
│                                                                     │
│  Letztes Backup:  15.11.2025, 14:32  (vor 2 Stunden)               │
│  Lokale Backups:  3 / 5  (älteste werden automatisch gelöscht)     │
│                                                                     │
│  Ziel:  ◉ Lokal speichern  ○ Auf USB-Stick                         │
│  ☑ Verschlüsseln (AES-256-GCM)                                     │
│                                                                     │
│  [ 🗄️ Backup jetzt erstellen ]   [ 📥 Letztes Backup herunterladen ]│
└─────────────────────────────────────────────────────────────────────┘
```

---

## 2. App-Logging mit Logfile

### Logging-Konfiguration

**In `app/core/logging_config.py`** (neue Datei):

```python
import logging
from logging.handlers import RotatingFileHandler

def setup_logging(log_level: str, log_path: str) -> None:
    """
    Konfiguriert strukturiertes Logging:
    - RotatingFileHandler: max 5 MB pro Datei, 3 Backups
    - StreamHandler: für Docker-Logs (stdout)
    - Format: ISO-Timestamp | Level | Logger | Message
    """
    fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    handlers = [
        RotatingFileHandler(
            log_path,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=3,
            encoding="utf-8"
        ),
        logging.StreamHandler()         # stdout für Docker
    ]

    logging.basicConfig(level=log_level, format=fmt,
                        datefmt=datefmt, handlers=handlers)
```

**Neue `.env`-Variablen:**
```env
PIBG_LOG_LEVEL=INFO          # DEBUG | INFO | WARNING | ERROR
PIBG_LOG_PATH=./data/logs/pibroadguard.log
```

### Was geloggt wird

| Logger | Level | Inhalt |
|--------|-------|--------|
| `pibroadguard.scan` | INFO/ERROR | Scan-Start, -Ende, Nmap-Exitcode |
| `pibroadguard.import` | INFO/ERROR | Import-Start, Checksummen-Fehler |
| `pibroadguard.usb` | INFO/WARNING | USB erkannt, Schreibfehler |
| `pibroadguard.crypto` | WARNING/ERROR | Entschlüsselungsfehler (kein Key-Logging!) |
| `pibroadguard.auth` | WARNING | Fehlgeschlagene Login-Versuche |
| `pibroadguard.api` | INFO | Alle API-Requests (nur im DEBUG-Modus) |
| `pibroadguard.backup` | INFO/ERROR | Backup-Start, -Ende, Fehler |

### Neuer API-Endpunkt (Admin)

```
GET /api/v1/system/logs?lines=100       # Letzte N Zeilen des Logfiles
GET /api/v1/system/logs/download        # Komplettes Logfile herunterladen
```

### UI: Log-Viewer auf der Settings-Seite

```
┌─────────────────────────────────────────────────────────────────────┐
│  📋 SYSTEM-LOG                                  [ 🔄 Aktualisieren ]│
│                                                                     │
│  [ INFO  | WARNING  | ERROR ]    Letzte: [ 50 ▼ ] Zeilen           │
│                                                                     │
│  2025-11-15T14:32:01 | INFO  | pibroadguard.scan | Scan #17 started   │
│  2025-11-15T14:32:45 | INFO  | pibroadguard.scan | Scan #17 completed │
│  2025-11-15T14:33:10 | INFO  | pibroadguard.usb  | USB detected: ...  │
│                                                                     │
│  [ 📥 Logfile herunterladen ]                                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Nmap Root-Privilegien (setcap)

SYN-Scans (`-sS`) benötigen Raw-Socket-Zugriff. Ohne Root-Rechte fällt
Nmap stillschweigend auf TCP-Connect-Scans (`-sT`) zurück – ohne
Fehlermeldung. Das verändert die Scan-Ergebnisse unbemerkt.

### Lösung: Linux Capabilities via setcap

**Empfohlene Methode (systemd-Deployment):**
```bash
sudo setcap cap_net_raw+ep $(which nmap)
```

Dies gibt Nmap gezielt `CAP_NET_RAW`, ohne den gesamten BDSA-Prozess
als root laufen zu lassen. Der `pibroadguard`-Service-User benötigt keine
sudo-Rechte.

**Docker-Deployment:** Bereits korrekt via `cap_add: [NET_RAW, NET_ADMIN]`
in `docker-compose.yml` (seit v1.0 vorgesehen).

### Startup-Check

Beim App-Start prüft `nmap_service.py`, ob SYN-Scans verfügbar sind:

```python
async def check_nmap_capabilities() -> NmapCapabilities:
    """
    Führt Test-SYN-Scan auf localhost aus.
    Wenn Output 'SYN Stealth Scan' enthält: raw sockets verfügbar.
    Wenn Output 'Connect Scan': nur TCP-Connect möglich.
    Gibt Warnung im Log aus und zeigt Badge im UI.
    """
```

### UI-Warnung (Dashboard, falls eingeschränkt)

```
⚠️  Nmap läuft ohne Raw-Socket-Rechte. SYN-Scans nicht verfügbar –
    nur TCP-Connect-Scans möglich (weniger präzise).
    Lösung: sudo setcap cap_net_raw+ep $(which nmap)
```

### README-Abschnitt "Installation"

```bash
# Nach der Installation, einmalig ausführen:
sudo setcap cap_net_raw+ep $(which nmap)

# Prüfen ob gesetzt:
getcap $(which nmap)
# Erwartete Ausgabe: /usr/bin/nmap cap_net_raw+ep
```

---

## 4. API-Versionierung (/api/v1/)

Alle API-Pfade werden von `/api/` auf `/api/v1/` umgestellt.
Dies betrifft die gesamte Spec – hier die Änderung einmalig dokumentiert:

### Änderung in main.py

```python
# Alle Router werden mit Prefix /api/v1 registriert
app.include_router(devices.router,    prefix="/api/v1")
app.include_router(assessments.router, prefix="/api/v1")
app.include_router(scans.router,      prefix="/api/v1")
app.include_router(reports.router,    prefix="/api/v1")
app.include_router(usb.router,        prefix="/api/v1")
app.include_router(system.router,     prefix="/api/v1")

# Unversioniert bleiben nur:
# GET /health    (Load-Balancer, Monitoring)
# GET /version   (App-Version)
```

### Versionsheader in Responses

Jede API-Response erhält den Header:
```
X-PiBroadGuard-Version: 1.0.0
X-PiBroadGuard-API: v1
```

### Zukunftssicherheit

Wenn Phase 3 ein Rollenmodell einführt, das Breaking Changes an der API
erfordert, kann `/api/v2/` parallel betrieben werden ohne v1-Clients
zu brechen. Das ist besonders relevant falls später externe Tools
(CMDB, Wiki, Ticketsystem) die PiBroadGuard-API direkt ansprechen.

---

## 5. Rate Limiting für Basic Auth

### Abhängigkeit

```
# requirements.txt – Ergänzung
slowapi>=0.1.9      # Rate Limiting für FastAPI, basiert auf limits
```

### Implementation in `app/core/security.py`

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

# In-Memory-Store (kein Redis nötig, ausreichend für Single-Instance)
# Limits: 10 Fehlversuche pro 5 Minuten pro IP
FAILED_AUTH_LIMIT = "10/5minutes"
```

```python
# In main.py
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
```

```python
# Nur der Auth-Endpunkt wird begrenzt – nicht alle API-Calls
# (Basic Auth wird bei jedem Request geprüft, daher am Auth-Handler)

def verify_credentials(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security)
):
    correct = (
        secrets.compare_digest(credentials.username, settings.username) and
        secrets.compare_digest(credentials.password, settings.password)
    )
    if not correct:
        # Fehlversuch loggen
        logger.warning(f"Failed auth attempt from {request.client.host}")
        # Rate Limit prüfen
        limiter.check()
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": "Basic"},
            detail="Ungültige Zugangsdaten"
        )
```

### Verhalten bei Überschreitung

- HTTP 429 Too Many Requests
- Response-Header: `Retry-After: 300` (5 Minuten)
- Log-Eintrag: `pibroadguard.auth | WARNING | Rate limit exceeded for IP x.x.x.x`
- Kein Lockout über den Neustart hinaus (In-Memory – akzeptabel für internes Tool)

---

## 6. Vollständige Übersicht aller .env-Variablen (konsolidiert)

```env
# ── Basis ──────────────────────────────────────────────────────────
PIBG_USERNAME=admin
PIBG_PASSWORD=changeme
PIBG_DB_PATH=./data/pibroadguard.db
PIBG_RULES_PATH=./app/rules/default_rules.yaml

# ── Logging ────────────────────────────────────────────────────────
PIBG_LOG_LEVEL=INFO
PIBG_LOG_PATH=./data/logs/pibroadguard.log

# ── Konnektivität ──────────────────────────────────────────────────
PIBG_INITIAL_CONNECTIVITY_MODE=auto   # auto | force_online | force_offline
PIBG_CONNECTIVITY_CHECK_URL=https://nvd.nist.gov
PIBG_CONNECTIVITY_TIMEOUT=5

# ── CVE / KEV ──────────────────────────────────────────────────────
PIBG_NVD_API_KEY=                     # Optional, erhöht Rate Limit
PIBG_CVE_CACHE_TTL_DAYS=7
PIBG_KEV_SYNC_INTERVAL_HOURS=24

# ── Verschlüsselung ────────────────────────────────────────────────
PIBG_SHARED_SECRET=                   # Für USB-Export-Verschlüsselung
PIBG_ENCRYPTION_ENABLED=true

# ── Backup ─────────────────────────────────────────────────────────
PIBG_BACKUP_MAX_COUNT=5

# ── Nmap ───────────────────────────────────────────────────────────
PIBG_NMAP_HOST_TIMEOUT=60s
PIBG_NMAP_MAX_RATE=100                # Pakete/Sekunde, schonend für Broadcast
```

---

## 7. Aktualisierte Projektstruktur (final)

```
pibroadguard/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   │
│   ├── api/v1/
│   │   ├── __init__.py
│   │   ├── devices.py
│   │   ├── assessments.py
│   │   ├── scans.py
│   │   ├── reports.py
│   │   ├── usb.py
│   │   ├── import_export.py
│   │   └── system.py          # Settings, Logs, Backup, Connectivity, KEV-Sync
│   │
│   ├── core/
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── security.py        # Auth + Rate Limiting
│   │   └── logging_config.py  # NEU
│   │
│   ├── models/
│   │   ├── device.py
│   │   ├── assessment.py
│   │   ├── scan_result.py
│   │   ├── finding.py
│   │   ├── manual_finding.py
│   │   ├── vendor_info.py
│   │   ├── audit_log.py
│   │   ├── scan_authorization.py
│   │   ├── kev_cache.py
│   │   ├── cve_cache.py
│   │   ├── import_log.py
│   │   ├── action_items.py
│   │   └── system_settings.py
│   │
│   ├── schemas/
│   │   ├── device.py
│   │   ├── assessment.py
│   │   ├── scan.py
│   │   ├── finding.py
│   │   ├── report.py
│   │   ├── usb.py
│   │   └── system.py
│   │
│   ├── services/
│   │   ├── nmap_service.py
│   │   ├── rule_engine.py
│   │   ├── scoring_service.py
│   │   ├── report_service.py
│   │   ├── cve_service.py
│   │   ├── remediation_service.py
│   │   ├── package_service.py
│   │   ├── usb_service.py
│   │   ├── crypto_service.py
│   │   ├── connectivity_service.py
│   │   └── backup_service.py  # NEU
│   │
│   ├── rules/
│   │   └── default_rules.yaml
│   │
│   └── templates/
│       ├── report.md.j2
│       └── report.html.j2
│
├── frontend/
│   ├── index.html             # Dashboard
│   ├── device_form.html       # Gerät erfassen/bearbeiten
│   ├── assessment.html        # Assessment (Tabs: Übersicht/Scan/Fragen/Findings/Report)
│   ├── import.html            # Paket importieren (Datei + USB)
│   ├── usb_export.html        # USB-Export-Wizard (3 Schritte)
│   └── settings.html          # System-Settings (Auth/Connectivity/Crypto/Backup/Logs)
│
├── migrations/
│   └── versions/
│
├── data/                      # Ausserhalb des Containers (Volume)
│   ├── pibroadguard.db
│   ├── backups/
│   └── logs/
│       └── pibroadguard.log
│
├── tests/
│   ├── test_nmap_service.py
│   ├── test_rule_engine.py
│   ├── test_scoring.py
│   ├── test_crypto.py         # NEU: AES round-trip
│   ├── test_package.py        # NEU: Export/Import/Checksummen
│   └── test_usb.py            # NEU: USB-Mock
│
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── alembic.ini
├── CLAUDE.md                  # Vollständige Spec (konsolidiert)
└── README.md
```

---

## 8. Finale requirements.txt

```
# Web Framework
fastapi>=0.111.0
uvicorn[standard]>=0.29.0

# Datenbank
sqlalchemy>=2.0.0
alembic>=1.13.0

# Schemas / Config
pydantic>=2.7.0
pydantic-settings>=2.3.0
python-dotenv>=1.0.0

# Templates
jinja2>=3.1.0

# HTTP Client (NVD API, KEV Sync)
httpx>=0.27.0

# Verschlüsselung
cryptography>=42.0.0

# Rate Limiting
slowapi>=0.1.9

# Datei-Upload
python-multipart>=0.0.9
```

**Keine weiteren Abhängigkeiten.** Bewusst schlank gehalten für Pi-Kompatibilität.

---

## 9. Alembic Auto-Migrate beim Start

In `app/main.py`:

```python
from alembic.config import Config
from alembic import command

@app.on_event("startup")
async def startup():
    # 1. Datenbankmigrationen automatisch anwenden
    alembic_cfg = Config("alembic.ini")
    command.upgrade(alembic_cfg, "head")

    # 2. Nmap-Capabilities prüfen
    await nmap_service.check_nmap_capabilities()

    # 3. Konnektivität prüfen
    asyncio.create_task(connectivity_service.check_internet())

    # 4. KEV-Cache aktualisieren falls veraltet
    asyncio.create_task(remediation_service.sync_kev_if_stale(max_age_hours=24))
```

---

*Finales Update-Dokument | Bereit zur Konsolidierung in CLAUDE.md | März 2026*

---

# BDSA_SPEC.md – Update v1.5
## rDNS, MAC, phpIPAM, Gerätetypen, Scan-Metadaten, Remediation-Sources

Ergänzung zu v1.0–v1.4 | Stand: März 2026

---

## ÄNDERUNG 1: rDNS-Lookup und MAC-Adress-Erkennung

### rDNS beim Gerät erfassen

Beim Erfassen oder Bearbeiten eines Geräts wird automatisch ein Reverse-DNS-Lookup
auf die eingetragene IP-Adresse durchgeführt. Das Ergebnis wird in `rdns_hostname` gespeichert
und im Formular als Hinweis angezeigt.

**Neuer Service: `services/dns_service.py`**
```python
async def reverse_lookup(ip: str) -> Optional[str]:
    """Async rDNS-Lookup. Timeout 3s. Gibt hostname oder None zurück."""
```

### MAC-Adress-Erkennung aus Nmap

Nmap liefert bei Scans im selben L2-Segment MAC-Adresse und Hersteller-Vendor.
Diese werden in `scan_results` erfasst und in `devices.mac_address` / `devices.mac_vendor`
übernommen (sofern vorhanden).

### Neue DB-Felder in `devices`
```
rdns_hostname       TEXT    -- Ergebnis des rDNS-Lookups
mac_address         TEXT    -- MAC-Adresse aus Nmap (nur L2)
mac_vendor          TEXT    -- Hersteller aus Nmap OUI-Datenbank
phpipam_id          INTEGER -- Referenz auf phpIPAM-Eintrag
phpipam_synced_at   DATETIME
```

---

## ÄNDERUNG 2: phpIPAM-Integration

**Ziel:** Geräte aus einer bestehenden phpIPAM-Infrastruktur-DB importieren, statt manuell zu erfassen.

**Neuer Service: `services/phpipam_service.py`**

```python
class PhpIpamService:
    def get_all_hosts(self) -> list[PhpIpamHost]:
        """Alle Hosts aus phpIPAM abrufen (paginiert)."""

    def import_to_db(self, hosts: list[PhpIpamHost], db: Session) -> ImportResult:
        """Neue Geräte anlegen, bestehende aktualisieren (phpipam_id als Schlüssel)."""
```

**Konfiguration in `.env`:**
```env
PIBG_PHPIPAM_URL=https://ipam.example.com
PIBG_PHPIPAM_APP_ID=pibroadguard
PIBG_PHPIPAM_TOKEN=abc123
```

**Neue Frontend-Seite: `phpipam_import.html`**
- Zeigt alle phpIPAM-Hosts (gefiltert nach Subnetz/VLAN)
- Checkbox-Auswahl welche importiert werden sollen
- Differenz-Anzeige: neu / aktualisiert / unverändert
- Import-Button mit Bestätigung

**Neue API-Endpunkte:**
```
GET  /api/v1/phpipam/hosts        # Hosts aus phpIPAM abrufen
POST /api/v1/phpipam/import       # Auswahl in PiBroadGuard importieren
```

---

## ÄNDERUNG 3: Konfigurierbare Gerätetypen

Statt eines hartcodierten Enums werden Gerätetypen in der Tabelle `device_types` gespeichert.
Das erlaubt spätere Erweiterungen ohne Code-Änderung.

### Neue DB-Tabelle: `device_types`
```
id          INTEGER PK
name        TEXT UNIQUE       -- interner Bezeichner (z.B. "encoder")
label_de    TEXT              -- "Encoder"
label_en    TEXT              -- "Encoder"
sort_order  INTEGER
active      BOOLEAN
created_at  DATETIME
```

**Seeded beim ersten Start:**
encoder, decoder, matrix, intercom, router, switch, camera, monitor,
multiviewer, playout, transcoder, signal_processor, frame_sync, other

**API-Endpunkt:**
```
GET /api/v1/device-types          # Alle aktiven Typen (für Formular-Dropdown)
```

Das Frontend lädt die Typen bei jedem Seitenaufruf frisch aus der API.

---

## ÄNDERUNG 4: Remediation Sources in Findings

Jedes Finding erhält ein JSON-Array `remediation_sources`, das die Quellen der
Lösungsvorschläge dokumentiert:

```json
[
  {"source": "rule", "label": "BDSA-Regelwerk"},
  {"source": "nvd", "label": "NVD CVE-2023-12345", "url": "https://nvd.nist.gov/..."},
  {"source": "kev", "label": "CISA KEV – aktiv ausgenutzt", "url": "https://..."},
  {"source": "cwe", "label": "CWE-287", "text": "Authentifizierung prüfen..."}
]
```

Im UI werden diese als farbige Badges mit Links angezeigt.

---

## ÄNDERUNG 5: Scan-Metadaten in `scan_results`

Neue Felder pro Scan-Durchführung:
```
scan_duration_seconds   REAL    -- Gesamtdauer in Sekunden
nmap_exit_code          INTEGER -- Exit-Code des Nmap-Prozesses (0 = OK)
nmap_version            TEXT    -- z.B. "7.94"
total_ports_scanned     INTEGER -- Anzahl gescannter Ports lt. scanstats
```

Diese werden beim Scan-Abschluss befüllt und im Assessment-Überblick angezeigt.

---

## ZUSAMMENFASSUNG v1.5

| Bereich | Änderung |
|---------|----------|
| DB | `devices`: 5 neue Felder (rdns, mac, phpipam) |
| DB | Neue Tabelle `device_types` (14 Seed-Einträge) |
| DB | `findings`: `remediation_sources` TEXT (JSON) |
| DB | `scan_results`: 4 neue Metadaten-Felder |
| Service | `dns_service.py` – rDNS async |
| Service | `phpipam_service.py` – phpIPAM REST API |
| API | `GET /api/v1/device-types` |
| API | `GET/POST /api/v1/phpipam/hosts|import` |
| Frontend | `phpipam_import.html` |

---

*Update v1.5 | März 2026*

---

# BDSA_SPEC.md – Update v1.6
## Assessment-Historie, i18n, Scan-Profil-Persistenz, UX-Verbesserungen

Ergänzung zu v1.0–v1.5 | Stand: März 2026

---

## ÄNDERUNG 1: Assessment-Historie in der Geräteansicht

In `device_form.html` wird unterhalb der Stammdaten eine Tabelle aller bisherigen
Assessments für dieses Gerät angezeigt:

| Datum | Status | Rating | Reviewer | Report |
|-------|--------|--------|----------|--------|
| 15.11.2025 | Abgeschlossen | 🟡 Gelb | M. Gerber | [↓ MD] [↓ HTML] |

Verlinkung direkt auf die jeweilige Assessment-Ansicht.

---

## ÄNDERUNG 2: Scan-Profil-Persistenz

Das zuletzt verwendete Scan-Profil (passive / standard / extended) wird pro
Assessment gespeichert und beim nächsten Aufruf der Scan-Seite vorausgewählt.

Beim Wechsel des Profils erscheint ein Bestätigungsdialog. Das neue Profil wird
via `PUT /api/v1/assessments/{id}` im Feld `scan_profile` persistiert.

---

## ÄNDERUNG 3: Internationalisierung (i18n)

**Datei: `frontend/i18n.js`**

Alle UI-Labels sind zweisprachig (Deutsch/Englisch). Sprachauswahl über EN/DE-Buttons
im Header, persistiert im `localStorage`.

```js
// Verwendung in Vue-Komponenten
const { t } = usePiBGi18n();
t('tab_scan', 'Scan')          // gibt übersetzten Text zurück
```

Sprachdateien: `de.json` / `en.json` (eingebettet in `i18n.js`).

---

## ÄNDERUNG 4: Tooltips

Alle wichtigen UI-Elemente haben Tooltip-Texte (hover-Erklärungen), ebenfalls
zweisprachig. Besonders in der Findings-Tabelle, Score-Balken und Regelwerk-Abschnitten.

---

## ÄNDERUNG 5: CVE-Cache-Alter und klickbare Badges

In der Findings-Tabelle werden CVE-Referenzen und KEV-Status als klickbare Badges
angezeigt:

- **NVD-Badge**: Link auf `https://nvd.nist.gov/vuln/detail/{cve_id}`
  mit Anzeige des Cache-Alters (z.B. „3d ago")
- **KEV-Badge**: Link auf CISA KEV Catalog

### Neues Feld `cve_fetched_at` in `FindingRead`

Das `GET /api/v1/assessments/{id}/findings`-Endpoint joiniert die `cve_cache`-Tabelle
und befüllt `cve_fetched_at` mit dem Zeitstempel des letzten Lookups.

---

## ÄNDERUNG 6: Korrigierte Scan-Profil-Beschreibungen

| Profil | Korrekte Beschreibung |
|--------|----------------------|
| `passive` | ~20 broadcast-relevante Ports (ST 2110, Modbus, SNMP, …), T2 |
| `standard` | **Top 1000 Ports** (nicht „alle Ports"), T3, Version-Intensity 5 |
| `extended` | Top 1000 TCP + UDP (SNMP/RTP/Discovery), T3, Version-Intensity 7 |

---

## ZUSAMMENFASSUNG v1.6

| Bereich | Änderung |
|---------|----------|
| Frontend | Assessment-Historie in `device_form.html` |
| Frontend | Scan-Profil-Persistenz mit Bestätigungsdialog |
| Frontend | i18n EN/DE via `i18n.js` |
| Frontend | Tooltips flächendeckend |
| Frontend | NVD/KEV-Badges mit Links und Cache-Alter |
| Schema | `FindingRead`: `cve_fetched_at: Optional[datetime]` |
| Schema | `FindingRead`: `remediation_sources: Optional[str]` |
| API | `GET /findings` joiniert `cve_cache` für `cve_fetched_at` |

---

*Update v1.6 | März 2026*

---

# BDSA_SPEC.md – Update v1.7
## Scan-Queue Service

Ergänzung zu v1.0–v1.6 | Stand: März 2026

---

## Hintergrund

Mehrere parallele Scans (z.B. durch Scheduler-Trigger + manuellen Start) können auf
dem Raspberry Pi zu Ressourcen-Engpässen führen. Ein Queue-System serialisiert die
Scans und gibt Feedback über die Warteposition im UI.

---

## Scan-Queue Service (`services/scan_queue_service.py`)

### Datenstrukturen

```python
@dataclass
class ScanJob:
    job_id: str           # UUID
    assessment_id: int
    device_id: int
    ip_address: str       # frisch aus DB beim Enqueuen
    scan_profile: str
    triggered_by: str     # "manual" | "schedule"
    schedule_id: Optional[int] = None
    queued_at: datetime   = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    status: ScanJobStatus = ScanJobStatus.QUEUED
    position: int = 0

class ScanJobStatus(str, Enum):
    QUEUED   = "queued"
    RUNNING  = "running"
    DONE     = "done"
    FAILED   = "failed"
    SKIPPED  = "skipped"    # Gerät bereits in Queue oder running
```

### Module-Level Singleton

```python
_instance: Optional[ScanQueueService] = None

def init_queue(max_parallel: int = 1) -> ScanQueueService:
    global _instance
    _instance = ScanQueueService(max_parallel)
    return _instance

def get_queue() -> Optional[ScanQueueService]:
    return _instance
```

### ScanQueueService

```python
class ScanQueueService:
    def __init__(self, max_parallel: int = 1):
        self._queue = asyncio.Queue()
        self._running: dict[str, ScanJob] = {}
        self._semaphore = asyncio.Semaphore(max_parallel)
        self._history: list[ScanJob] = []  # max. 50 Jobs
        self._job_processor: Optional[Callable] = None

    def set_job_processor(self, fn: Callable) -> None:
        """Vermeidet zirkuläre Imports: scans.py injiziert seinen _run_scan_task."""

    async def enqueue(self, job: ScanJob) -> ScanJob:
        """Duplikat-Schutz: gleiche device_id nicht doppelt in Queue oder running."""

    async def worker(self) -> None:
        """Asyncio-Task (gestartet in main.py startup). Läuft endlos."""

    def get_status(self) -> dict:
        """Gibt queued/running/history für API-Polling zurück."""

    async def cancel(self, job_id: str) -> bool:
        """Entfernt Job aus Queue (nur wenn noch nicht gestartet)."""
```

### Konfiguration

```env
PIBG_MAX_PARALLEL_SCANS=1    # 1 = sequenziell (empfohlen für Pi)
```

### Neue API-Endpunkte

```
GET    /api/v1/scan-queue/status           # Queue-Zustand (queued/running/history)
DELETE /api/v1/scan-queue/{job_id}         # Job aus Queue entfernen
```

`POST /api/v1/assessments/{id}/scan` gibt jetzt zusätzlich zurück:
```json
{
  "assessment_id": 17,
  "status": "queued",
  "job_id": "uuid...",
  "position": 2
}
```

### UI-Integration

**Scan-Tab im Assessment:** Zeigt Queue-Position an wenn `position > 1`:
```
⏳ Scan ist in der Warteschlange (Position 2 von 3)
[✕ Abbrechen]
```

**Dashboard (`index.html`):** Queue-Widget zeigt laufende/wartende Jobs,
aktualisiert alle 5 Sekunden per Polling.

### Starten in `main.py` (lifespan)

```python
scan_queue = init_queue(settings.pibg_max_parallel_scans)
scan_queue.set_job_processor(_run_scan_task)
asyncio.create_task(scan_queue.worker())
```

---

*Update v1.7 | März 2026*

---

# BDSA_SPEC.md – Update v1.8
## Geplante Scans (Scheduler)

Ergänzung zu v1.0–v1.7 | Stand: März 2026

---

## Hintergrund

Scans sollen automatisch zu festgelegten Zeiten oder in regelmässigen Abständen
ausgeführt werden, ohne dass ein Benutzer aktiv sein muss. Die Schedules werden
in der SQLite-DB persistiert und überleben einen Neustart.

---

## Scheduler-Service (`services/scheduler_service.py`)

**Basis:** APScheduler 3.x (`AsyncIOScheduler` + `SQLAlchemyJobStore`)

```python
def init_scheduler(db_url: str, timezone_str: str) -> AsyncIOScheduler:
    """Erstellt und startet den Scheduler mit SQLAlchemyJobStore."""

def get_scheduler() -> Optional[AsyncIOScheduler]:
    """Gibt den laufenden Scheduler zurück."""
```

### Trigger-Typen

| Trigger | Implementierung | Uhrzeit |
|---------|----------------|---------|
| `once` | `DateTrigger(run_date=run_at_utc_aware)` | exaktes Datum/Uhrzeit |
| `interval` hours | `IntervalTrigger(hours=N)` | keine Uhrzeit |
| `interval` days=1 | `CronTrigger(hour=H, minute=M)` | Uhrzeit wählbar |
| `interval` days>1 / weeks | `IntervalTrigger(days/weeks=N, start_date=next_HH_MM)` | Uhrzeit wählbar |
| `interval` months | `CronTrigger(day=1, hour=H, minute=M, month=*/N)` | Uhrzeit wählbar |
| `cron` | `CronTrigger.from_crontab(expr)` | im Cron-Ausdruck |

**Wichtig:** APScheduler 3.x `IntervalTrigger` unterstützt kein `months`-Parameter.
Monats-Intervalle werden intern auf `CronTrigger` umgestellt.

### Timezone-Handling

- `run_at` wird bei Typ `once` immer UTC-aware gemacht (naive Datetimes werden mit `.replace(tzinfo=timezone.utc)` konvertiert)
- `get_next_fire_time()` ist in `try/except` gekapselt gegen tz-naive/aware-Mismatches

### Ausführung eines geplanten Scans

```python
async def execute_scheduled_scan(
    device_id: int,
    scan_profile: str,
    scheduled_scan_id: int,
    authorized_by_name: str,
    authorized_by_role: str,
) -> None:
    """
    1. Device frisch aus DB lesen (aktuelle IP-Adresse)
    2. Assessment erstellen (Status: scan_running)
    3. ScanAuthorization mit "scheduler" als confirmed_by_user erstellen
    4. ScanJob in die Queue einreihen
    5. ScheduledScan.run_count und last_run_at aktualisieren
    """
```

Die IP-Adresse wird immer frisch aus der DB gelesen – nie gecacht.

---

## Neue DB-Tabelle: `scheduled_scans`

```
id                  INTEGER PK
device_id           INTEGER FK -> devices.id
apscheduler_job_id  TEXT UNIQUE    -- APScheduler Job-ID
trigger_type        TEXT           -- "once" | "interval" | "cron"
run_at              DATETIME       -- für trigger_type=once
interval_unit       TEXT           -- "hours" | "days" | "weeks" | "months"
interval_value      INTEGER
start_hour          INTEGER        -- Uhrzeit HH für Intervall-Scans (UTC)
start_minute        INTEGER        -- Uhrzeit MM für Intervall-Scans
cron_expression     TEXT           -- für trigger_type=cron
scan_profile        TEXT
authorized_by_name  TEXT NOT NULL
authorized_by_role  TEXT NOT NULL
active              BOOLEAN
last_run_at         DATETIME
last_run_status     TEXT           -- "success" | "failed" | "skipped"
next_run_at         DATETIME
run_count           INTEGER
created_at          DATETIME
created_by          TEXT
```

APScheduler verwaltet seine Job-Persistenz in der eigenen Tabelle `apscheduler_jobs`
(automatisch erstellt, nicht via Alembic verwaltet).

---

## API-Endpunkte

```
GET    /api/v1/schedules                    # Alle Schedules (mit next_run_at)
POST   /api/v1/schedules                    # Schedule erstellen
GET    /api/v1/schedules/{id}               # Einzelner Schedule
DELETE /api/v1/schedules/{id}               # Löschen (auch APScheduler-Job)
POST   /api/v1/schedules/{id}/pause         # Pausieren
POST   /api/v1/schedules/{id}/resume        # Fortsetzen
POST   /api/v1/schedules/{id}/run-now       # Sofort auslösen (Test)
GET    /api/v1/devices/{id}/schedules       # Schedules eines Geräts
```

**POST `/api/v1/schedules` Body:**
```json
{
  "device_id": 42,
  "trigger_type": "interval",
  "scan_profile": "passive",
  "authorized_by_name": "Max Muster",
  "authorized_by_role": "Broadcast Engineer",
  "interval_unit": "weeks",
  "interval_value": 4,
  "start_hour": 2,
  "start_minute": 0
}
```

---

## Frontend-Seiten

### `schedules.html` – Standalone Schedules-Übersicht

- Tabelle aller Schedules (alle Geräte)
- Filter: Gerät / Status (aktiv/pausiert)
- Aktionen: Pause / Resume / Jetzt ausführen / Löschen
- Erstellen-Modal (identisch zum Assessment-Tab)

### Assessment-Tab „Schedules"

Neuer Tab in `assessment.html` mit:
- Tabelle der Schedules für dieses Gerät
- Erstellen-Modal mit Trigger-Typ/Intervall/Uhrzeit/Profil/Autorisierung

### Create-Modal – Felder

| Feld | Sichtbar wenn |
|------|---------------|
| Date/Time | `trigger_type = once` |
| Interval Value + Unit | `trigger_type = interval` |
| **Time of Day (HH:MM)** | `trigger_type = interval` UND `interval_unit ≠ hours` |
| Cron Expression | `trigger_type = cron` |
| Scan Profile | immer |
| Authorized by Name/Role | immer (Pflichtfelder) |
| Bestätigungs-Checkbox | immer |

Die Uhrzeit-Eingabe (`<input type="time">`) zeigt den Hinweis „HH:MM – UTC".
Standard: `02:00`.

### Dashboard-Widget – Nächste Scans

```
⏰ Nächste Scans
──────────────────────────────────────────
Riedel MediorNet  passive  Do 26.03 02:00
Grass Valley AMPP passive  Mo 30.03 02:00
```

Zeigt die nächsten 4 aktiven Schedules, Polling alle 5 Sekunden.

---

## Konfiguration

```env
PIBG_MAX_PARALLEL_SCANS=1       # Queue-Parallelität
PIBG_SCHEDULER_TIMEZONE=Europe/Zurich
```

## Neue Abhängigkeit

```
apscheduler>=3.10.4
```

---

## Starten in `main.py` (lifespan)

```python
# Scan-Queue initialisieren
scan_queue = init_queue(settings.pibg_max_parallel_scans)
scan_queue.set_job_processor(_run_scan_task)
asyncio.create_task(scan_queue.worker())

# Scheduler initialisieren
init_scheduler(settings.database_url, settings.pibg_scheduler_timezone)

# Shutdown
shutdown_scheduler()
```

---

## Migrationen (Übersicht)

| Migration | Was |
|-----------|-----|
| `001_initial.py` | Alle Basistabellen (v1.0–v1.4) |
| `002_v15_extensions.py` | rDNS/MAC/phpIPAM-Felder, `device_types`, `remediation_sources`, Scan-Metadaten |
| `003_scheduled_scans.py` | `scheduled_scans`-Tabelle |
| `004_schedule_time_of_day.py` | `start_hour`/`start_minute` in `scheduled_scans` |

---

*Update v1.8 | März 2026*

---

# BDSA_SPEC.md – Update v1.9
## UI-Verbesserungen: Pagination, Netzwerk-Konfiguration, Findings-Fix, Logging

Ergänzung zu v1.0–v1.8 | Stand: März 2026

---

## ÄNDERUNG 1: Paginierung in allen Listen

Alle Listenansichten zeigen ab einer konfigurierbaren Anzahl Einträge mehrere Seiten an.
Die Paginierung erfolgt clientseitig via Vue 3 `computed`-Properties.

### Paginierte Seiten und Standardgrössen

| Seite / Bereich | Einträge pro Seite | Beschreibung |
|---|---|---|
| `index.html` – Geräteliste | 25 | Gefilterte Gerätliste mit Such- und Filterfeldern |
| `device_form.html` – Assessment-Historie | 10 | Bisherige Assessments eines Geräts |
| `assessment.html` – Findings | 25 | Rule-triggered Findings pro Assessment |
| `assessment.html` – Scan-Resultate | 25 | Offene Ports aus dem letzten Nmap-Scan |
| `schedules.html` – Schedule-Liste | 25 | Alle geplanten Scans |

### Paginierungs-Muster (Vue 3)

```javascript
// Refs
const page = ref(1);
const PAGE_SIZE = 25;

// Computeds
const totalPages = computed(() => Math.max(1, Math.ceil(filteredItems.value.length / PAGE_SIZE)));
const pageStart  = computed(() => (page.value - 1) * PAGE_SIZE + 1);
const pageEnd    = computed(() => Math.min(page.value * PAGE_SIZE, filteredItems.value.length));
const pagedItems = computed(() => filteredItems.value.slice((page.value - 1) * PAGE_SIZE, page.value * PAGE_SIZE));

// Bei Filteränderung Seite zurücksetzen
function resetPage() { page.value = 1; }
```

### Paginierungs-UI mit Ellipsis

```html
<div v-if="totalPages > 1" class="flex items-center justify-between mt-3 text-xs text-slate-500">
  <span>{{ pageStart }}–{{ pageEnd }} / {{ items.length }}</span>
  <div class="flex gap-1">
    <button @click="page = Math.max(1, page - 1)" :disabled="page === 1" ...>‹</button>
    <template v-for="p in totalPages" :key="p">
      <button v-if="p === 1 || p === totalPages || Math.abs(p - page) <= 1"
        @click="page = p" :class="p === page ? 'bg-blue-600 text-white' : ''" ...>{{ p }}</button>
      <span v-else-if="p === 2 && page > 3" class="px-2 py-1">…</span>
      <span v-else-if="p === totalPages - 1 && page < totalPages - 2" class="px-2 py-1">…</span>
    </template>
    <button @click="page = Math.min(totalPages, page + 1)" :disabled="page === totalPages" ...>›</button>
  </div>
</div>
```

---

## ÄNDERUNG 2: Port-Scan-Resultate im Findings-Tab

Im Findings-Tab von `assessment.html` werden neu vor den rule-triggered Findings alle
erkannten offenen Ports aus dem letzten Nmap-Scan als Tabelle angezeigt.

### Tabellen-Spalten

| Spalte | Datenquelle | Beschreibung |
|---|---|---|
| Port / Proto | `scan_results.port` / `.protocol` | z.B. `22/tcp` |
| Service | `scan_results.service_name` | z.B. `ssh` |
| Product / Version | `.service_product` / `.service_version` | z.B. `OpenSSH 8.4` |
| State | `.state` | `open` (rot hinterlegt) / `filtered` |
| Extra Info | `.extra_info` | OS-Hinweise, SSH-Version etc. |

Die Tabelle hat dieselbe Paginierung (25 Einträge pro Seite) wie die Findings-Liste.
Wenn keine Scan-Resultate vorhanden sind, wird der Abschnitt nicht angezeigt.

---

## ÄNDERUNG 3: Finding-Karten – immer sichtbares Kompensationsfeld + Speichern-Button

### Vorher
- Kompensationsfeld (`v-if="f.compensating_control_required"`) nur sichtbar wenn Regel `ask_compensation: true`
- Automatisches Speichern via `@change` / `@blur` (kein sichtbarer Button)

### Nachher
- Kompensationsfeld immer sichtbar (kein `v-if`); Pflichtfeld-Marker `*` wenn `compensating_control_required`
- Expliziter **Save**-Button pro Finding-Karte (`@click="updateFinding(f)"`)
- Status-Dropdown ohne Auto-Save (erst beim Klick auf Save)

### Layout der Finding-Karte (Bottom Row)

```
[ Status-Dropdown ] [ Compensating Control Input Field ... ] [ Save ]
```

---

## ÄNDERUNG 4: Netzwerk-Konfiguration über das UI

### Übersicht

Auf der Settings-Seite (`settings.html`) gibt es eine neue Sektion **Network Configuration**.
Sie zeigt alle Netzwerk-Interfaces des Systems und erlaubt, IP-Adresse, Gateway und DNS
über das UI zu konfigurieren – ohne direkten SSH-Zugriff.

### Backend: Neue API-Endpunkte in `app/api/v1/system.py`

```
GET  /api/v1/system/network-config         # Alle Interfaces, Gateway, DNS abrufen
POST /api/v1/system/network-config/apply   # Netzwerk-Konfiguration anwenden
```

**GET Response-Schema:**
```json
{
  "interfaces": [
    {
      "name": "eth0",
      "state": "UP",
      "addresses": ["192.168.1.100/24"],
      "mac": "b8:27:eb:xx:xx:xx"
    }
  ],
  "default_gateway": "192.168.1.1",
  "dns_servers": ["8.8.8.8", "1.1.1.1"],
  "nmcli_available": true
}
```

**POST Body:**
```json
{
  "interface": "eth0",
  "mode": "static",           // "static" | "dhcp"
  "ip_cidr": "192.168.1.100/24",
  "gateway": "192.168.1.1",
  "dns": "8.8.8.8 1.1.1.1"
}
```

**POST Response (nmcli verfügbar):**
```json
{
  "success": true,
  "message": "Network configuration applied via nmcli",
  "applied_commands": ["nmcli connection modify eth0 ipv4.addresses 192.168.1.100/24 ..."]
}
```

**POST Response (nmcli nicht verfügbar – Fallback):**
```json
{
  "success": false,
  "manual_instructions": true,
  "message": "nmcli not available. Use these shell commands manually:",
  "commands": ["ip addr add 192.168.1.100/24 dev eth0", "ip route add default via 192.168.1.1"]
}
```

### Implementierung: `_read_network_config()`

Liest aktuelle Netzwerkkonfiguration via Shell-Kommandos:
- `ip -o addr show` → Interfaces mit IP-Adressen
- `ip -o link show` → Interface-Status (UP/DOWN) und MAC
- `ip route show default` → Standard-Gateway
- `/etc/resolv.conf` + `resolvectl status` → DNS-Server

### Implementierung: Anwenden via nmcli

```python
# Static-Konfiguration
nmcli connection modify {iface} ipv4.method manual ipv4.addresses {ip_cidr} ipv4.gateway {gw} ipv4.dns "{dns}"
nmcli connection up {iface}

# DHCP
nmcli connection modify {iface} ipv4.method auto ipv4.addresses "" ipv4.gateway "" ipv4.dns ""
nmcli connection up {iface}
```

### UI: Settings-Seite – Network Configuration Sektion

```
┌─────────────────────────────────────────────────────────────────────┐
│  🌐 NETWORK CONFIGURATION                                           │
│                                                                     │
│  Interface  State  Addresses               MAC          Action      │
│  eth0       UP     192.168.1.100/24        b8:27:eb:…   [Configure] │
│  lo         UP     127.0.0.1/8, ::1/128    —                        │
│                                                                     │
│  Default Gateway: 192.168.1.1                                       │
│  DNS Servers: 8.8.8.8, 1.1.1.1                                     │
│  nmcli: ✅ Available                                                │
└─────────────────────────────────────────────────────────────────────┘
```

Klick auf **Configure** öffnet ein Modal mit:
- **Mode**: Static / DHCP (Radio-Buttons)
- **IP Address / Prefix**: `192.168.1.100/24` (nur bei Static)
- **Default Gateway**: `192.168.1.1` (nur bei Static)
- **DNS Servers**: `8.8.8.8 1.1.1.1` (nur bei Static)
- **Apply**-Button → POST an Backend → zeigt Ergebnis oder Shell-Befehle

---

## ÄNDERUNG 5: Logging-Fix (uvicorn-Konflikt)

### Problem
`setup_logging()` wird beim Modul-Import ausgeführt, bevor uvicorn seine eigenen
Handler konfiguriert. Uvicorn's `configure_logging()` kann danach die Root-Logger-Handler
zurücksetzen, wodurch der File-Handler verloren geht.

### Lösung
`setup_logging()` wird **zusätzlich** als erste Aktion im `lifespan`-Startup-Context
aufgerufen (nach uvicorn-Initialisierung):

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Re-apply after uvicorn has configured its handlers
    setup_logging(settings.pibg_log_level, settings.pibg_log_path)
    run_migrations()
    ...
```

---

## ÄNDERUNG 6: Auth-Log-Deduplication

### Problem
Basic Auth wird bei jedem API-Request geprüft. Bei normaler Nutzung würde dadurch
ein Log-Eintrag pro Request entstehen (potentiell Hunderte pro Minute).

### Lösung
Ein module-level Set `_logged_logins: set[str]` in `app/core/security.py` trackt,
von welchen IP-Adressen bereits ein erfolgreicher Login geloggt wurde. Jede IP wird
nur beim **ersten** erfolgreichen Login in `pibroadguard.auth` auf INFO-Level geloggt.

```python
_logged_logins: set[str] = set()

# In verify_credentials():
if ip not in _logged_logins:
    _logged_logins.add(ip)
    logger.info(f"Successful auth from {ip} (user: {credentials.username})")
```

Fehlgeschlagene Auth-Versuche werden weiterhin **jeden** Versuch auf WARNING geloggt
(für Security-Monitoring wichtig).

---

## ZUSAMMENFASSUNG v1.9

| Bereich | Änderung |
|---------|----------|
| Frontend | Paginierung in index.html, device_form.html, assessment.html (Findings + ScanResults), schedules.html |
| Frontend | Port-Scan-Resultate als Tabelle im Findings-Tab |
| Frontend | Finding-Karte: immer sichtbares Kompensationsfeld + expliziter Save-Button |
| Frontend | Settings: Network Configuration Sektion mit Interface-Übersicht und Modal-Editor |
| API | `GET /api/v1/system/network-config` |
| API | `POST /api/v1/system/network-config/apply` |
| Backend | Logging-Fix: setup_logging() im lifespan-Startup wiederholt aufrufen |
| Backend | Auth-Log-Deduplication: nur erster Login pro IP geloggt |

---

*Update v1.9 | März 2026*

---

# BDSA_SPEC.md – Update v1.10
## Device Probe + Discovery Scan Mode

Ergänzung zu v1.0–v1.9 | Stand: März 2026

---

## ÄNDERUNG 1: Device Probe – Leichtgewichtiger Gerätescan

### Hintergrund

Ein **Device Probe** ist ein unabhängiger, leichtgewichtiger Nmap-Scan auf Geräte-Ebene –
kein vollständiges Assessment. Er dient dazu, schnell zu prüfen, ob ein Gerät erreichbar ist
und welche Ports offen sind, ohne den Assessment-Workflow zu durchlaufen.

Probes laufen ausserhalb der Scan-Queue und haben keine Auswirkung auf bestehende Assessments.

### Neue DB-Tabelle: `probe_results`

```
id                    INTEGER PK
device_id             INTEGER FK -> devices.id
scan_profile          TEXT              -- verwendetes Profil
status                TEXT              -- running | complete | failed
port_count            INTEGER           -- Anzahl offener Ports
raw_nmap_output       TEXT              -- Nmap-XML
scan_results_json     TEXT              -- JSON-Array geparster Ports
observations          TEXT              -- Freitext-Notizen des Engineers
duration_seconds      REAL
nmap_version          TEXT
exit_code             INTEGER
started_at            DATETIME
completed_at          DATETIME
initiated_by          TEXT              -- BDSA-Username
```

### API-Endpunkte

```
POST   /api/v1/devices/{id}/probes              # Probe starten
GET    /api/v1/devices/{id}/probes              # Alle Probes dieses Geräts
GET    /api/v1/devices/{id}/probes/{probe_id}   # Einzelner Probe (inkl. Status-Polling)
PUT    /api/v1/devices/{id}/probes/{probe_id}   # Observations aktualisieren
```

### Ausführungsmodell

Probes laufen via `asyncio.create_task()` direkt – sie umgehen die Scan-Queue.
Begründung: Probes sind explorative Aktionen und sollen nicht durch wartende
Assessment-Scans blockiert werden.

### UI: Probes-Sektion in `device_form.html`

Unterhalb der Assessment-Historie wird eine neue Sektion **Gerätesonden (Probes)** angezeigt:

- Profil-Dropdown + "Probe starten"-Button
- Live-Polling alle 2 Sekunden während Probe läuft
- Port-Tabelle (Port | Protokoll | Service | Produkt/Version | State)
- Observations-Textfeld (freie Notizen, direkt speicherbar)
- Paginierte Probe-Historie (10 Einträge pro Seite)
- Badge: Anzahl offener Ports im Ergebnis

**Abgrenzung zur Scan-Autorisierung:** Probes zeigen keinen Autorisierungs-Dialog –
sie sind explizit als schnelle Erkundungsscans gedacht. Für reguläre Assessments
bleibt die Autorisierungspflicht bestehen.

---

## ÄNDERUNG 2: Discovery Scan Mode

### Hintergrund

Ein **Discovery-Scan** ist ein Nmap-Scan, der bewusst **kein vollständiges Security-Assessment**
durchführen soll. Er dient der Bestandsaufnahme (welche Ports sind offen?), ohne den vollen
Regelwerk-Auswertungs- und Scoring-Prozess auszulösen.

Das Gegenteil ist ein **Assessment-Scan**: Regelwerk, CVE-Lookup, Scoring, vollständige Findings.

### Neues Feld: `is_discovery` auf `ScanProfile`

```python
# app/models/scan_profile.py
is_discovery = Column(Boolean, default=False)
```

Wenn `is_discovery=True`, überspringt der Scan:
- Regelwerk-Auswertung (keine auto-generierten Findings)
- CVE-Lookup
- Scoring-Berechnung

### Neues Feld: `scan_mode` auf `Assessment`

```python
# app/models/assessment.py
scan_mode = Column(String, default="assessment")  # "assessment" | "discovery"
```

Wird beim Scan-Start automatisch gesetzt:
```python
assessment.scan_mode = "discovery" if is_discovery else "assessment"
```

### Verhalten im Scan-Workflow (`scans.py`)

```python
if is_discovery:
    assessment.status = "scan_complete"
    assessment.scan_mode = "discovery"
    db.commit()
    # Früher Return – kein Regelwerk, kein CVE, kein Scoring
    return
# Normaler Workflow (Regelwerk, Scoring) folgt hier
```

### Report-Template: `report_discovery.html.j2`

Separate Jinja2-Vorlage mit lila Akzentfarbe und "🔍 Discovery-Modus"-Badge.
Enthält:
- Gerätemetadaten-Tabelle
- Port-Tabelle mit allen Scan-Resultaten
- Scan-Seiteneffekte-Fragen (Antworten farbcodiert: Ja=rot, Nein=grün, Teilweise=amber)
- Methodikhinweis
- Anhang: Nmap-Raw-XML (escaped)

`report_service.py` wählt das Template automatisch anhand von `assessment.scan_mode`:
```python
template_name = "report_discovery.html.j2" if scan_mode == "discovery" else "report.html.j2"
```

### UI-Anpassungen (`assessment.html`)

Bei Discovery-Assessments:
- Header-Badge: "🔍 Discovery-Modus – kein Scoring, kein Regelwerk"
- Score-Balken und Gesamtbewertung: ausgeblendet
- "Neu berechnen"-Button: ausgeblendet
- Manuelle Fragen: nur `scan_effects`-Kategorie sichtbar
- Autorisierungs-Modal: Hinweis wenn das gewählte Profil `is_discovery=true` hat

`settings.html` zeigt Discovery-Profile mit lila "🔍 discovery"-Badge.
Inline-Edit und "Profil hinzufügen"-Modal enthalten `is_discovery`-Checkbox.

### Migration 011

```python
# migrations/versions/011_discovery_mode.py
# Revision: 011, down_revision: 010
# Fügt hinzu:
# - scan_profiles.is_discovery (Boolean, server_default="0")
# - assessments.scan_mode (String, server_default="assessment")
```

---

## ÄNDERUNG 3: Gerätetyp → Scan-Profil-Vorschlag

Neue API-Abfrage, die anhand des Gerätetyps ein geeignetes Scan-Profil empfiehlt:

```
GET /api/v1/system/scan-profile-suggestion?device_type=camera
```

**Response:**
```json
{
  "device_type": "camera",
  "suggested_profile": "passive",
  "rationale": "Kameras sind oft eingeschränkt härtbar und empfindlich auf aggressive Scans.",
  "standard_ref": "IEC 62443-3-2 / NIST SP 800-115 / BSI ICS"
}
```

Die Empfehlung basiert auf einer internen Mapping-Tabelle in `system.py`.

---

## ZUSAMMENFASSUNG v1.10

| Bereich | Änderung |
|---------|----------|
| DB | Neue Tabelle `probe_results` (Migration 010) |
| DB | `scan_profiles.is_discovery` (Migration 011) |
| DB | `assessments.scan_mode` (Migration 011) |
| Service | Probe-Ausführung via `asyncio.create_task()` (kein Queue) |
| API | `POST/GET /api/v1/devices/{id}/probes` |
| API | `GET /api/v1/system/scan-profile-suggestion` |
| Frontend | Probes-Sektion in `device_form.html` |
| Frontend | Discovery-Mode-Anzeige in `assessment.html` und `settings.html` |
| Template | Neues `report_discovery.html.j2` |

---

*Update v1.10 | März 2026*

---

# BDSA_SPEC.md – Update v1.11
## PDF-Reports, Regelwerk-Verwaltung, Re-Assessment-Fälligkeit, Backup-Erweiterungen

Ergänzung zu v1.0–v1.10 | Stand: März 2026

---

## ÄNDERUNG 1: PDF-Report-Generierung via WeasyPrint

### Neue Report-Format-Option

Neben Markdown, HTML und JSON gibt es neu **PDF-Export**:

```
GET /api/v1/assessments/{id}/report/pdf     # PDF-Report herunterladen
```

**Implementierung:** WeasyPrint (server-seitig, kein Browser benötigt)
- Rendert den bestehenden HTML-Report via `weasyprint.HTML(string=html).write_pdf()`
- CSS-Ergänzungen für Print: `page-break-inside: avoid`, `thead { display: table-header-group }`
- Responsive-Klassen werden für PDF optimiert

**Neue Abhängigkeit:**
```
weasyprint>=60.0
```

WeasyPrint benötigt zusätzliche System-Dependencies (Cairo, Pango, GLib):
```dockerfile
# Dockerfile-Ergänzung
RUN apt-get install -y libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

**Frontend:** PDF-Download-Button im Report-Tab von `assessment.html`.

---

## ÄNDERUNG 2: Regelwerk-Verwaltung im UI

### Neue Seite: `rules.html`

Vollständige CRUD-Verwaltung des YAML-Regelwerks über das Webinterface:

**Features:**
- Tabellarische Ansicht aller Regeln (rule_key, title, severity, affects_score)
- Live-Filter nach Severity, Kategorie und Suchbegriff
- Paginierung (25 pro Seite)
- Inline-Bearbeitung: Zeile aufklappen → alle Felder editierbar
- Zeilen-Reihenfolge: Verschieben nach oben/unten
- Neue Regel hinzufügen (Formular unterhalb der Tabelle)
- Regel löschen (mit Bestätigungsdialog)

### Neue API-Endpunkte

```
GET    /api/v1/rules                    # Alle Regeln
POST   /api/v1/rules                    # Neue Regel anlegen
PUT    /api/v1/rules/{rule_key}         # Regel bearbeiten
DELETE /api/v1/rules/{rule_key}         # Regel löschen
POST   /api/v1/rules/{rule_key}/move    # Position verschieben (body: {"direction": "up"|"down"})
```

Änderungen am Regelwerk werden direkt in der SQLite-DB gespeichert (nicht mehr nur YAML).
Die YAML-Datei dient weiterhin als Seed beim ersten Start.

---

## ÄNDERUNG 3: Re-Assessment-Fälligkeitsliste

### Neue Seite: `reassessment-due.html`

Standalone-Seite, die alle Geräte anzeigt, deren periodisches Re-Assessment ansteht oder überfällig ist.

**Spalten:** Gerät | Letztes Assessment | Bewertung | Re-Assessment fällig | Tage bis/seit Fälligkeit | Aktionen

**Aktionen:**
- Direkt zu bestehendem Assessment navigieren
- Neues Assessment starten

**Filter:** Nur überfällige / Alle / Bald fällig (konfigurierbarer Horizont)

### Neuer API-Endpunkt

```
GET /api/v1/devices/reassessment-due?days_ahead=30
```

Gibt alle Devices zurück, deren `reassessment_due`-Datum im angegebenen Horizont liegt
oder bereits überschritten ist.

### Dashboard-Integration (`index.html`)

- Kachel: Anzahl überfälliger Re-Assessments (mit Link auf `reassessment-due.html`)
- Kompaktes Widget: Nächste 5 fällige Geräte

---

## ÄNDERUNG 4: Backup-Erweiterungen (Löschen + Wiederherstellen)

Ergänzung zu Abschnitt 1 aus Update v1.4:

### Neuer Endpunkt: Backup löschen

```
DELETE /api/v1/system/backup/{filename}    # Einzelnes Backup löschen
```

### Neuer Endpunkt: Backup wiederherstellen

```
POST /api/v1/system/backup/restore/{filename}    # Backup als neue DB aktivieren
```

**Restore-Verhalten:**
1. Backup-Datei verifizieren (existiert, lesbar)
2. Aktuelle DB in temporäres Backup schreiben (`pibroadguard-prerestore-{ts}.db`)
3. Backup-Datei als neue aktive DB einsetzen
4. App-Neustart erforderlich (Hinweis im UI)

**UI:** Auf der Settings-Seite erhält jede Backup-Zeile Buttons für [Herunterladen], [Wiederherstellen] und [Löschen].

---

## ÄNDERUNG 5: Duplikat-Findings bei Re-Scan verhindert

Wenn ein Assessment erneut gescannt wird (z.B. periodisch oder nach Änderungen),
werden Findings nicht dupliziert, sondern **upserted**:

- **Bestehender Finding mit gleichem `rule_key`:** Status und Kompensation werden erhalten,
  `evidence` und `title` werden aktualisiert.
- **Neuer Finding ohne Entsprechung:** Wird neu angelegt.
- **Alter Finding der nicht mehr zutrifft** (Port geschlossen): Status bleibt erhalten,
  aber Finding wird als stale markiert (kein automatisches Löschen offener Findings).
- **ScanResult-Zeilen:** Werden vor dem Re-Scan gelöscht und neu befüllt.

---

## ZUSAMMENFASSUNG v1.11

| Bereich | Änderung |
|---------|----------|
| Report | PDF-Export via WeasyPrint (`GET /api/v1/assessments/{id}/report/pdf`) |
| Frontend | Neue Seite `rules.html` – CRUD-Regelwerk-Verwaltung |
| Frontend | Neue Seite `reassessment-due.html` – Fälligkeitsliste |
| Frontend | Dashboard-Kachel + Widget für Re-Assessment-Fälligkeiten |
| Frontend | Settings: Backup-Zeilen mit Löschen/Wiederherstellen-Buttons |
| API | `GET/POST/PUT/DELETE/move /api/v1/rules` |
| API | `GET /api/v1/devices/reassessment-due` |
| API | `DELETE /api/v1/system/backup/{filename}` |
| API | `POST /api/v1/system/backup/restore/{filename}` |
| Backend | Upsert-Logik für Findings bei Re-Scan |
| Dependency | `weasyprint>=60.0` + System-Libs |

---

*Update v1.11 | März 2026*

---

# BDSA_SPEC.md – Update v1.12
## EPSS-Integration, Scan-Profil-Verbesserungen, Scan-Initiator, Scan-Seiteneffekte

Ergänzung zu v1.0–v1.11 | Stand: März 2026

---

## ÄNDERUNG 1: EPSS-Integration (Exploit Prediction Scoring System)

### Was ist EPSS?

EPSS (Exploit Prediction Scoring System) von FIRST.org schätzt die Wahrscheinlichkeit,
dass eine CVE innerhalb der nächsten 30 Tage aktiv ausgenutzt wird (0.0–1.0 Score + Perzentile).
Die API ist kostenlos und benötigt keinen API-Key.

**API-URL:** `https://api.first.org/data/1.0/epss?cve=CVE-XXXX-YYYY`

### Implementierung in `cve_service.py`

```python
async def get_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    Batch-Abfrage für bis zu 30 CVE-IDs gleichzeitig.
    Gibt Dict {cve_id: {"epss": 0.123, "percentile": 0.987}} zurück.
    Graceful Fallback: leeres Dict bei Netzwerkfehler.
    """
```

### API-Integration

Der bestehende CVE-Lookup-Endpunkt wird mit EPSS-Daten angereichert:

```
GET /api/v1/cve/lookup?vendor=...&product=...
→ jede CVE enthält neu: "epss_score": 0.123, "epss_percentile": 0.987
```

Zusätzlicher direkter EPSS-Endpunkt:
```
GET /api/v1/cve/epss?cve=CVE-2021-44228,CVE-2023-12345
```

### UI-Darstellung

Im CVE-Lookup-Dialog und in Finding-Karten:
- EPSS-Score als Badge (z.B. "EPSS 12.3%")
- Rot wenn Perzentile > 90 (hohes relatives Exploit-Risiko)

---

## ÄNDERUNG 2: Scan-Profil-Verbesserungen

### SYN-Scan-Upgrade bei verfügbaren Capabilities

`nmap_service.py` führt beim Start einen Capability-Check durch. Falls `CAP_NET_RAW`
verfügbar ist, werden Profil-Flags automatisch von `-sT` (TCP-Connect) auf `-sS` (SYN Stealth)
umgestellt. Das verbessert die Präzision und verringert sichtbare Verbindungsaufbauten.

### Retries-Konfiguration pro Profil

| Profil | Ergänzte Flags |
|--------|----------------|
| `passive` | `--max-retries 1` |
| `standard` | `--max-retries 2` |
| `extended` | `--max-retries 1 --defeat-icmp-ratelimit` |

### `version_deep`-Profil überarbeitet

Das ursprüngliche `version_deep`-Profil verwendete aggressive NSE-Scripts (`-sC`), die nach
IEC 62443 und BSI ICS-Empfehlungen für produktive Broadcast-Geräte ungeeignet sind.
Das überarbeitete Profil:
- Entfernt `-sC` (NSE-Scripts deaktiviert)
- Fokus auf reine Versionserkennung mit hoher Intensität (`--version-intensity 9`)
- Behält UDP-Scan für Discovery-relevante Protokolle (SNMP, SSDP, mDNS)

### Flag-Bereinigung beim Speichern

Beim Anlegen oder Bearbeiten von Scan-Profilen werden automatisch bereinigt:
- Führendes `nmap`-Token (`nmap -sV ...` → `-sV ...`)
- Platzhalter `<target>` (wird entfernt)

---

## ÄNDERUNG 3: Scan-Initiator-Anzeige

Nach Abschluss eines Scans lädt das Assessment-UI die zugehörige `ScanAuthorization`
und zeigt an, wer den Scan ausgelöst hat:

| Initiator | Anzeige |
|-----------|---------|
| Manueller Start | Benutzername (aus Basic Auth) |
| Geplanter Scan | 🤖 + `authorized_by_name` aus Schedule |

**Backend:** `initiated_by` wird in `ScanAuthorization.confirmed_by_user` gespeichert.
Scheduled Scans setzen `"scheduler"` als `confirmed_by_user`.

---

## ÄNDERUNG 4: Scan-Seiteneffekte-Fragen (`scan_effects`-Kategorie)

### Hintergrund

Bei Broadcast-Geräten können selbst schonende Nmap-Scans Seiteneffekte auslösen
(Reboots, Signalunterbrechungen, False-Positive-Alarme). Diese Beobachtungen sollen
systematisch erfasst werden.

### Neue Fragenkategorie in `QUESTION_CATALOG`

```python
"scan_effects": [
    {"key": "effect_reboot",     "question": "Hat das Gerät während/nach dem Scan neu gestartet?"},
    {"key": "effect_service",    "question": "Wurden Services unterbrochen oder gestört?"},
    {"key": "effect_av_alert",   "question": "Wurde ein Alarm in einer AV/Monitoring-Konsole ausgelöst?"},
    {"key": "effect_performance","question": "War eine messbare Leistungsbeeinträchtigung feststellbar?"},
    {"key": "effect_config",     "question": "Hat der Scan eine Konfigurationsänderung am Gerät verursacht?"},
    {"key": "effect_notes",      "question": "Weitere Beobachtungen (Freitext)"},
]
```

### Sichtbarkeitsregeln

| Bedingung | `scan_effects` sichtbar |
|-----------|------------------------|
| Discovery-Profil (`is_discovery=True`) | Immer – ist die primäre Fragengruppe |
| Aggressives Profil (extended, version_deep) | Automatisch hervorgehoben (amber) |
| Passive/Standard-Profil | Nur wenn bereits Antworten vorhanden |

### Verwendung im Discovery-Report

Im `report_discovery.html.j2`-Template werden die `scan_effects`-Antworten mit
farbcodierten Badges dargestellt:
- `yes` → roter Badge (potenziell problematisch)
- `no` → grüner Badge (kein Effekt)
- `partial` → gelber Badge

---

## ZUSAMMENFASSUNG v1.12

| Bereich | Änderung |
|---------|----------|
| Service | EPSS-Lookup in `cve_service.get_epss_scores()` |
| API | EPSS-Anreicherung in `GET /api/v1/cve/lookup` |
| API | `GET /api/v1/cve/epss?cve=...` |
| Backend | SYN-Scan-Upgrade bei CAP_NET_RAW (nmap_service.py) |
| Backend | Retries-Flags pro Profil (passive, standard, extended) |
| Backend | `version_deep`-Profil überarbeitet (kein `-sC`) |
| Backend | Flag-Bereinigung beim Profil-Speichern |
| Frontend | Scan-Initiator-Anzeige im Assessment-Tab |
| Fragenkat. | Neue Kategorie `scan_effects` (6 Fragen) |
| Template | `scan_effects`-Antworten im Discovery-Report mit Badges |

---

*Update v1.12 | März 2026*

---

# Roadmap / Geplante Erweiterungen

Die folgenden Erweiterungen sind für zukünftige Versionen geplant.
Detaillierte Aufgabenlisten und Prioritäten sind in `TODO.md` dokumentiert.

## Hybrides Audit-Modell (Zielarchitektur)

PiBroadGuard wird nach einem vierschichtigen Modell weiterentwickelt:

| Modul | Inhalt |
|-------|--------|
| **A – Discovery** | Nmap + NMOS IS-04 Query + rDNS + MAC OUI |
| **B – Broadcast Compliance** | EBU R143/R148/R160 S1, AMWA BCP-003, SMPTE ST 2059, JT-NM TR-1001-1 |
| **C – Vulnerability Enrichment** | NVD (CPE-basiert), CISA KEV, CISA ICS Advisories, EPSS, CSAF 2.0 |
| **D – Externe Scanner** | Greenbone GMP, Tenable API, Rapid7 InsightVM (optional) |
| **E – Broadcast Risk Layer** | PTP/Timing-Kritikalität, Real-Time-Media-Segmentierung |

## Neue Broadcast-Standards als Referenz

Ergänzung zu den bestehenden Standards (IEC 62443, NIST SP 800-82/-115):

| Standard | Relevanz für PiBroadGuard |
|----------|---------------------------|
| **EBU R143** | Hardening-Katalog: Accounts, Protokolle, Logging, Härtung, Defaults |
| **EBU R148** | Mindesttests für Netzwerksicherheit an Media Equipment |
| **EBU R160 S1** | Leitfaden Basis- und vertiefte Schwachstellenprüfung an Broadcast-Geräten |
| **AMWA BCP-003-01/02** | TLS und Authorization für NMOS APIs (OAuth2/JWT, IS-10) |
| **AMWA IS-04/05/10** | NMOS Discovery, Connection Management, Authorization API |
| **JT-NM TR-1001-1** | Erwartetes Verhalten von ST-2110-Media-Nodes |
| **SMPTE ST 2110** | Professional Media over IP (Referenzrahmen) |
| **SMPTE ST 2059** | PTP-Synchronisation in Broadcast-Netzwerken |

## Neue Datenquellen (geplant)

| Quelle | Priorität | Zweck |
|--------|-----------|-------|
| NVD CPE API v2 | Prio 1 | Präzisere CVE-Suche via strukturierten Produktnamen |
| NVD `hasKev`/`isVulnerable` Filter | Prio 1 | Gezieltere NVD-Abfragen |
| CISA ICS Advisories (RSS) | Prio 1 | OT/Appliance-Advisories für Broadcast-ähnliche Geräte |
| CSAF 2.0 Vendor Advisories | Prio 2 | Maschinenlesbare Herstellerhinweise (Siemens, Bosch, Cisco…) |
| AMWA NMOS IS-04 Query API | Prio 2 | Passives Geräte-Inventar ohne Portscan |
| Greenbone / Tenable / Rapid7 | Prio 3 | Externe Scanner-Konsolidierung |

## Neue Regelwerk-Kategorien (geplant)

| Kategorie | Fragenkatalog | Standard |
|-----------|---------------|---------|
| `nmos` | IS-04 vorhanden, IS-10 Auth, TLS/BCP-003, Registry-Adresse | AMWA BCP-003, IS-10 |
| `ptp_timing` | PTP vorhanden, GM-Rolle möglich, Domain gesperrt, Netz isoliert | SMPTE ST 2059, JT-NM TR-1001-1 |
| `network_arch` | Management/Media getrennt, VLAN erzwungen, Multicast kontrolliert | EBU R143, IEC 62443-3-2 |

## Neue Port-Regeln (geplant)

| rule_key | Port | Severity | Standard |
|----------|------|----------|---------|
| `ptp_event_open` | UDP 319 | medium | SMPTE ST 2059 |
| `ptp_general_open` | UDP 320 | medium | SMPTE ST 2059 |
| `nmos_registry_http` | TCP 8080 | medium | AMWA BCP-003 |
| `ssdp_open` | UDP 1900 | low | EBU R143 §4.2 |
| `mdns_open` | UDP 5353 | info | JT-NM TR-1001-1 |
| `bacnet_open` | UDP 47808 | high | IEC 62443 |

---

*Roadmap – Stand März 2026 | Details: TODO.md*
