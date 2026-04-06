# PiBroadGuard – Device Security Assessment Platform

Standardisiertes Sicherheits-Assessment für Broadcast-Geräte in Medienunternehmen.
Läuft auf dem Raspberry Pi 4 (ARM64) und Standard Linux (x86_64).

---

## Was ist PiBroadGuard?

Broadcast-Geräte – Encoder, Decoder, Matrixsysteme, Intercom, Multiviewer – verhalten sich anders als klassische IT-Systeme. Sie haben lange Produktlebenszyklen, proprietäre Management-Interfaces und betriebsnotwendige Legacy-Protokolle. Ein offener Telnet-Port ist auf einem Broadcast-Encoder möglicherweise nicht vermeidbar – aber er muss bewertet, dokumentiert und kompensiert werden.

**PiBroadGuard** schafft genau diesen Prozess: kontrollierte Netzwerkscans, ein broadcast-spezifisches Regelwerk und strukturierte Reports, die Technik, Betriebskontext und Kompensationsmassnahmen gemeinsam bewerten.

> PiBroadGuard ist kein Penetrationstest-Tool. Es ist ein standardisierter Assessment-Prozess für Geräte, die mit generischen Security-Tools nicht angemessen bewertet werden können.

---

## Für wen ist PiBroadGuard?

| Rolle | Nutzen |
|-------|--------|
| **IT Security Reviewer** | Technische Findings bewerten, Scores setzen, Freigabe erteilen |
| **Broadcast Engineer** | Geräte erfassen, betriebsnotwendige Dienste dokumentieren, Hersteller-Infos ergänzen |
| **Asset Management / Governance** | Reports als Grundlage für Einkaufsentscheide und Lifecycle-Planung |

---

## Was wird bewertet?

| Dimension | Inhalt | Standard |
|-----------|--------|----------|
| **Technisch** | Angriffsfläche, offene Ports, Scan-Findings | IEC 62443-4-2 / NIST SP 800-82 |
| **Betrieb** | Produktionskritikalität, Redundanz, Fallback | IEC 62443-3-2 |
| **Kompensation** | Segmentierung, ACLs, Monitoring | IEC 62443: Compensating Countermeasures |
| **Lifecycle** | Update-Fähigkeit, EOL-Datum, Support | IEC 62443-4-1 / NIST SP 800-30 |
| **Hersteller** | PSIRT, Advisories, Reaktionsfähigkeit | IEC 62443-4-1 PSIRT / SDL |

---

## Wie läuft ein Assessment ab?

```
1. Gerät erfassen (manuell oder via phpIPAM-Import)
2. Scan-Freigabe dokumentieren (Name, Rolle des Autorisierenden)
3. Nmap-Scan starten (Profil: passive / standard / extended)
4. Regelwerk erzeugt automatisch Findings (inkl. CVE/KEV-Lookup)
5. Broadcast Engineer ergänzt manuelle Antworten (Default-Creds? Telnet deaktivierbar? EOL-Datum?)
6. IT Security Reviewer setzt Scores und Kompensationsmassnahmen
7. Report generieren (Markdown / HTML / JSON)
8. Entscheid: Freigegeben / Mit Auflagen / Zurückgestellt / Abgelehnt
9. Re-Assessment-Termin festlegen + Scheduled Scan konfigurieren
```

---

## Scoring-Modell

Fünf gewichtete Dimensionen ergeben einen Gesamtscore (0–100):

| Dimension | Gewicht |
|-----------|---------|
| Technisch | 35 % |
| Betrieb | 20 % |
| Kompensation | 20 % |
| Lifecycle | 15 % |
| Hersteller | 10 % |

**Gesamtbewertung:**
- 🟢 Grün (≥ 75): Geeignet
- 🟡 Gelb (≥ 55): Geeignet mit Auflagen
- 🟠 Orange (≥ 35): Begrenzt einsetzbar
- 🔴 Rot (< 35): Nicht freigeben

**Überschreibungsregeln:**
- 2+ kritische Findings → automatisch Rot
- 1 unkompensiertes kritisches Finding → maximal Orange
- Lifecycle-Score < 20 → maximal Gelb

---

## Zweiphasiger Betrieb (Air-Gap)

```
Phase 1: Raspberry Pi im Broadcast-Netz (offline)
  → Gerät erfassen → Scan-Autorisierung → Nmap-Scan → .bdsa-Paket exportieren

Phase 2: Workstation mit Internetzugang (online)
  → Paket importieren → CVE/KEV-Lookup → Manuelle Fragen → Report generieren
```

Transport via USB (3-Schritt-Wizard). Optionale AES-256-GCM-Verschlüsselung mit Shared Secret.

---

## Angewandte Standards

**Broadcast-/Realtime-spezifisch:**

| Standard | Relevanz |
|----------|----------|
| **EBU R143** | Hardening-Katalog für Broadcast-Geräte (Accounts, Protokolle, Logging) |
| **EBU R148** | Mindesttests für Netzwerksicherheit an Media Equipment |
| **EBU R160 S1** | Leitfaden Basis- und vertiefte Schwachstellenprüfung |
| **AMWA BCP-003-01/02** | TLS und OAuth2/JWT-Authorization für NMOS APIs |
| **SMPTE ST 2110** | Professional Media over IP (Referenzrahmen) |
| **SMPTE ST 2059** | PTP-Synchronisation im Broadcast (Timing-Risiken) |
| **JT-NM TR-1001-1** | Erwartetes Verhalten von ST-2110-Media-Nodes |

**IT-Security / OT-Methodik:**

| Standard | Relevanz |
|----------|----------|
| **IEC 62443-3-2** | Risk Assessment für OT/ICS |
| **IEC 62443-4-2** | Component Security Requirements |
| **IEC 62443-4-1** | Product Lifecycle Security / PSIRT |
| **NIST SP 800-82r3** | Guide to OT Security |
| **NIST SP 800-115** | Technical Guide to Security Testing |
| **NIST SP 800-30r1** | Risk Assessment Methodology |
| **NIST CSF 2.0** | Cybersecurity Framework |

---

## Schnellstart (Docker)

```bash
git clone https://github.com/htckusi-ops/pibroadguard
cd pibroadguard
cp .env.example .env
# .env anpassen (Passwort, optionaler NVD API Key)
docker compose up -d
# Öffnen: http://localhost:8000
```

## Direktinstallation (systemd)

```bash
git clone https://github.com/htckusi-ops/pibroadguard
cd pibroadguard
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env && nano .env

# Nmap Raw-Socket-Berechtigung (für SYN-Scans)
sudo setcap cap_net_raw+ep $(which nmap)
getcap $(which nmap)  # Prüfen: cap_net_raw+ep

# Datenbank initialisieren
mkdir -p data/backups data/logs
alembic upgrade head

# Starten
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**systemd-Service installieren:**
```bash
sudo cp pibroadguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pibroadguard
```

---

## Update (Docker)

```bash
cd pibroadguard
git pull origin main
docker compose up -d --build
docker compose exec pibroadguard alembic upgrade head
```

## Update (systemd)

```bash
cd pibroadguard
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
sudo systemctl restart pibroadguard
```

---

## Konfiguration (.env)

| Variable | Standard | Beschreibung |
|----------|---------|--------------|
| `PIBG_USERNAME` | `admin` | Login-Benutzername |
| `PIBG_PASSWORD` | `changeme` | **Unbedingt ändern!** |
| `PIBG_DB_PATH` | `./data/pibroadguard.db` | Datenbankpfad |
| `PIBG_NVD_API_KEY` | — | Kostenlos: https://nvd.nist.gov/developers/request-an-api-key |
| `PIBG_SHARED_SECRET` | — | AES-256-GCM-Verschlüsselung für USB-Export |
| `PIBG_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `PIBG_MAX_PARALLEL_SCANS` | `1` | Gleichzeitige Scans (1 = sequenziell, empfohlen für Pi) |
| `PIBG_SCHEDULER_TIMEZONE` | `Europe/Zurich` | Zeitzone für geplante Scans |
| `PIBG_PHPIPAM_URL` | — | phpIPAM-Basis-URL (optional) |
| `PIBG_PHPIPAM_TOKEN` | — | phpIPAM API-Token (optional) |

Vollständige Liste: `.env.example`

---

## Geplante Scans (Scheduler)

Scans können zeitgesteuert ausgeführt werden:

- **Einmalig** – bestimmtes Datum/Uhrzeit
- **Intervall** – z.B. „alle 4 Wochen, dienstags um 02:00"
- **Cron** – beliebiger Cron-Ausdruck (z.B. `0 2 * * 1` für jeden Montag 02:00)

Alle Schedules werden mit Betriebsfreigabe (Name/Rolle) dokumentiert.
APScheduler persistiert die Jobs in der SQLite-DB – Schedules überleben Neustarts.

Übersicht aller Schedules: `/app/schedules.html`

---

## Scan-Auswirkungen auf Broadcast-Geräte

| Scan-Profil | Ports / Flags | Risiko | Empfehlung |
|-------------|--------------|--------|------------|
| `passive` | ~20 broadcast-relevante Ports, T2 | Niedrig | **Empfohlen für Live-Produktion** |
| `standard` | Top 1000 Ports, T3 | Mittel | Wartungsfenster nutzen |
| `extended` | Top 1000 TCP + UDP (SNMP/RTP), T3 | Erhöht | Nur im Testbetrieb |

---

## API-Dokumentation

Interaktive API-Docs: http://localhost:8000/api/docs

Alle Endpunkte unter `/api/v1/` – Basic Auth erforderlich.

```
GET/POST        /api/v1/devices
GET/PUT/DELETE  /api/v1/devices/{id}
POST            /api/v1/devices/{id}/assessments
GET/PUT         /api/v1/assessments/{id}
POST            /api/v1/assessments/{id}/scan
GET             /api/v1/assessments/{id}/scan/status
GET             /api/v1/assessments/{id}/scan/stream     # SSE
GET             /api/v1/assessments/{id}/scoring-details # Transparent scoring
GET/POST        /api/v1/assessments/{id}/manual-findings
GET             /api/v1/assessments/{id}/findings
GET             /api/v1/assessments/{id}/report/{md|html|json|pdf}
POST            /api/v1/assessments/{id}/export
POST            /api/v1/import
GET/POST        /api/v1/schedules
GET/DELETE      /api/v1/schedules/{id}
POST            /api/v1/schedules/{id}/pause|resume|run-now
GET             /api/v1/scan-queue/status
GET             /api/v1/device-types
GET             /api/v1/device-classes
GET             /api/v1/devices/reassessment-due         # Fälligkeitsliste
POST            /api/v1/devices/{id}/ping                # Einfacher Reachability-Check (persistiert Last Seen)
GET/POST        /api/v1/devices/{id}/probes              # Device Probe (Ping-only, kein Assessment)
POST            /api/v1/devices/{id}/nmos-check          # NMOS-Sicherheitscheck
GET/POST/PUT/DELETE /api/v1/rules                        # Regelwerk-CRUD
GET/POST        /api/v1/usb/devices|export|import
GET/POST        /api/v1/system/settings|backup|logs|connectivity|kev-sync
POST            /api/v1/system/ics-sync                  # CISA ICS Advisories synchronisieren
GET             /api/v1/system/ics-advisories            # ICS-Advisory-Suche
GET             /api/v1/system/api-keys                  # API-Key-Status und Rate-Limits
GET             /api/v1/cve/epss                         # FIRST EPSS-Scores (Exploit-Wahrscheinlichkeit)
POST            /api/v1/cve/csaf-import                  # CSAF 2.0 Advisory importieren
GET             /health  /version  (kein Auth)
```

---

## Frontend-Seiten

| Seite | Beschreibung |
|-------|-------------|
| `/app/index.html` | Dashboard: Geräteliste, Scan-Queue-Status, nächste Schedules, Re-Assessment-Fälligkeiten |
| `/app/device_form.html` | Gerät erfassen/bearbeiten, Assessment-Historie, Device Probes |
| `/app/assessment.html` | Assessment-Tabs: Übersicht / Scan / Fragen / Findings / Report / Schedules |
| `/app/schedules.html` | Alle geplanten Scans: Übersicht, Erstellen, Pause/Resume |
| `/app/rules.html` | Regelwerk-Verwaltung: CRUD, Filter, Inline-Bearbeitung |
| `/app/reassessment-due.html` | Re-Assessment-Fälligkeitsliste (überfällig / bald fällig) |
| `/app/import.html` | Scan-Paket importieren (Datei oder USB) |
| `/app/usb_export.html` | USB-Export-Wizard (3 Schritte, optional verschlüsselt) |
| `/app/phpipam_import.html` | Geräte aus phpIPAM importieren |
| `/app/settings.html` | System: Konnektivität, API-Keys, Verschlüsselung, Backup, Netzwerk-Konfiguration, Logfile-Viewer |

---

## Docker – Nmap und Raw Sockets

Im Docker-Container werden Nmap-Raw-Sockets über Linux Capabilities bereitgestellt. Die `docker-compose.yml` enthält bereits:

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

**Ohne diese Capabilities** fällt Nmap stillschweigend auf TCP-Connect-Scans zurück. Prüfen unter **Settings → Nmap Diagnostics**.

Für Scans ins Broadcast-Netz vom Pi aus empfohlen:
```yaml
network_mode: host
```

---

## Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Sicherheitshinweis

Scans nur mit expliziter Betriebsfreigabe durchführen (NIST SP 800-115). Das Tool erzwingt Dokumentation der Scan-Autorisierung vor jedem Scan.

---

## Datenbankstruktur

PiBroadGuard verwendet **SQLite** (via SQLAlchemy 2.x). Die Datenbank liegt standardmässig unter `./data/pibroadguard.db`. Migrationen werden mit Alembic verwaltet und beim App-Start automatisch eingespielt.

### Übersicht aller Tabellen

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAMMDATEN                                                                  │
│                                                                             │
│  devices ─────────────────────────┐                                         │
│  │ id, manufacturer, model        │                                         │
│  │ device_type, ip_address        │──── device_classes (Gerätetyp-Klassen)  │
│  │ hostname, firmware_version     │                                         │
│  │ location, network_segment      │──── device_types (konfigurierbar)       │
│  │ production_criticality         │                                         │
│  │ mac_address, rdns_hostname     │──── probe_results (schnelle Checks)     │
│  │ phpipam_id, device_class_id    │                                         │
│  └────────────────────────────────┘                                         │
│                    │ 1:n                                                     │
│  ASSESSMENT-KERN   ▼                                                         │
│                                                                             │
│  assessments ─────────────────────┐                                         │
│  │ id, device_id (FK)             │                                         │
│  │ status, scan_profile           │                                         │
│  │ scan_mode (assessment/         │                                         │
│  │   discovery)                   │                                         │
│  │ overall_rating                 │                                         │
│  │ technical/operational/         │                                         │
│  │   compensation/lifecycle/      │                                         │
│  │   vendor_score                 │                                         │
│  │ reviewer, summary              │                                         │
│  │ decision, reassessment_due     │                                         │
│  └──────────────┬─────────────────┘                                         │
│                 │ 1:n / 1:1                                                  │
│     ┌───────────┼────────────┬──────────────┬───────────────┐               │
│     ▼           ▼            ▼              ▼               ▼               │
│  scan_results  findings  manual_findings  scan_auth.  vendor_info           │
│  scan_authori- action_    audit_log       import_log                        │
│  zations       items                                                         │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  EXTERNE DATENQUELLEN (Caches)                                               │
│                                                                             │
│  cve_cache          kev_cache           ics_advisory_cache                  │
│  (NVD API, 7d TTL)  (CISA KEV, täglich) (CISA ICS Advisories, täglich)    │
│                                                                             │
│  system_settings  (Key-Value, persistent)                                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  AUTOMATISIERUNG                                                             │
│                                                                             │
│  scheduled_scans ──► devices (device_id FK)                                 │
│  scan_profiles   (konfigurierbare Scan-Profile inkl. is_discovery-Flag)    │
│  apscheduler_jobs (APScheduler-intern, nicht via Alembic)                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tabellen im Detail

| Tabelle | Zweck | Wichtige Felder |
|---------|-------|-----------------|
| `devices` | Gerät-Stammdaten | `ip_address` (Pflicht), `device_type`, `production_criticality`, `mac_address`, `rdns_hostname`, `phpipam_id` |
| `device_classes` | Geräteklassen (z.B. Broadcast, IT) | `name`, `label_de/en`, `risk_weight` |
| `device_types` | Gerätetypen (konfigurierbar) | `name`, `label_de/en`, `sort_order` |
| `assessments` | Sicherheitsbewertung | `scan_mode` (assessment/discovery), `overall_rating`, 5× Score, `decision` |
| `scan_results` | Nmap-Ergebnisse pro Port | `port`, `protocol`, `service_product`, `service_version`, `raw_nmap_output` |
| `findings` | Bewertete Schwachstellen | `rule_key`, `severity`, `cve_id`, `cvss_score`, `kev_listed`, `status`, `compensating_control_description` |
| `manual_findings` | Manuelle Antworten | `category` (auth/patch/hardening/monitoring/operational/vendor/scan_effects), `question_key`, `answer_value` |
| `scan_authorizations` | Scan-Freigabe (NIST 800-115) | `authorized_by_name/role`, `authorization_date`, `scan_profile`, `target_ip` |
| `vendor_information` | Hersteller-Sicherheitsinfos | `support_end_date`, `psirt_available`, `hardening_guide` |
| `action_items` | POA&M-Massnahmen | `priority` (immediate/short_term/long_term), `responsible_team`, `due_date` |
| `audit_log` | Änderungsprotokoll | `user`, `action`, `field_name`, `old_value`, `new_value` |
| `cve_cache` | NVD-API-Cache | `cve_id`, `cvss_score`, `description`, `fetched_at` (TTL: konfigurierbar) |
| `kev_cache` | CISA-KEV-Cache | `cve_id`, `required_action`, `known_ransomware`, `date_added_to_kev` |
| `ics_advisory_cache` | CISA ICS Advisories | `advisory_id`, `vendor`, `product`, `cve_ids` (JSON), `advisory_url`, `fetched_at` |
| `scan_profiles` | Nmap-Profile (YAML-Flags) | `nmap_flags` (JSON), `timeout_seconds`, `built_in`, `is_discovery` |
| `scheduled_scans` | Geplante Scans | `trigger_type` (once/interval/cron), `interval_unit/value`, `start_hour/minute` |
| `probe_results` | Schnelle Geräte-Probes (Ping-only) | `reachable`, `scan_duration_seconds`, `observations_json` |
| `system_settings` | Laufzeit-Konfiguration | Key-Value: `connectivity_mode`, `last_backup_at`, `encryption_enabled` |
| `import_log` | USB/Datei-Import-Protokoll | `package_id`, `source_host`, `package_checksum`, `status` |

### Tabellenbeziehungen (vereinfacht)

```
devices (1) ──── (n) assessments (1) ──── (n) scan_results
                                     (1) ──── (n) findings
                                     (1) ──── (n) manual_findings
                                     (1) ──── (1) scan_authorization
                                     (1) ──── (1) vendor_information
                                     (1) ──── (n) action_items
                                     (1) ──── (n) audit_log

devices (1) ──── (n) probe_results
devices (1) ──── (n) scheduled_scans

findings.cve_id  ─ ─ ─ (lookup) ─ ─ ─ cve_cache.cve_id
findings.cve_id  ─ ─ ─ (lookup) ─ ─ ─ kev_cache.cve_id
```

---

## Datenfluss

### Überblick: Woher kommen welche Daten?

```
┌──────────────────┐   ┌──────────────────┐   ┌───────────────────────┐
│  MANUELLE EINGABE│   │  NMAP-SCAN       │   │  EXTERNE QUELLEN      │
│                  │   │                  │   │                       │
│ • Gerät erfassen │   │ Nmap-Prozess     │   │ NVD API (NIST)        │
│   (Formular)     │   │ startet per      │   │ → CVE-IDs, CVSS       │
│ • Manuelle Fragen│   │ subprocess       │   │   Beschreibungen      │
│   beantworten    │   │ → XML-Output     │   │                       │
│ • Vendor-Infos   │   │   parsen         │   │ CISA KEV Feed         │
│   ergänzen       │   │ → Ports, Dienste │   │ → Aktiv ausgenutzte   │
│ • Findings       │   │   Versionen      │   │   Schwachstellen      │
│   bewerten       │   │   MAC-Adresse    │   │                       │
│ • Massnahmen     │   │                  │   │ phpIPAM (optional)    │
│   definieren     │   │                  │   │ → Geräteimport        │
└────────┬─────────┘   └────────┬─────────┘   └──────────┬────────────┘
         │                      │                         │
         ▼                      ▼                         ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     VERARBEITUNGSSCHICHT                              │
│                                                                      │
│  Rule Engine               CVE-Abgleich              Scoring         │
│  (YAML-Regelwerk)          (nur bei Assessments,     (5 Dimensionen, │
│  → Ports-offen-Regeln      nicht bei Discovery)      gewichtet)      │
│  → Manual-Antwort-Regeln   → Produkt+Version         → Overall       │
│  → Findings erstellen        aus scan_results          Rating        │
│                            → NVD-Lookup              → Schwellenwert-│
│                            → CVSS → Severity           Überschreib.  │
│                            → KEV-Check                               │
└────────────────────────────────────┬─────────────────────────────────┘
                                     │
                                     ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     SQLITE-DATENBANK                                 │
│                                                                      │
│  devices → assessments → scan_results                                │
│                       → findings (rule-based + CVE-based)            │
│                       → manual_findings                              │
│                       → scan_authorization                           │
│                       → vendor_information                           │
│                                                                      │
│  cve_cache / kev_cache (externe Daten, gecacht)                     │
│  scheduled_scans / scan_profiles (Automatisierung)                  │
└────────────────────────────────────┬─────────────────────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
             ┌──────────┐    ┌──────────────┐  ┌──────────────┐
             │ FRONTEND │    │ REPORT-ENGINE│  │ EXPORT       │
             │          │    │              │  │              │
             │ Vue 3    │    │ Jinja2       │  │ .bdsa-Paket  │
             │ Dashboard│    │ HTML-Report  │  │ (ZIP + SHA256)│
             │ Assessment│   │ MD-Report    │  │ Optional:    │
             │ Findings │    │ JSON-Report  │  │ AES-256-GCM  │
             │ Tab      │    │ PDF (WeasyP.)│  │ USB-Export   │
             └──────────┘    └──────────────┘  └──────────────┘
```

### Detaillierter Datenfluss: Von Scan bis Report

```
1. GERÄT ERFASSEN
   Formular / phpIPAM-Import
   → devices-Tabelle
   → rDNS-Lookup (async) → devices.rdns_hostname

2. ASSESSMENT STARTEN
   POST /devices/{id}/assessments
   → assessments-Tabelle (status=draft)
   → Manuelle Fragen vom letzten Assessment vorausgefüllt

3. SCAN AUTORISIEREN
   Formular (Name, Rolle, Zeitfenster)
   → scan_authorizations-Tabelle (Pflicht vor Scan)

4. NMAP-SCAN
   Nmap-Prozess (subprocess, XML-Output)
   → XML parsen: Ports, Dienste, Versionen, MAC
   → scan_results-Tabelle (inkl. raw_nmap_output für Audit)
   → assessments.scan_mode = "discovery" | "assessment"

5a. REGELWERK (nur Assessment-Modus)
    YAML-Regeln (port_open, manual_answer, service_detected)
    → findings-Tabelle (rule_key, severity, evidence, recommendation)

5b. CVE-LOOKUP (nur Assessment-Modus, nur online)
    service_product + service_version aus scan_results
    → cve_cache prüfen (TTL: 7 Tage)
    → Bei Cache-Miss: NVD API anfragen
    → CVSS-Score → Severity-Mapping
    → KEV-Daten prüfen (lokaler Cache)
    → findings-Tabelle (rule_key: cve_CVE-..., cve_id, cvss_score, kev_listed)

5c. SCORING (nur Assessment-Modus)
    Alle Findings (Severity + Status + Kompensation)
    → 5 Dimensionen berechnen
    → Überschreibungsregeln prüfen
    → assessments.*_score, assessments.overall_rating aktualisieren

6. MANUELLE FRAGEN
   Broadcast Engineer beantwortet Fragenkatalog
   → manual_findings-Tabelle (category, question_key, answer_value)
   → Bei Assessment: alle Kategorien (auth/patch/hardening/…)
   → Bei Discovery: nur scan_effects (Geräteverhalten während Scan)
   → POST /recalculate aktualisiert Scoring mit Manual-Antworten

7. REPORT-GENERIERUNG
   Jinja2-Templates lesen aus DB:
   → device, assessment, scan_results, findings
   → manual_findings, vendor_information, scan_authorization
   → Bei Assessment: report.html.j2 (Scores, Findings, Methodik)
   → Bei Discovery: report_discovery.html.j2 (Ports, Geräteverhalten)
   → Ausgabe: HTML / Markdown / JSON / PDF
```

### Datenquellen und ihre Verwendung

| Quelle | Daten | Verwendet für |
|--------|-------|---------------|
| **Formular-Eingabe** | Gerätestammdaten, Vendor-Infos | Identifikation, Lifecycle-Score, Report-Stammdaten |
| **Nmap-Scan** | Offene Ports, Dienste, Versionen, MAC, XML-Rohdaten | Regelwerk-Auswertung, CVE-Abgleich, Audit-Anhang im Report |
| **YAML-Regelwerk** | Regeln (port_open, manual_answer) | Technische Findings, broadcast-spezifische Empfehlungen |
| **NIST NVD API** | CVE-IDs, CVSS-Scores, Beschreibungen, Patches | CVE-Findings, Severity, NVD-Lösungsvorschläge im Report |
| **CISA KEV Feed** | Aktiv ausgenutzte CVEs, Required Action | KEV-Badge im Finding, erhöhte Severity, Dringlichkeits-Hinweis |
| **CISA ICS Advisories** | OT/ICS-spezifische Herstelleradvisories | Advisory-Abgleich für Broadcast-ähnliche Geräte (Siemens, ABB etc.) |
| **FIRST EPSS** | Exploit-Wahrscheinlichkeit pro CVE (0–100%) | EPSS-Badge im Finding; rot wenn Perzentile > 90 |
| **CSAF 2.0** | Maschinenlesbare Herstelleradvisories | Import via URL oder Upload; extrahiert CVEs, Produkte, Remediations |
| **AMWA NMOS IS-04/10** | Passiver NMOS-Dienst-Check auf Geräten | TLS-Check, Auth-Check (IS-10/BCP-003) via NMOS-Endpunkte |
| **Manuelle Fragen** | 58 strukturierte Fragen (10 Kategorien: auth/patch/hardening/monitoring/operational/vendor/nmos/ptp_timing/network_arch/scan_effects) | Operational/Lifecycle/Vendor-Score, Report-Fragebogen |
| **phpIPAM** | Hostlisten mit IP/Hostname/Subnetz | Massenimport von Geräten ohne manuelle Erfassung |

---

## CVE/NVD/KEV-Verarbeitung

### Übersicht: Externe Datenquellen

| Quelle | URL | Zugriff | Offline-fähig |
|--------|-----|---------|---------------|
| **NIST NVD API v2** | `services.nvd.nist.gov/rest/json/cves/2.0` | REST, optional API-Key | Nein (Cache 7 Tage) |
| **NIST NVD CPE API** | `services.nvd.nist.gov/rest/json/cpes/2.0` | REST, optional API-Key | Nein |
| **CISA KEV Feed** | `cisa.gov/.../known_exploited_vulnerabilities.json` | JSON-Download | Ja (lokaler Cache) |
| **CISA ICS Advisories** | `cisa.gov/ics-advisories.xml` (RSS) | RSS-Feed | Ja (lokaler Cache) |
| **FIRST.org EPSS** | `api.first.org/data/1.0/epss` | REST, kein Key nötig | Nein (Fallback: leer) |
| **CSAF 2.0** | Vendor-URL oder Upload | JSON-Fetch oder Datei | Ja (Datei-Upload) |
| **AMWA NMOS** | `http://{device}/x-nmos/...` | HTTP auf Gerät | Ja (lokal) |

### Schritt 1: Wie werden Scan-Resultate abgeglichen?

Das Matching basiert auf dem **Produktnamen**, den Nmap aus dem Dienst-Banner erkennt:

```
Nmap scan_result:
  port=443, service_product="OpenSSL", service_version="3.0.2"
         ↓
  cve_service.lookup_cves(
      vendor  = "OpenSSL",   ← gleich wie product (kein separater Hersteller)
      product = "OpenSSL",
      version = "3.0.2"
  )
```

> **Wichtig – Keyword-Matching, kein CPE:**
> Die NVD-Suche verwendet `keywordSearch=OpenSSL OpenSSL` – d.h. eine Freitextsuche.
> Es wird **kein** CPE-Matching (Common Platform Enumeration) verwendet.
> Das bedeutet: Bei generischen Produktnamen (z.B. "Apache", "nginx") können
> zu viele oder falsche Treffer entstehen. Die Ergebnisse sind als Hinweise zu
> verstehen und müssen vom Reviewer beurteilt werden.

### Schritt 2: Cache-Logik

```
lookup_cves() aufgerufen
        ↓
cve_cache-Tabelle prüfen:
  WHERE vendor = X AND product = Y
    AND fetched_at > (jetzt - TTL_Tage)
        ↓
  Cache-Hit?  ──→ Ja:  Cached-Einträge zurückgeben (kein API-Call)
                  Nein: NVD API aufrufen
                        ↓
                   Ergebnisse in cve_cache speichern (db.merge)
                   ↓
                   Zurückgeben
```

TTL konfigurierbar via `PIBG_CVE_CACHE_TTL_DAYS` (Standard: 7 Tage).

### Schritt 3: NVD-API-Antwort → Felder

```json
NVD-Response (vereinfacht):
{
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-2022-0778",
      "descriptions": [{"lang": "en", "value": "The BN_mod_sqrt() function..."}],
      "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]
      },
      "evaluatorSolution": "Upgrade to OpenSSL 3.0.2 or later.",
      "references": [{"url": "https://...", "tags": ["Vendor Advisory"]}],
      "weaknesses": [{"description": [{"value": "CWE-835"}]}]
    }
  }]
}
```

Extrahierte Felder und Verwendung:

| NVD-Feld | Gespeichert in | Angezeigt als |
|----------|----------------|---------------|
| `cve.id` | `findings.cve_id`, `cve_cache.cve_id` | CVE-Badge mit NVD-Link |
| `cvssMetricV31.baseScore` | `cve_cache.cvss_score`, `findings.cvss_score` | CVSS-Badge (farbkodiert) |
| `descriptions[lang=en]` | `cve_cache.description`, `findings.description` | Finding-Beschreibung |
| `evaluatorSolution` | `findings.nvd_solution` | „NVD-Lösung:" in Empfehlung |
| `references[Vendor Advisory].url` | `findings.vendor_advisory_url` | „🔗 Hersteller-Advisory" |
| `weaknesses[0].value` | `findings.cwe_id` | CWE-Badge mit MITRE-Link |
| `published` | `cve_cache.published_date` | Publikationsdatum (Info) |

### Schritt 4: CVSS → Severity-Mapping

```python
CVSS >= 9.0  →  critical   (Findings-Karte: dunkelrot)
CVSS >= 7.0  →  high       (Findings-Karte: orange)
CVSS >= 4.0  →  medium     (Findings-Karte: gelb)
CVSS  < 4.0  →  low        (Findings-Karte: grün)
CVSS  = 0.0  →  Finding wird nicht erstellt (kein Score = kein Treffer)
```

Bei `severity >= high` (CVSS ≥ 7.0) wird `compensating_control_required = True` gesetzt.

### Schritt 5: KEV-Abgleich

Nach dem NVD-Lookup wird jede gefundene CVE-ID gegen den lokalen KEV-Cache geprüft:

```
cve_id = "CVE-2021-44228"
        ↓
kev_cache WHERE cve_id = "CVE-2021-44228"
        ↓
  Treffer?  →  Ja:  findings.kev_listed = True
                    findings.kev_required_action = "Apply updates per vendor instructions."
                    → Rotes ⚠️-KEV-Badge im Finding
                    → „CISA KEV – Required Action:" in Empfehlung

             →  Nein: kein KEV-Badge
```

KEV-Cache wird täglich synchronisiert (manuell über Settings oder automatisch beim Start wenn online).

### Schritt 6: EPSS (Exploit Prediction Scoring System)

Zusätzlich zu CVSS bietet PiBroadGuard den **EPSS-Score** von FIRST.org an:

- Gibt die **Wahrscheinlichkeit** an (0–1), dass eine CVE innerhalb von 30 Tagen aktiv ausgenutzt wird
- Kostenlos, kein API-Key nötig
- Wird **automatisch beim Scan-Abschluss** für alle neu gefundenen CVEs als Batch abgerufen (`get_epss_scores()`)
- Ergebnis: `epss_score` + `epss_percentile` pro Finding; Badge im UI und Report (rot wenn Perzentile ≥ 90)
- Graceful Fallback (kein Badge) bei Offline-Betrieb

### Zusammenfassung: CVE-Finding Erstellungsprozess

```
┌─────────────────────────────────────────────────────────────────────┐
│  scan_results: service_product="OpenSSL", service_version="3.0.2"  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  cve_cache prüfen   │
                    │  (TTL: 7 Tage)      │
                    └──────────┬──────────┘
               Cache-Hit ◄─────┴─────► Cache-Miss
                    │                       │
                    │              ┌────────▼────────┐
                    │              │  NVD API v2     │
                    │              │  keywordSearch= │
                    │              │  "OpenSSL       │
                    │              │   OpenSSL"      │
                    │              │  max. 10 CVEs   │
                    │              └────────┬────────┘
                    │                       │
                    └──────────┬────────────┘
                               │ CVE-Liste
                               ▼
                    ┌──────────────────────┐
                    │  Pro CVE:            │
                    │  • CVSS → Severity   │
                    │  • KEV-Cache prüfen  │
                    │  • Deduplizieren     │
                    │    (seen_cves Set)   │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │  Finding upsert:     │
                    │  rule_key =          │
                    │  "cve_cve_2022_0778" │
                    │  title = "CVE-... – │
                    │    OpenSSL (CVSS 7.5)"│
                    │  evidence = "Port    │
                    │    443/tcp: OpenSSL  │
                    │    3.0.2"            │
                    │  kev_listed = False  │
                    │  nvd_solution = "..."│
                    │  cwe_id = "CWE-835"  │
                    └──────────────────────┘
```

### Einschränkungen und Hinweise

| Thema | Details |
|-------|---------|
| **Kein CPE-Matching** | Suche ist Keyword-basiert → False-Positives bei generischen Namen möglich |
| **Keine Version-Filterung** | Alle CVEs zum Produkt werden zurückgegeben, unabhängig ob die Version betroffen ist |
| **Nur NVD v3.1/v3.0** | CVSS v4.0-Scores werden noch nicht ausgewertet (NVD-Feld vorhanden aber nicht implementiert) |
| **Rate Limits** | Ohne API-Key: 5 Req/30s · Mit Key: 50 Req/30s (Key kostenlos: nvd.nist.gov/developers) |
| **Offline-Betrieb** | CVE-Findings werden nicht erstellt; bestehende Cache-Daten bleiben erhalten |
| **CVE-Findings im Report** | Erscheinen im Finding-Tab zusammen mit regelwerk-basierten Findings; unterscheidbar am `rule_key`-Präfix `cve_` |

---

*PiBroadGuard v1.12 – Device Security Assessment Platform | April 2026 | Markus Gerber · markus.gerber@npn.ch*
