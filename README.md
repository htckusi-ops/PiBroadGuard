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
GET             /api/v1/assessments/{id}/report/{md|html|json}
POST            /api/v1/assessments/{id}/export
POST            /api/v1/import
GET/POST        /api/v1/schedules
GET/DELETE      /api/v1/schedules/{id}
POST            /api/v1/schedules/{id}/pause|resume|run-now
GET             /api/v1/scan-queue/status
GET             /api/v1/device-types
GET             /api/v1/device-classes
GET/POST        /api/v1/usb/devices|export|import
GET/POST        /api/v1/system/settings|backup|logs|connectivity|kev-sync
GET             /health  /version  (kein Auth)
```

---

## Frontend-Seiten

| Seite | Beschreibung |
|-------|-------------|
| `/app/index.html` | Dashboard: Geräteliste, Scan-Queue-Status, nächste Schedules |
| `/app/device_form.html` | Gerät erfassen/bearbeiten, Assessment-Historie |
| `/app/assessment.html` | Assessment-Tabs: Übersicht / Scan / Fragen / Findings / Report / Schedules |
| `/app/schedules.html` | Alle Schedules: Übersicht, Erstellen, Pause/Resume |
| `/app/import.html` | Scan-Paket importieren (Datei oder USB) |
| `/app/usb_export.html` | USB-Export-Wizard (3 Schritte, optional verschlüsselt) |
| `/app/phpipam_import.html` | Geräte aus phpIPAM importieren |
| `/app/settings.html` | System: Konnektivität, Verschlüsselung, Backup, Logfile-Viewer |

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

*PiBroadGuard v1.8 – Device Security Assessment Platform | März 2026 | Markus Gerber · markus.gerber@npn.ch*
