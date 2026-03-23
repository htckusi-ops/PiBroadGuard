# PiBroadGuard – Broadcast Device Security Assessment

Standardisiertes Sicherheits-Assessment-Tool für Broadcast-Geräte in Medienunternehmen. Läuft auf dem Raspberry Pi 4 (ARM64) und Standard Linux (x86_64).

## Überblick

PiBroadGuard kombiniert Nmap-Scans mit einem broadcast-spezifischen Regelwerk und manuellen Bewertungsfragen zu strukturierten Security-Reports. Es berücksichtigt die besonderen Anforderungen von Broadcast-Umgebungen (Legacy-Protokolle, Produktionskritikalität, Kompensationsmassnahmen).

**Bewertungsdimensionen:** Technisch | Betrieb | Kompensation | Lifecycle | Hersteller

**Standards:** IEC 62443-3-2/-4-2/-4-1, NIST SP 800-82r3/-115/-30r1, NIST CSF 2.0

## Funktionsübersicht

| Bereich | Features |
|---------|----------|
| **Geräte-Management** | CRUD, Gerätetypen aus DB, rDNS-Lookup, MAC-Erkennung, phpIPAM-Import |
| **Scan** | 3 Profile (passive/standard/extended), Autorisierungsformular, Live-Output (SSE), Scan-Queue, parallele Jobs konfigurierbar |
| **Geplante Scans** | Einmalig / Intervall (Stunden/Tage/Wochen/Monate) / Cron-Expression, Uhrzeit-Auswahl, APScheduler-Persistenz |
| **Regelwerk** | YAML, 15+ broadcast-spezifische Regeln, Severity-basiertes Scoring |
| **Findings** | CVE-Lookup (NVD API v2), KEV-Check (CISA), CWE-Empfehlungen, Lösungsquellen-Badges, KEV-Badge mit Link |
| **Scoring** | 5 Dimensionen gewichtet, Kompensations-Override, Norm-Referenz pro Dimension |
| **Reports** | Markdown / HTML / JSON, Methodikabschnitt, Normenreferenzen |
| **Zweiphasig** | .bdsa-Pakete (ZIP + SHA256), optionale AES-256-GCM-Verschlüsselung, USB-Wizard (3 Schritte) |
| **Settings** | Konnektivitätsmodus (Auto/Online/Offline), KEV-Sync, SQLite-Backup, Logfile-Viewer, Nmap-Diagnose |
| **UI** | Vue 3 via CDN, Tailwind CSS, Deutsch/Englisch (i18n), Tooltips |

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

## Update (Docker)

**Wichtig:** Alle Befehle müssen im Projektverzeichnis (`cd pibroadguard`) ausgeführt werden.

```bash
cd pibroadguard

# 1. Neuen Code holen
git pull origin main

# 2. Image neu bauen und Container neu starten
docker compose up -d --build

# 3. Datenbankmigrationen anwenden (neue Tabellen/Spalten)
docker compose exec pibroadguard alembic upgrade head
```

Daten (SQLite-Datenbank in `./data/`) bleiben beim Update erhalten.

## Update (systemd)

```bash
cd pibroadguard

# 1. Neuen Code holen
git pull origin main

# 2. Abhängigkeiten aktualisieren
source venv/bin/activate
pip install -r requirements.txt

# 3. Datenbankmigrationen anwenden
alembic upgrade head

# 4. Service neu starten
sudo systemctl restart pibroadguard
```

## Zweiphasiger Betrieb (Air-Gap)

```
Phase 1: Raspberry Pi im Broadcast-Netz (offline)
  → Gerät erfassen → Scan-Autorisierung → Nmap-Scan → .bdsa-Paket exportieren

Phase 2: Workstation mit Internetzugang (online)
  → Paket importieren → CVE/KEV-Lookup → Manuelle Fragen → Report generieren
```

Export via USB (3-Schritt-Wizard): `/app/usb_export.html`

Verschlüsselung: AES-256-GCM mit Shared Secret (in `.env` oder Settings-Seite konfigurierbar).

## Geplante Scans (Scheduler)

Scans können zeitgesteuert ausgeführt werden:

- **Einmalig** – bestimmtes Datum/Uhrzeit
- **Intervall** – z.B. „alle 4 Wochen, dienstags um 02:00" mit Uhrzeit-Auswahl
- **Cron** – beliebiger Cron-Ausdruck (z.B. `0 2 * * 1` für jeden Montag 02:00)

Alle Schedules werden mit Betriebsfreigabe (Name/Rolle) dokumentiert.
APScheduler persistiert die Jobs in der SQLite-DB – Schedules überleben Neustarts.

Übersicht aller Schedules: `/app/schedules.html`

## Konfiguration (.env)

| Variable | Standard | Beschreibung |
|----------|---------|--------------|
| `PIBG_USERNAME` | `admin` | Login-Benutzername |
| `PIBG_PASSWORD` | `changeme` | **Unbedingt ändern!** |
| `PIBG_DB_PATH` | `./data/pibroadguard.db` | Datenbankpfad |
| `PIBG_NVD_API_KEY` | — | Kostenlos: https://nvd.nist.gov/developers/request-an-api-key |
| `PIBG_SHARED_SECRET` | — | Für verschlüsselten USB-Export (AES-256-GCM) |
| `PIBG_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |
| `PIBG_MAX_PARALLEL_SCANS` | `1` | Gleichzeitige Scans (1 = sequenziell, empfohlen für Pi) |
| `PIBG_SCHEDULER_TIMEZONE` | `Europe/Zurich` | Zeitzone für geplante Scans |
| `PIBG_PHPIPAM_URL` | — | phpIPAM-Basis-URL (optional) |
| `PIBG_PHPIPAM_TOKEN` | — | phpIPAM API-Token (optional) |

Vollständige Liste: `.env.example`

## Tests

```bash
pip install pytest
pytest tests/ -v
```

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
GET/POST        /api/v1/assessments/{id}/manual-findings
GET             /api/v1/assessments/{id}/findings
GET             /api/v1/assessments/{id}/report/{md|html|json}
POST            /api/v1/assessments/{id}/export
POST            /api/v1/import
GET/POST        /api/v1/schedules
GET/DELETE      /api/v1/schedules/{id}
POST            /api/v1/schedules/{id}/pause|resume|run-now
GET             /api/v1/scan-queue/status
DELETE          /api/v1/scan-queue/{job_id}
GET/POST        /api/v1/usb/devices|export|import
GET/POST        /api/v1/system/settings|backup|logs|connectivity|kev-sync
GET             /health  /version  (kein Auth)
```

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

## Docker – wichtige Hinweise

### Nmap und Raw Sockets

Im Docker-Container werden Nmap-Raw-Sockets über Linux Capabilities bereitgestellt. Die `docker-compose.yml` enthält bereits:

```yaml
cap_add:
  - NET_RAW
  - NET_ADMIN
```

**Ohne diese Capabilities** fällt Nmap stillschweigend auf TCP-Connect-Scans zurück (kein SYN-Scan, weniger präzise, keine Fehlermeldung). Prüfen im UI unter **Settings → Nmap Diagnostics**.

### Netzwerk-Modus (Raspberry Pi)

Der Docker-Container verwendet standardmässig Bridge-Networking. Für Scans ins Broadcast-Netz muss der Container das Zielnetz erreichen können:

```bash
# Option A: Host-Networking (einfachste Lösung, empfohlen für den Pi)
# In docker-compose.yml unter dem Service ergänzen:
network_mode: host

# Option B: Statische Route auf dem Pi-Host hinzufügen
sudo ip route add 192.168.10.0/24 via <gateway>
```

**Prüfen ob das Zielnetz erreichbar ist:**
```bash
docker compose exec pibroadguard ping -c 2 <ziel-ip>
```

### Datenpersistenz

Die SQLite-Datenbank liegt im Volume `./data/` ausserhalb des Containers:
```
./data/pibroadguard.db     # Datenbank
./data/backups/            # Lokale Backups (max. 5, konfigurierbar)
./data/logs/               # Logfiles (RotatingFileHandler, 5 MB / 3 Backups)
```

`docker compose down` löscht **nicht** die Daten. Nur `docker compose down -v` würde das Volume entfernen (nicht empfohlen).

---

## Direktinstallation – Nmap Capabilities (systemd)

Bei der direkten Installation ohne Docker müssen Raw-Socket-Rechte explizit gesetzt werden:

```bash
# Einmalig nach der Installation
sudo setcap cap_net_raw+ep $(which nmap)

# Prüfen
getcap $(which nmap)
# Erwartete Ausgabe: /usr/bin/nmap cap_net_raw+ep
```

**Ohne `setcap`** laufen Nmap-Scans nur als TCP-Connect-Scan. Das Tool zeigt eine Warnung im Dashboard und unter Settings → Nmap Diagnostics.

> **Hinweis:** Bei einem Nmap-Update via `apt upgrade` kann die Capability verloren gehen. Nach jedem Nmap-Update erneut ausführen.

---

## Netzwerk-Hinweise für Broadcast-Umgebungen

### VLAN-Zugriff

Wenn der Raspberry Pi in einem separaten Management-VLAN steht, muss Routing zum Broadcast-VLAN eingerichtet sein. Empfehlung: Pi ins Management-VLAN mit gerouteten Pfaden zu allen Broadcast-Segmenten.

### Scan-Auswirkungen auf Broadcast-Geräte

Manche Broadcast-Geräte reagieren empfindlich auf Netzwerkscans:

| Scan-Profil | Ports / Flags | Risiko | Empfehlung |
|-------------|--------------|--------|------------|
| `passive` | ~20 broadcast-relevante Ports, T2 | Niedrig | **Empfohlen für Live-Produktion** |
| `standard` | Top 1000 Ports, T3 | Mittel | Wartungsfenster nutzen |
| `extended` | Top 1000 TCP + UDP (SNMP/RTP), T3 | Erhöht | Nur im Testbetrieb / ausserhalb Produktion |

**SNMP-UDP-Scans** (Extended-Profil) können bei manchen Geräten Syslog-Floods auslösen.

### Firewall / ACL-Anforderungen

Für Nmap-Scans muss der Pi direkte TCP/UDP-Verbindungen zu den Zielgeräten aufbauen können. Temporäre ACL-Regeln falls nötig:
```
Quelle:  <Pi-IP>
Ziel:    <Broadcast-Subnetz>
Ports:   TCP 1-65535, UDP (Extended-Profil)
Protokoll: ICMP (optional, für Host-Discovery)
```

---

## Sicherheitshinweis

Scans nur mit expliziter Betriebsfreigabe durchführen (NIST SP 800-115). Das Tool erzwingt Dokumentation der Scan-Autorisierung vor jedem Scan.

---

*PiBroadGuard v1.8 | März 2026 | Markus Gerber · markus.gerber@npn.ch*
