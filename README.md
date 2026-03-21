# PiBroadGuard – Broadcast Device Security Assessment

Standardisiertes Sicherheits-Assessment-Tool für Broadcast-Geräte in Medienunternehmen. Läuft auf dem Raspberry Pi 4 (ARM64) und Standard Linux (x86_64).

## Überblick

PiBroadGuard kombiniert Nmap-Scans mit einem broadcast-spezifischen Regelwerk und manuellen Bewertungsfragen zu strukturierten Security-Reports. Es berücksichtigt die besonderen Anforderungen von Broadcast-Umgebungen (Legacy-Protokolle, Produktionskritikalität, Kompensationsmassnahmen).

**Bewertungsdimensionen:** Technisch | Betrieb | Kompensation | Lifecycle | Hersteller

**Standards:** IEC 62443-3-2/-4-2, NIST SP 800-82r3/-115/-30r1

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
docker compose exec bdsa alembic upgrade head
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

## Konfiguration (.env)

| Variable | Standard | Beschreibung |
|----------|---------|--------------|
| `PIBG_USERNAME` | `admin` | Login-Benutzername |
| `PIBG_PASSWORD` | `changeme` | **Unbedingt ändern!** |
| `PIBG_NVD_API_KEY` | — | Kostenlos: https://nvd.nist.gov/developers/request-an-api-key |
| `PIBG_SHARED_SECRET` | — | Für verschlüsselten USB-Export (AES-256-GCM) |
| `PIBG_LOG_LEVEL` | `INFO` | DEBUG / INFO / WARNING / ERROR |

Vollständige Liste: `.env.example`

## Tests

```bash
pip install pytest
pytest tests/ -v
```

## API-Dokumentation

Interaktive API-Docs: http://localhost:8000/api/docs

Alle Endpunkte unter `/api/v1/` – Basic Auth erforderlich.

## Sicherheitshinweis

Scans nur mit expliziter Betriebsfreigabe durchführen (NIST SP 800-115). Das Tool erzwingt Dokumentation der Scan-Autorisierung vor jedem Scan.

---

*PiBroadGuard v1.0 | März 2026*
