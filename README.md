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
./data/backups/            # Lokale Backups
./data/logs/               # Logfiles
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

| Scan-Profil | Risiko | Empfehlung |
|-------------|--------|------------|
| `passive` | Niedrig – nur bekannte Ports, T2 | **Empfohlen für Live-Produktion** |
| `standard` | Mittel – alle Ports, T3 | Wartungsfenster nutzen |
| `extended` | Erhöht – inkl. UDP-Scan | Nur im Testbetrieb / ausserhalb Produktion |

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

*PiBroadGuard v1.0 | March 2026*
