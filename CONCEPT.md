# CONCEPT.md – PiBroadGuard
## Fachliches Konzept und Hintergrund
**Version:** 1.12 | März 2026

Dieses Dokument erklärt den fachlichen Kontext, die Zielgruppe und die
Leitprinzipien von PiBroadGuard. Es ergänzt die technische Spezifikation
(CLAUDE.md) und hilft bei Designentscheidungen, die die Spec nicht explizit
abdeckt.

---

## 1. Problemstellung

In Medienunternehmen und Broadcast-Umgebungen existiert eine Sicherheitslücke
zwischen klassischer IT-Security und produktionsnaher Broadcast-Infrastruktur.

**Broadcast-Geräte folgen anderen Mustern als IT-Systeme:**
- Proprietäre oder spezialisierte Management-Interfaces
- Eingeschränkte Härtbarkeit durch den Hersteller
- Sehr lange Produktlebenszyklen (10–20 Jahre)
- Legacy-Protokolle die betriebsnotwendig sind (Telnet, unverschlüsseltes HTTP)
- Eingeschränkte oder fehlende Update-Fähigkeit
- Hohe Verfügbarkeitsanforderungen – Ausfall bedeutet Sendeausfall
- Trennung zwischen Herstellerlogik und klassischer IT-Logik

**Das Ergebnis:** IT-Security-Teams können diese Geräte mit generischen Tools
nicht angemessen bewerten. Ein offener Telnet-Port ist auf einem Office-PC
inakzeptabel, auf einem Broadcast-Encoder aber möglicherweise betriebsnotwendig
und durch Netzwerksegmentierung kompensierbar.

---

## 2. Lösung: PiBroadGuard

PiBroadGuard schafft einen standardisierten, nachvollziehbaren und teilweise
automatisierten Bewertungsprozess speziell für Broadcast-Geräte.

**Der zentrale Unterschied zu generischen Security-Tools:**
Ein technischer Befund wird nicht isoliert betrachtet, sondern immer in den
Betriebs- und Produktionskontext eingeordnet. Ein Finding ist nicht
automatisch ein Freigabehindernis – es kann durch kompensierende Massnahmen
(Netzwerksegmentierung, ACLs, Jump Hosts, Monitoring) akzeptierbar gemacht
werden.

**PiBroadGuard ist kein Penetrationstest-Tool.** Es führt kontrollierte,
schonende Netzwerkscans durch und kombiniert diese mit manuellen
Beurteilungen zu einem strukturierten Assessment-Report.

---

## 3. Zielgruppe

PiBroadGuard richtet sich an drei Gruppen, die im Assessment-Prozess
zusammenarbeiten:

**IT Security Reviewer**
Bewertet technische Findings, setzt Scores, gibt Freigabe oder definiert
Auflagen. Hat Erfahrung mit Netzwerksicherheit, aber möglicherweise wenig
Broadcast-Know-how.

**Broadcast Engineer**
Kennt die Geräte, weiss welche Dienste betriebsnotwendig sind, kann
Hersteller-Informationen beschaffen. Hat möglicherweise wenig IT-Security-
Erfahrung.

**Asset Management / Governance**
Nutzt den Report als Grundlage für Einkaufsentscheide, Freigaben,
Ausnahmedokumentation und Lifecycle-Planung.

**Das Tool muss für alle drei Gruppen verständlich und bedienbar sein.**
Technische Details gehören in die Findings-Tabs, nicht in die Executive
Summary.

---

## 4. Typischer Anwendungsfall

**Erstbewertung (neues Gerät):**
```
1. Neues Broadcast-Gerät soll beschafft oder in Betrieb genommen werden.
2. Broadcast Engineer erfasst das Gerät in PiBroadGuard (optional via phpIPAM-Import).
3. Scan-Freigabe wird vom Betriebsverantwortlichen eingeholt und dokumentiert.
4. Nmap-Scan wird gegen die Test-IP durchgeführt (Passive-Profil empfohlen).
5. Regelwerk erzeugt automatische Findings (inkl. CVE-Lookup, KEV-Check).
6. Broadcast Engineer ergänzt manuelle Informationen:
   - Gibt es Default-Credentials?
   - Ist Telnet deaktivierbar?
   - Gibt es Security-Updates?
   - Ist das Gerät produktionskritisch?
7. IT Security Reviewer prüft, ergänzt Kompensationsmassnahmen, setzt Scores.
8. Report wird generiert (MD / HTML / JSON).
9. Entscheid: Freigegeben / Freigegeben mit Auflagen / Zurückgestellt / Abgelehnt.
10. Re-Assessment-Termin wird festgelegt + Scheduled Scan konfiguriert.
```

**Periodische Neubewertung (bestehende Geräte):**
```
1. Geplanter Scan wird automatisch ausgelöst (APScheduler).
2. Neues Assessment mit Scan-Resultaten wird erstellt.
3. Reviewer prüft Veränderungen gegenüber dem letzten Assessment.
4. Report und Entscheid werden aktualisiert.
```

**Air-Gap-Betrieb (Pi ohne Internetzugang):**
```
1. Scans auf Pi (Phase 1) → .bdsa-Paket auf USB exportieren (optional verschlüsselt).
2. Paket auf Online-Workstation importieren (Phase 2).
3. CVE/KEV-Anreicherung, manuelle Fragen, Report-Generierung.
```

**Schnelle Geräteerkundung (Device Probe):**
```
1. Gerät ist neu im Netz oder Verhalten unbekannt.
2. Broadcast Engineer startet einen Probe direkt auf der Geräteseite.
3. Probe läuft ausserhalb der Assessment-Queue – kein Regelwerk, kein Scoring.
4. Offene Ports werden angezeigt; Beobachtungen (Freitext) können notiert werden.
5. Bei auffälligem Ergebnis: vollständiges Assessment starten.
```

---

## 5. Leitprinzipien (für Designentscheidungen)

Diese Prinzipien helfen bei Entscheidungen, die die Spec nicht explizit
abdeckt:

### 5.1 Broadcast-Kontext vor generischer IT-Logik
Ein Finding wird nie nur technisch bewertet. Immer die Frage: Ist dieser
Befund in einer Broadcast-Umgebung mit entsprechenden Kompensationen
akzeptierbar?

### 5.2 Befund ist nicht gleich Freigabeentscheid
Ein offener unsicherer Dienst kann kompensiert werden. Die Regeln müssen
bewusst definiert sein – ein roter technischer Befund kann durch starke
Kompensation zu Gelb werden, aber nicht beliebig.

### 5.3 Reproduzierbarkeit und Nachvollziehbarkeit
Alle Bewertungen müssen dokumentiert, später überprüfbar und konsistent
sein. Deshalb: Audit-Log, Scan-Autorisierung, Regelwerk-Snapshot im Paket,
SHA256-Checksummen.

### 5.4 Automatisierung wo sinnvoll, manuelle Bewertung wo nötig
Scans, erste Klassifikationen und periodische Wiederholungs-Scans werden automatisiert.
Kontextbewertung, Hersteller-Informationen und Freigabeentscheide bleiben beim Menschen.
Das Tool unterstützt – es ersetzt kein Fachwissen. Geplante Scans erfordern trotzdem eine
vorab dokumentierte Betriebsfreigabe (Name, Rolle des Autorisierenden).

### 5.8 Discovery vor Assessment
Unbekannte Geräte werden zuerst mit einem leichtgewichtigen Discovery-Scan erkundet,
bevor ein vollständiges Assessment mit Regelwerk und Scoring durchgeführt wird.
Discovery-Scans erzeugen keine Findings und beeinflussen kein bestehendes Assessment.
Sie dokumentieren auch Scan-Seiteneffekte (Reboots, Signalstörungen), die auf die
Empfindlichkeit des Geräts hinweisen.

### 5.5 Hersteller- und Lifecycle-Aspekte gehören zur Sicherheitsbewertung
Ein technisch unauffälliges Gerät kann langfristig ungeeignet sein, wenn
Security-Updates fehlen oder der Support unklar ist. Deshalb sind
Lifecycle-Score und Vendor-Score eigenständige Bewertungsdimensionen.

### 5.6 Einfachheit vor Vollständigkeit
PiBroadGuard soll auf einem Raspberry Pi laufen und von einem kleinen Team
ohne dediziertes Security-Operations-Center betrieben werden. Kein
Overengineering. Pragmatischer MVP statt perfektes System.

### 5.7 Sicherheit des Tools selbst
Das Tool verarbeitet sensible Infrastrukturinformationen (IP-Adressen,
offene Ports, Firmware-Versionen). Scan-Pakete müssen verschlüsselt
transportierbar sein. Der Zugang ist durch Auth geschützt.

---

## 6. Abgrenzung: Was PiBroadGuard nicht ist

| Nicht | Stattdessen |
|-------|-------------|
| Vollautomatisches Vulnerability-Management | Ergänzung zu bestehenden Prozessen |
| Penetrationstest-Tool | Schonender Assessment-Scan |
| Ersatz für Broadcast-Engineering-Know-how | Strukturiertes Werkzeug dafür |
| Forensik- oder Reverse-Engineering-Tool | Standardisierte Bewertung |
| Produktiv-Netzwerk-Scanner ohne Freigabe | Immer mit expliziter Betriebsfreigabe |

---

## 7. Bewertungsmodell: Die fünf Dimensionen

| Dimension | Was bewertet wird |
|-----------|-------------------|
| **Technisch** | Angriffsfläche, unsichere Dienste, Scan-Findings |
| **Betrieb** | Produktionskritikalität, Downtime-Toleranz, Redundanz |
| **Kompensation** | Segmentierung, ACLs, Monitoring als Ausgleich |
| **Lifecycle** | Update-Fähigkeit, EOL-Datum, Support-Garantie |
| **Hersteller** | PSIRT, Security-Advisories, Reaktionsfähigkeit |

**Gesamtbewertung:**
- 🟢 Grün: Geeignet
- 🟡 Gelb: Geeignet mit Auflagen
- 🟠 Orange: Nur begrenzt / isoliert einsetzbar
- 🔴 Rot: Nicht freigeben

Ein roter technischer Befund kann durch starke Kompensation zu Gelb werden.
Zwei kritische Findings ohne Kompensation → automatisch Rot.
Lifecycle-Score unter 20 → maximal Gelb.

---

## 8. Angewandte Standards

PiBroadGuard orientiert sich an folgenden internationalen Standards:

**Broadcast-/Realtime-spezifisch:**

| Standard | Relevanz |
|----------|----------|
| **EBU R143** | Sicherheitsanforderungen an Broadcast-Geräte: Accounts, Protokolle, Logging, Härtung (Hardening-Katalog) |
| **EBU R148** | Mindesttests für Netzwerksicherheit an vernetztem Media Equipment |
| **EBU R160 S1** | Leitfaden Basis- und vertiefte Schwachstellenprüfung an Broadcast-Geräten |
| **AMWA BCP-003-01/02** | TLS und Authorization (OAuth2/JWT via IS-10) für NMOS APIs |
| **JT-NM TR-1001-1** | Erwartetes Verhalten von ST-2110-Media-Nodes im Netzwerk |
| **SMPTE ST 2110** | Professional Media over IP (Referenzrahmen) |
| **SMPTE ST 2059** | PTP-basierte Synchronisation im Broadcast (Timing-Risiken) |

**IT-Security / OT-Methodik:**

| Standard | Relevanz |
|----------|----------|
| **IEC 62443-3-2** | Risk Assessment Methodik für OT/ICS-Systeme |
| **IEC 62443-4-2** | Component Security Requirements (Gerätebewertung) |
| **IEC 62443-4-1** | Product Lifecycle Security (Vendor-Bewertung) |
| **NIST SP 800-82r3** | Guide to OT Security |
| **NIST SP 800-115** | Technical Guide to Security Testing (Scan-Methodik) |
| **NIST SP 800-30r1** | Risk Assessment Methodology |
| **NIST CSF 2.0** | Cybersecurity Framework (GOVERN/IDENTIFY/PROTECT/DETECT) |

Diese Standards werden im generierten Report referenziert, um die Bewertung
zu legitimieren und für externe Stellen nachvollziehbar zu machen.

**Wichtiger Hinweis:** EBU, AMWA und JT-NM liefern Anforderungen, Testprofile und
Verhaltensregeln für IP-Media-Systeme – aber **keine zentrale Vulnerability-API** für
Broadcast-Geräte. Broadcast-spezifische Prüfregeln müssen deshalb als eigenes
Regelwerk modelliert werden (nicht als fertiger Feed konsumierbar).

---

## 9. Zweiphasiger Betrieb

PiBroadGuard ist für zwei Betriebsmodi konzipiert, die oft kombiniert werden:

**Phase 1 – Scan-System (typisch: Raspberry Pi, offline)**
Liegt im Broadcast-Netz ohne Internetzugang. Führt Scans durch,
wendet Regelwerk an, exportiert Scan-Pakete auf USB.

**Phase 2 – Report-System (typisch: Workstation, online)**
Hat Internetzugang für CVE/KEV-Lookups. Importiert Scan-Pakete,
reichert mit aktuellen Schwachstellendaten an, generiert finale Reports.

Beide Systeme laufen mit derselben Software. Der Betriebsmodus wird
automatisch erkannt oder manuell gesetzt.

---

## 10. Zielgeräte (Scope)

Primär bewertet PiBroadGuard:
- Broadcast-Encoder und Decoder
- Audio- und Video-Matrixsysteme
- Intercom-Systeme
- Studiogeräte mit Netzwerkmanagement
- KVM- und Steuerungsgeräte
- Monitoring- und Multiviewer-Systeme
- Produktionsnahe Appliances
- IP-basierte Audio-/Video-Geräte (ST 2110, AES67)
- Management-Interfaces von Studio- und Regiekomponenten

Später optional:
- Virtuelle Broadcast-Systeme
- Cloud-basierte Broadcast-Komponenten
- Standard-IT-Geräte im Broadcast-Umfeld

---

---

## 11. Integrationen

| Integration | Zweck | Status |
|-------------|-------|--------|
| **phpIPAM** | Geräte-Import aus bestehender IP-Adressverwaltung | ✅ implementiert |
| **NIST NVD API v2** | CVE-Details, CVSS-Scores, Lösungshinweise | ✅ implementiert |
| **CISA KEV Feed** | Aktiv ausgenutzte Schwachstellen (lokaler Cache, tägl. Sync) | ✅ implementiert |
| **CISA ICS Advisories** | OT/ICS-Advisories für Broadcast-ähnliche Geräte (RSS-Cache) | ✅ implementiert |
| **NVD CPE API** | Präzisere Produkt-zu-CVE-Zuordnung via CPE-Namen | ✅ implementiert |
| **FIRST EPSS API** | Exploit-Wahrscheinlichkeit pro CVE (0–100%, kein API-Key) | ✅ implementiert |
| **CSAF 2.0** | Maschinenlesbare Herstelleradvisories (URL-Fetch oder Datei-Upload) | ✅ implementiert |
| **AMWA NMOS IS-04/10** | Passiver TLS/Auth-Check auf NMOS-fähigen Geräten | ✅ implementiert |
| **Greenbone / Tenable** | Externe Vulnerability-Scanner-Konsolidierung | 🔶 geplant (Prio 3) |

Alle Integrationen sind optional und graceful degradiert: Wenn eine externe Quelle
nicht erreichbar ist, arbeitet PiBroadGuard mit lokalem Cache oder ohne die
betreffende Information. Der Status aller konfigurierten API-Keys und Rate-Limits
ist unter **Settings → External API Keys** einsehbar.

---

*CONCEPT.md – PiBroadGuard v1.12 | März 2026 | Markus Gerber · markus.gerber@npn.ch*
