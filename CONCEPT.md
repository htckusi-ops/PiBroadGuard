# CONCEPT.md – PiBroadGuard
## Fachliches Konzept und Hintergrund

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

```
1. Neues Broadcast-Gerät soll beschafft oder in Betrieb genommen werden.
2. Broadcast Engineer erfasst das Gerät in PiBroadGuard.
3. Scan-Freigabe wird vom Betriebsverantwortlichen eingeholt und dokumentiert.
4. Nmap-Scan wird gegen die Test-IP durchgeführt (Passive-Profil empfohlen).
5. Regelwerk erzeugt automatische Findings.
6. Broadcast Engineer ergänzt manuelle Informationen:
   - Gibt es Default-Credentials?
   - Ist Telnet deaktivierbar?
   - Gibt es Security-Updates?
   - Ist das Gerät produktionskritisch?
7. IT Security Reviewer prüft, ergänzt Kompensationsmassnahmen, setzt Scores.
8. Report wird generiert.
9. Entscheid: Freigegeben / Freigegeben mit Auflagen / Zurückgestellt / Abgelehnt.
10. Re-Assessment-Termin wird festgelegt.
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
Scans und erste Klassifikationen werden automatisiert. Kontextbewertung,
Hersteller-Informationen und Freigabeentscheide bleiben beim Menschen.
Das Tool unterstützt – es ersetzt kein Fachwissen.

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

*CONCEPT.md – PiBroadGuard | März 2026*
