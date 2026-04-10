# UI/UX-Verbesserungsvorschläge für PiBroadGuard

## Kurzfazit
Die Oberfläche ist bereits funktional und relativ konsistent (Tailwind, gleiche Header-Struktur, Karten + Tabellen). Für einen wirklich einheitlichen Look-and-Feel und bessere Bedienbarkeit fehlen vor allem: ein zentrales Design-System, ein global sichtbarer Task-Status und klarere Rückmeldungen während laufender Aktionen.

## Beobachtungen (Ist-Zustand)
- Gute Basis mit wiederkehrendem Header/Navigation und ähnlichen Tabellen-/Kartenmustern.
- Task-Status ist teilweise vorhanden (z. B. Scan-Queue im Dashboard, Running/Waiting, Queue-Position), aber nicht global und nicht immer im gleichen Interaktionsmuster.
- Viele Labels/Microcopy sind gemischt (DE/EN), was den konsistenten Eindruck reduziert.

## Priorisierte Maßnahmen

### P1 – Globaler Task-Status (höchster Impact)
1. **Globales „Task-Center“ in der Topbar**
   - Immer sichtbar auf allen Seiten.
   - Zeigt live: laufende Scans, Warteschlange, letzte Fehler, zuletzt abgeschlossen.
   - Ampel-/Badge-System: `Running`, `Queued`, `Succeeded`, `Failed`.
2. **Persistente Statusleiste bei lang laufenden Aktionen**
   - Bei Start eines Scans direkt ein „läuft“-Zustand mit Startzeit/Device/Profile.
   - Bei Queue-Status zusätzlich Position + geschätzte Wartezeit.
3. **Einheitliche Status-Texte und Farben**
   - Status immer als Badge + optional Icon.
   - Kein freier Text ohne visuelle Codierung.

### P1 – Einheitliches Design-System
1. **Design Tokens definieren**
   - Farben, Abstände, Radius, Schatten, Typografie, Fokus-Stile.
   - Einmal definieren, überall nutzen.
2. **Komponenten-Standards**
   - Primär-/Sekundär-Button, Danger-Button, Badge, Alert, Empty-State, Loading-State.
   - Gleiches Hover/Disabled/Focus-Verhalten auf allen Seiten.
3. **Konsistente Seitenstruktur**
   - Standard: Titelbereich, Kontext-Infos, Aktionen, Content.
   - Gleiche Reihenfolge für wiederkehrende Elemente.


### P1 – Übersetzungen getrennt verwalten (für externe Übersetzer)
1. **Sprache pro Datei**
   - Jede Sprache in eigener JSON-Datei (`app/i18n/de.json`, `app/i18n/en.json`, `app/i18n/fr.json`, `app/i18n/it.json`).
   - Übersetzer können direkt pro Sprache arbeiten, ohne UI-Code anzufassen.
2. **Neue Sprachen hinzufügen: Französisch + Italienisch**
   - FR und IT als offizielle UI-Sprachen im Backend freischalten und im Sprachmenü anzeigen.
3. **Fallback-Strategie dokumentieren**
   - Fehlende Keys fallen auf EN (oder den Fallback-Text) zurück, damit die Oberfläche funktionsfähig bleibt.

### P2 – Bessere Bedienbarkeit und Rückmeldung
1. **Asynchrone Aktionen mit klaren Zustandswechseln**
   - `Idle → Running → Success/Failure` immer gleich visualisieren.
   - Buttons während Requests deaktivieren + Inline-Spinner.
2. **Verbesserte Empty/Loading/Error States**
   - Nicht nur „Loading...“, sondern skeletons oder klare Hinweise.
   - Fehler mit konkreter Aktion („Erneut versuchen“, „Zu Logs“).
3. **Progressive Disclosure bei komplexen Formularen**
   - Erweiterte Optionen einklappen.
   - Hilfetexte nur dort, wo wirklich nötig.

### P2 – Sprache, Lesbarkeit, Barrierefreiheit
1. **Einheitliche Sprache je Session (DE oder EN)**
   - Keine gemischten Labels in derselben Sicht.
2. **Kontraste und Fokus-Indikatoren härten**
   - Keyboard-Navigation sichtbar machen.
3. **Status nicht nur über Farbe vermitteln**
   - Immer Icon + Text ergänzen.

## Konkrete Umsetzung in 3 Iterationen

### Iteration 1 (1–2 Tage)
- Globales Task-Center in Header (MVP).
- Einheitliche Status-Badges + zentrale Mapping-Funktion.
- Standardisierte Toasts für Erfolg/Fehler.

### Iteration 2 (2–3 Tage)
- Design Tokens + Basis-Komponenten (Button, Badge, Alert, Panel, Table-Header).
- Loading/Empty/Error-States vereinheitlichen.
- Sprachkonsistenz in allen Hauptseiten.

### Iteration 3 (2–4 Tage)
- Form-Wizard für Assessment/Scan.
- ETA/Detailstatus für Queue.
- Accessibility-Pass (Fokus, ARIA, Kontraste).

## Messbare Akzeptanzkriterien
- Nutzer sieht auf **jeder Seite innerhalb von 2 Sekunden**, ob ein Task läuft.
- Jeder Task hat einen eindeutig nachvollziehbaren Statusverlauf.
- Primäre Interaktionen (Scan starten, Schedule erstellen, speichern) zeigen immer sofortiges Feedback.
- Keine gemischte UI-Sprache in derselben Ansicht.

## Quick Wins (sehr schnell umsetzbar)
- Header um globales Running-Widget erweitern.
- Einheitliche Badge-Texte: `Running`, `Queued`, `Complete`, `Failed`.
- „Loading...“-Texte durch standardisierte Skeleton-/Status-Komponente ersetzen.
- Für `Run now` und `Start scan` sofortigen Pending-Status + Disable-Zustand anzeigen.
