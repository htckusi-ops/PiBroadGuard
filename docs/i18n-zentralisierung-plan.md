# i18n- und UI-Zentralisierung (Analyse + verfeinertes Konzept)

## Beobachtungen
- Sprachwahl war bislang inkonsistent: auf einigen Seiten nur EN/DE, auf anderen bereits EN/DE/FR/IT.
- Footer-Metadaten (Author/Standards/Version) waren als Übersetzungskeys modelliert, obwohl sie keine sprachabhängigen Inhalte sind.
- Viele UI-Texte sind noch hardcoded in HTML (insbesondere Seitentitel, Tabellenüberschriften, Action-Labels).

## Verfeinertes Zielbild
1. **Sprachdaten pro Sprache getrennt** (`app/i18n/<lang>.json`) bleibt bestehen.
2. **Nicht-sprachliche Metadaten zentral verwalten** (Version, Author, Standards) in Konfiguration + API.
3. **Einheitliche Sprachwahl in allen Views** (EN/DE/FR/IT sofort verfügbar).
4. **Schrittweise Entkopplung harter Texte** in i18n-Keys mit klarer Priorisierung:
   - P1: Navigation, Buttons, Statusmeldungen, Seitentitel.
   - P2: Form-Hilfetexte, Tooltips.
   - P3: Long-tail Texte/seltene States.

## Bereits umgesetzt in diesem Schritt
- Footer-Metadaten jetzt zentral via `/api/v1/system/ui-meta` (statt Übersetzungsdateien).
- Frontend lädt Metadaten zentral über `frontend/app-meta.js` und rendert Footer-Werte über `data-pibg-meta`.
- Sprachwahl EN/DE/FR/IT in allen Hauptseiten vereinheitlicht.
- Erste FR/IT-Übersetzungen für zentrale Navigations-/Button-/Status-Keys ergänzt.

## Nächste technische Schritte
1. **Gemeinsame Header/Footer-Komponente** (oder serverseitiges Include), um Redundanz in HTML-Seiten zu reduzieren.
2. **Automatischer Missing-Key-Report** für jede Sprache im CI.
3. **Fallback-Policy dokumentieren** (Language -> EN -> Fallback-String).
4. **Glossar für Fachbegriffe** (Assessment, Finding, Scan Profile) pro Sprache pflegen.
