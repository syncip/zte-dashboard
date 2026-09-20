# ZTE G5TS Dashboard

Zeichnet Signalqualität (RSRP, RSRQ, SINR, RSSI, Band, Zelle, Trägeraggregation), Datenverbrauch, Latenz und Ausfälle
des ZTE G5TS / MC8830 (Aldi Talk) in SQLite auf und zeigt alles in einem Dashboard.
Nur Python-Standardbibliothek, keine Abhängigkeiten.

Seiten: **Dashboard** · **Auswertung** (nach Tageszeit) · **Setup** (Router-Standort finden) · **Einstellungen**.

## Start

Das Ganze muss auf einem Gerät laufen, das den Router erreicht (Windows-PC, Raspberry Pi, NAS, Mini-PC, Docker-Host im Heimnetz).

    cp .env.example .env      # optional: ZTE_PASSWORD eintragen (geht auch später in den Einstellungen)
    docker compose up -d --build
    # -> http://<ip-des-geräts>:8080

Ohne Docker:

    ZTE_PASSWORD='…' python3 zte_dash.py

Windows (PowerShell):

    $env:ZTE_PASSWORD="dein-passwort"
    python zte_dash.py          # -> http://localhost:8080

Das Router-Passwort kann auch komplett in der Oberfläche unter **Einstellungen → Router-Verbindung** eingetragen werden
(danach ist die Umgebungsvariable nicht mehr nötig). Mit dem Knopf „Verbindung testen“ wird Login, Signal und Datenverbrauch geprüft.

**Wichtig beim Aktualisieren:** immer den ganzen Ordner `static` (enthält jetzt auch `login.html`) **und** `zte_dash.py` ersetzen. Die Datenbank (`data/`) bleibt unverändert.

## Docker-Image über GitHub bauen (Docker Hub)

Das Repo enthält `.github/workflows/docker.yml`: bei jedem Push auf `main` (und bei Tags wie `v1.0.0`) wird ein Multi-Arch-Image
(amd64 + arm64, also auch Raspberry Pi) gebaut und nach Docker Hub hochgeladen.

1. Repository auf GitHub anlegen und den Inhalt dieses Ordners hochladen (`.env` und `data/` sind per `.gitignore` ausgeschlossen).
2. In Docker Hub unter *Account Settings → Personal access tokens* ein Token mit Schreibrechten erzeugen.
3. In GitHub unter *Settings → Secrets and variables → Actions* zwei Secrets anlegen: `DOCKERHUB_USERNAME` und `DOCKERHUB_TOKEN`.
4. Push auslösen (oder *Actions → Docker Image → Run workflow*). Das Image heißt `<DOCKERHUB_USERNAME>/zte-dashboard`.
5. Starten: `docker run -d --name zte-dash -p 8080:8080 -v $(pwd)/data:/data <user>/zte-dashboard:latest`
   (das Volume `/data` enthält die Datenbank – nicht weglassen, sonst sind die Daten beim Neuanlegen des Containers weg).

Hinweise: Der Container braucht nur Netzzugriff auf den Router (Standard `http://192.168.168.1`, per `-e ZTE_HOST=…` oder in den Einstellungen änderbar).
Den Port `8080` nicht ungeschützt ins Internet freigeben – vorher Passwortschutz aktivieren und HTTPS-Proxy davorsetzen.

## Einstellungen (alles im Dashboard)

Alle Werte lassen sich ohne Neustart ändern und gelten sofort:

- Router-Adresse und -Passwort, Abfrageintervall Signal, Intervall Datenverbrauch, Oberflächen-Aktualisierung, Rohdaten-Tage
- Tarifgrenze (0 = unbegrenzt) und Abrechnungstag
- Ping-Ziele (Host, ICMP/TCP, Port), Intervall, Timeout
- Watchdog (Schwellen, Schutzzeiten, Testmodus)
- Dashboard-Passwortschutz
- Manueller Verbindungs-Neustart

Vorrang: **Einstellungen im Dashboard > Umgebungsvariablen > Standardwerte.** Die Umgebungsvariablen dienen also nur als Startwerte.
Nur `ZTE_BIND` / `ZTE_PORT` (Adresse/Port des Dashboards) werden weiterhin ausschließlich per Umgebungsvariable oder Kommandozeile gesetzt.

Das Router-Passwort wird **unverschlüsselt in der lokalen Datenbank** (`data/zte.db`) abgelegt – die Datei also nicht weitergeben.

## Passwortschutz

Unter **Einstellungen → Sicherheit** aktivierbar (optional, standardmäßig aus). Ohne Anmeldung sind Dashboard und API gesperrt
(Seiten leiten auf `/login` um, die API antwortet 401).

- Passwort wird nur als PBKDF2-Hash (SHA-256, 200 000 Runden) gespeichert; Sitzung per signiertem Cookie (HttpOnly, SameSite=Strict), Laufzeit einstellbar.
- Passwortwechsel meldet alle Geräte ab. Fehlversuche werden je IP gebremst (ab 5 Fehlern 30 s Sperre, verdoppelt sich bis 15 min).
- Schreibende Aufrufe sind zusätzlich gegen CSRF geschützt.
- Startwert per Umgebungsvariable: `ZTE_DASH_PASSWORD` (wirkt nur, solange noch kein Schutz eingerichtet ist).
- **Passwort vergessen:** `python zte_dash.py --reset-auth` schaltet den Schutz wieder aus (Daten bleiben erhalten).
- Über normales HTTP im LAN wird das Passwort unverschlüsselt übertragen. Für Zugriff aus dem Internet einen Reverse-Proxy mit HTTPS
  (Caddy, nginx, Traefik) davorsetzen – dann setzt das Dashboard das Cookie automatisch als `Secure` (Header `X-Forwarded-Proto: https`).
  Beim Start warnt das Skript, wenn es ohne Passwort auf einer nicht-lokalen Adresse lauscht.

## Diagramme zoomen

- Im Diagramm mit der Maus einen Bereich aufziehen (Touch: wischen) → hineinzoomen.
- Über der Diagrammleiste: ◀ ▶ verschieben, Hinein / Heraus, Zurück (einen Zoom-Schritt), „Zoom aufheben“. Doppelklick setzt zurück.
- Klick auf einen Tag im Verbrauchs-Balkendiagramm zoomt auf diesen Tag.
- Bei langen Zeiträumen oder Bereichen außerhalb der Rohdaten-Frist werden automatisch die dauerhaften Stundenwerte benutzt.

## Ping-Statistik

Ziele stellst du unter Einstellungen ein. Jede Messung wird gespeichert. Das Latenz-Diagramm zeigt den Mittelwert je Ziel,
darunter eine Tabelle mit Aktuell / Ø / Min / Max / Jitter / Verlust. **Angezeigt werden nur Ziele, die aktuell in den Einstellungen stehen** –
alte Messwerte entfernter Ziele bleiben in der Datenbank, erscheinen aber nicht mehr (kommt das Ziel zurück, sind sie wieder da).
Der Ping läuft auf dem Rechner des Dashboards, gemessen wird also der ganze Weg Rechner → Router → Mobilfunk → Internet.
Fehlt das `ping`-Programm (oder die Berechtigung), fällt der Test automatisch auf TCP-Verbindungen (Port 443) zurück.

## Watchdog (standardmäßig AUS)

Fällt die Erreichbarkeit der Watchdog-Ziele aus, wird die Mobilfunkverbindung neu aufgebaut. Ausfälle erscheinen als
rot hinterlegte Bänder, Neustarts als Raute in allen Zeitdiagrammen und in der Ereignisliste.

- Auslöser: mehr als *X* aufeinanderfolgende fehlgeschlagene Ping-Runden **und** mehr als *Y* Sekunden seit dem ersten Fehler.
- Schutz: Wartezeit nach dem Neustart, Abkühlzeit zwischen Neustarts, Höchstzahl pro Stunde.
- Testmodus („dry run“): protokolliert nur, was passiert wäre.
- Neustart-Methode: der Netzmodus des Routers wird kurz umgeschaltet (z. B. 4G+5G → nur LTE → 4G+5G).
  Der ursprüngliche Modus wird gemerkt und beim nächsten Start wiederhergestellt, falls das Skript dazwischen beendet wird.
- **Vor dem ersten Einsatz** einmal `python zte_dash.py --test-reconnect` ausführen (trennt die Verbindung ca. 10–60 s).
  Diese Methode ist mit einem echten G5TS noch nicht geprüft.

## Auswertung nach Tageszeit

Aus den dauerhaften Stundenwerten: Verlauf je Stunde (0–23 Uhr) und Heatmap Wochentag × Stunde für Signal (RSRP, SINR, RSRQ),
Durchsatz/Verbrauch, Latenz, Paketverlust und Ausfälle, dazu beste/schlechteste Stunde. Zeigt z. B., ob abends die Zelle überlastet ist.

## Setup – besten Router-Standort finden

Die Seite liest das Signal hochfrequent (0,5–5 s wählbar; die Signalwerte kommen ohne Router-Login) und bewertet es in Worten:
**Hervorragend · Sehr gut · Gut · Mittel · Schwach · Sehr schwach**.

Bewertung (Punkte 0–100): SINR 45 %, RSRP 40 %, RSRQ 15 % (jeweils interpoliert); ab 85 Hervorragend, ab 70 Sehr gut, ab 55 Gut, ab 40 Mittel, ab 20 Schwach.
Zusätzlich wird die Stabilität (sehr stabil … unruhig) aus der Schwankung der letzten Werte angezeigt.

Vorgehen:

1. Setup-Seite auf dem Handy/Tablet öffnen (Dashboard-Rechner muss im selben Netz erreichbar sein), Bildschirm bleibt an (Wake Lock).
2. „Ton“ einschalten: Die Tonhöhe folgt der Bewertung, so kann man den Router bewegen, ohne auf den Bildschirm zu schauen.
3. Am Standort „Messung“ starten (15 / 30 / 60 / 120 s) und benennen (z. B. „Fenster Süd“). Die Standorte werden mit Mittelwert, Streuung und Rang verglichen
   (Rang = Mittelwert − ½ × Streuung, stabile Plätze gewinnen also gegenüber schwankenden).
4. Den Standort mit dem besten Rang wählen. Messungen bleiben gespeichert und lassen sich löschen.

Hinweis: Nach dem Umstellen des Routers braucht das Modem ein paar Sekunden, bis Band/Zelle stabil sind – Messung erst dann starten.

## Prognose Periodenende

Grundlage ist der Monatszähler des Routers. Schätzung = bisher verbraucht (ohne heute) + max(heute, Tagesschnitt) + Tagesschnitt × verbleibende Tage.
Tagesschnitt = Mittel der letzten bis zu 7 vollständigen Tage. Angezeigt werden Spanne (25./75. Perzentil), Güte (gut/mittel/grob)
und zum Vergleich die lineare Hochrechnung wie bei vnStat.

## Datenhaltung – es wird nichts gelöscht

Rohwerte (Signal, Durchsatz, Pings) werden `raw_days` Tage (Standard 30) gehalten; vorher werden sie zu **Stundenwerten** verdichtet, die dauerhaft bleiben.
Tagesverbrauch, Ereignisse, Ausfälle, Neustarts und Setup-Messungen werden dauerhaft gespeichert. Der Router-Zähler startet am 1. neu, die Historie bleibt.
Export: `/api/export.csv?range=30d&kind=signal|ping` (auch mit `from`/`to`; Links im Dashboard).

## Hinweise

- **Signalwerte** kommen ohne Login vom Router. **Datenverbrauch** und **Neustart** brauchen das Admin-Passwort.
- Der Router erlaubt meist nur eine Admin-Sitzung: Loggst du dich parallel in der Router-Oberfläche ein,
  kann das Dashboard kurz ausgeloggt werden und loggt sich beim nächsten Abruf automatisch neu ein.
- Nach 2 abgelehnten Router-Logins pausiert das Skript 30 Minuten (der Router sperrt nach 5 Fehlversuchen). Beim Ändern von Adresse/Passwort wird diese Pause zurückgesetzt.
- Docker: Das Image enthält `ping`.

## Diagnose

    python3 zte_dash.py --probe

Loggt sich ein und listet, was der Router liefert (Antwort von `get_wwandst`, verfügbare ubus-Objekte).
Wenn der Datenverbrauch leer bleibt: Ausgabe von `--probe` schicken, dann lässt sich der Parser anpassen.

## Testen ohne Router

    python3 dev/mock_router.py --seed data/demo.db --days 60     # 60 Tage Demo-Daten (inkl. Ausfälle)
    python3 dev/mock_router.py --port 9999 &                     # Fake-Router (Passwort: demo)
    ZTE_HOST=http://127.0.0.1:9999 ZTE_PASSWORD=demo ZTE_DB=data/demo.db python3 zte_dash.py
