#!/usr/bin/env python3
"""
ZTE G5TS (MC8830) Dashboard - Collector, Ping-Monitor/Watchdog und Webserver
============================================================================
Fragt den Router regelmäßig über seine ubus-JSON-RPC-Schnittstelle ab, speichert
Signalwerte, Datenverbrauch und Ping-Statistiken in SQLite, überwacht die Verbindung
(optional mit automatischem Neuverbinden) und liefert ein Dashboard aus.

Nur Python-Standardbibliothek (>= 3.9), keine Abhängigkeiten.

Start:            python3 zte_dash.py
Diagnose:         python3 zte_dash.py --probe
Einzelabruf:      python3 zte_dash.py --once
Reconnect testen: python3 zte_dash.py --test-reconnect
"""
import argparse
import calendar
import csv
import hashlib
import hmac
import io
import json
import logging
import math
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

log = logging.getLogger("zte_dash")
BASE_DIR = Path(__file__).resolve().parent
ANON_SID = "0" * 32
HOUR = 3600


# --------------------------------------------------------------------------- #
# Konfiguration (Umgebungsvariablen) - Ping/Watchdog werden im Dashboard eingestellt
# --------------------------------------------------------------------------- #
def _env(name, default=""):
    return os.environ.get("ZTE_" + name, default)


class Config:
    """Startwerte aus Umgebungsvariablen. Was im Dashboard unter "Einstellungen" gespeichert wird, hat Vorrang
    (siehe apply_runtime) und gilt sofort, ohne Neustart."""

    def __init__(self):
        self.host = _env("HOST", "http://192.168.168.1").rstrip("/")
        self.password = _env("PASSWORD", "")          # nötig für Datenverbrauch und Reconnect
        self.session = _env("SESSION", "")            # optional: manuelle ubus-Session-ID
        self.login_mode = _env("LOGIN_MODE", "salted")  # salted | sha
        self.poll = max(2, int(_env("POLL_SECONDS", "10")))
        self.usage_s = max(10, int(_env("USAGE_SECONDS", "30")))
        self.ui_refresh = 5
        self.db = _env("DB", str(BASE_DIR / "data" / "zte.db"))
        self.bind = _env("BIND", "0.0.0.0")
        self.port = int(_env("PORT", "8080"))
        # Rohdaten (Sekundenauflösung) werden so lange aufgehoben; danach bleiben die
        # Stundenwerte dauerhaft erhalten. Es wird nichts endgültig gelöscht.
        self.raw_days = int(_env("RAW_DAYS", _env("RETENTION_DAYS", "30")))
        self.limit_gb = float(_env("MONTH_LIMIT_GB", "0") or 0)   # 0 = unlimited
        self.billing_day = min(28, max(1, int(_env("BILLING_DAY", "1"))))
        self.static_dir = Path(_env("STATIC_DIR", str(BASE_DIR / "static")))
        self.dash_password = _env("DASH_PASSWORD", "")  # optional: schaltet beim ersten Start den Dashboard-Login ein
        self.defaults = {k: getattr(self, k) for k in
                         ("host", "password", "poll", "usage_s", "ui_refresh", "raw_days", "limit_gb", "billing_day")}

    @property
    def usage_every(self):
        return max(self.poll, self.usage_s)


# --------------------------------------------------------------------------- #
# Datenbank
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
  ts INTEGER PRIMARY KEY,
  net_type TEXT, provider TEXT, bars INTEGER,
  band TEXT, pci INTEGER, cell_id TEXT, arfcn INTEGER, bw INTEGER,
  nr_rsrp REAL, nr_rsrq REAL, nr_snr REAL, nr_rssi REAL,
  lte_rsrp REAL, lte_rsrq REAL, lte_snr REAL, lte_rssi REAL,
  ca TEXT
);
CREATE TABLE IF NOT EXISTS traffic (
  ts INTEGER PRIMARY KEY,
  rx_total INTEGER, tx_total INTEGER, rx_month INTEGER, tx_month INTEGER,
  rx_speed REAL, tx_speed REAL, rx_delta INTEGER, tx_delta INTEGER
);
CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, kind TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS pings (ts INTEGER NOT NULL, target TEXT NOT NULL, rtt REAL, PRIMARY KEY (ts, target));
CREATE TABLE IF NOT EXISTS outages (id INTEGER PRIMARY KEY AUTOINCREMENT, start INTEGER NOT NULL, end INTEGER, reconnects INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS idx_outages_start ON outages(start);
CREATE TABLE IF NOT EXISTS spots (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, name TEXT NOT NULL, note TEXT, duration INTEGER, n INTEGER,
  net TEXT, band TEXT, pci INTEGER, bw INTEGER, rsrp REAL, rsrq REAL, snr REAL, rssi REAL, rsrp_std REAL, snr_std REAL,
  score REAL, rank_score REAL, level TEXT, limiting TEXT, stability TEXT, series TEXT
);
-- SMS: lokales Archiv (Eingang und Gesendet). Gelöschte Einträge bleiben als "deleted" markiert, damit sie
-- beim nächsten Abgleich mit dem Router nicht wieder auftauchen.
CREATE TABLE IF NOT EXISTS sms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  box TEXT NOT NULL,                 -- 'in' | 'out'
  number TEXT NOT NULL, nkey TEXT NOT NULL,
  text TEXT NOT NULL,
  ts INTEGER NOT NULL,               -- Zeitpunkt der Nachricht
  created INTEGER NOT NULL,          -- Zeitpunkt der Aufnahme ins Archiv
  read INTEGER NOT NULL DEFAULT 0,
  status TEXT, detail TEXT,          -- nur 'out': sending | sent | failed | unconfirmed
  router_id TEXT, source TEXT,
  deleted INTEGER NOT NULL DEFAULT 0,
  fp TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_sms_box_ts ON sms(box, ts);
CREATE INDEX IF NOT EXISTS idx_sms_nkey ON sms(nkey);
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, hash TEXT NOT NULL UNIQUE, prefix TEXT NOT NULL,
  can_read INTEGER NOT NULL DEFAULT 1, can_send INTEGER NOT NULL DEFAULT 0, can_delete INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, last_used INTEGER, uses INTEGER NOT NULL DEFAULT 0
);
-- Stundenaggregate: bleiben dauerhaft erhalten
CREATE TABLE IF NOT EXISTS samples_h (
  ts INTEGER PRIMARY KEY, n INTEGER,
  nr_rsrp REAL, nr_rsrp_min REAL, nr_rsrp_max REAL, nr_rsrq REAL, nr_snr REAL, nr_rssi REAL,
  lte_rsrp REAL, lte_rsrp_min REAL, lte_rsrp_max REAL, lte_rsrq REAL, lte_snr REAL, lte_rssi REAL,
  bars REAL, q0 INTEGER, q1 INTEGER, q2 INTEGER, q3 INTEGER
);
CREATE TABLE IF NOT EXISTS traffic_h (
  ts INTEGER PRIMARY KEY, rx_speed REAL, tx_speed REAL, rx_max REAL, tx_max REAL, rx_delta INTEGER, tx_delta INTEGER
);
CREATE TABLE IF NOT EXISTS pings_h (
  ts INTEGER NOT NULL, target TEXT NOT NULL, n INTEGER, lost INTEGER,
  rtt_n INTEGER, rtt_sum REAL, rtt_sq REAL, rtt_min REAL, rtt_max REAL, PRIMARY KEY (ts, target)
);
"""


def connect(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path):
    conn = connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def kv_get(conn, key, default=None):
    row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return json.loads(row["v"]) if row else default


def kv_set(conn, key, value):
    conn.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                 (key, json.dumps(value)))


def kv_del(conn, key):
    conn.execute("DELETE FROM kv WHERE k=?", (key,))


def add_event(conn, ts, kind, detail):
    conn.execute("INSERT INTO events(ts,kind,detail) VALUES(?,?,?)", (ts, kind, detail))


def rollup(conn, since_ts):
    """Rohdaten -> Stundenwerte (ab der Stunde, in die since_ts fällt). Idempotent."""
    since = since_ts // HOUR * HOUR
    conn.execute(f"""
        INSERT OR REPLACE INTO samples_h
        SELECT (ts/{HOUR})*{HOUR}, COUNT(*),
               AVG(nr_rsrp), MIN(nr_rsrp), MAX(nr_rsrp), AVG(nr_rsrq), AVG(nr_snr), AVG(nr_rssi),
               AVG(lte_rsrp), MIN(lte_rsrp), MAX(lte_rsrp), AVG(lte_rsrq), AVG(lte_snr), AVG(lte_rssi),
               AVG(bars),
               SUM(CASE WHEN COALESCE(nr_rsrp,lte_rsrp) >= -90 THEN 1 ELSE 0 END),
               SUM(CASE WHEN COALESCE(nr_rsrp,lte_rsrp) < -90 AND COALESCE(nr_rsrp,lte_rsrp) >= -100 THEN 1 ELSE 0 END),
               SUM(CASE WHEN COALESCE(nr_rsrp,lte_rsrp) < -100 AND COALESCE(nr_rsrp,lte_rsrp) >= -110 THEN 1 ELSE 0 END),
               SUM(CASE WHEN COALESCE(nr_rsrp,lte_rsrp) < -110 THEN 1 ELSE 0 END)
        FROM samples WHERE ts >= ? GROUP BY 1""", (since,))
    conn.execute(f"""
        INSERT OR REPLACE INTO traffic_h
        SELECT (ts/{HOUR})*{HOUR}, AVG(rx_speed), AVG(tx_speed), MAX(rx_speed), MAX(tx_speed),
               COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0)
        FROM traffic WHERE ts >= ? GROUP BY 1""", (since,))
    conn.execute(f"""
        INSERT OR REPLACE INTO pings_h
        SELECT (ts/{HOUR})*{HOUR}, target, COUNT(*), SUM(CASE WHEN rtt IS NULL THEN 1 ELSE 0 END),
               COUNT(rtt), COALESCE(SUM(rtt),0), COALESCE(SUM(rtt*rtt),0), MIN(rtt), MAX(rtt)
        FROM pings WHERE ts >= ? GROUP BY 1, 2""", (since,))


# --------------------------------------------------------------------------- #
# Einstellungen (im Dashboard änderbar, in der DB gespeichert)
# --------------------------------------------------------------------------- #
DEFAULT_SETTINGS = {
    "ping": {
        "enabled": True, "interval_s": 10, "timeout_ms": 2000,
        "targets": [
            {"host": "1.1.1.1", "method": "icmp", "port": 443, "watchdog": True},
            {"host": "8.8.8.8", "method": "icmp", "port": 443, "watchdog": True},
            {"host": "google.com", "method": "icmp", "port": 443, "watchdog": False},
            {"host": "cloudflare.com", "method": "icmp", "port": 443, "watchdog": False},
        ],
    },
    "watchdog": {
        "enabled": False,       # bewusst aus, bis der Reconnect einmal getestet wurde
        "dry_run": False,       # nur protokollieren, nicht neu verbinden
        "min_failed_targets": 0,  # 0 = alle Watchdog-Ziele müssen ausfallen
        "fail_rounds": 6,       # Neustart nach so vielen Ping-Runden in Folge ohne Antwort ... (0 = aus)
        "fail_seconds": 60,     # ... oder nach so vielen Sekunden ohne Antwort (0 = aus)
        "outage_rounds": 2,     # ab so vielen Runden gilt es als Ausfall (für die Anzeige)
        "grace_s": 60,          # Wartezeit nach einem Neustart, bevor wieder gezählt wird
        "cooldown_s": 300,      # Mindestabstand zwischen zwei Neustarts
        "max_per_hour": 3,      # Sicherung gegen Endlosschleifen
        "method": "netselect",
    },
    "sms": {
        "enabled": True,            # SMS regelmäßig vom Router abholen (braucht das Router-Passwort)
        "interval_s": 60,           # Abholtakt
        "send_limit_per_hour": 20,  # Sicherung gegen versehentlich viele (kostenpflichtige) SMS
        "delete_on_router": False,  # nach der Übernahme im Router löschen (schafft Platz im Router-Speicher)
        "webhook_url": "",          # optional: bei jeder neuen SMS per HTTP POST melden
    },
}
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,251}[A-Za-z0-9])?$")
WD_LIMITS = {"min_failed_targets": (0, 10), "fail_rounds": (0, 1000), "fail_seconds": (0, 86400),
             "outage_rounds": (1, 100), "grace_s": (10, 900), "cooldown_s": (30, 86400), "max_per_hour": (1, 30)}


def _int(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(float(v))))
    except (TypeError, ValueError):
        return default


def sanitize_settings(raw, strict=False):
    """Prüft/normalisiert Einstellungen. strict=True (Speichern) wirft ValueError, sonst werden Fehler verworfen."""
    raw = raw if isinstance(raw, dict) else {}
    d = json.loads(json.dumps(DEFAULT_SETTINGS))
    rp, rw = raw.get("ping") or {}, raw.get("watchdog") or {}
    p = d["ping"]
    p["enabled"] = bool(rp.get("enabled", p["enabled"]))
    p["interval_s"] = _int(rp.get("interval_s"), 5, 3600, p["interval_s"])
    p["timeout_ms"] = _int(rp.get("timeout_ms"), 200, 10000, p["timeout_ms"])
    if "targets" in rp:
        targets, seen = [], set()
        for t in rp["targets"] if isinstance(rp["targets"], list) else []:
            host = str((t or {}).get("host", "")).strip()
            if not host:
                continue
            if not HOST_RE.match(host):
                if strict:
                    raise ValueError(f"Ungültiger Hostname/IP: {host!r}")
                continue
            method = "tcp" if (t or {}).get("method") == "tcp" else "icmp"
            port = _int((t or {}).get("port"), 1, 65535, 443)
            key = (host.lower(), method, port if method == "tcp" else 0)
            if key in seen:
                continue
            seen.add(key)
            targets.append({"host": host, "method": method, "port": port, "watchdog": bool((t or {}).get("watchdog"))})
        if len(targets) > 10 and strict:
            raise ValueError("Maximal 10 Ziele")
        p["targets"] = targets[:10]
    w = d["watchdog"]
    w["enabled"] = bool(rw.get("enabled", w["enabled"]))
    w["dry_run"] = bool(rw.get("dry_run", w["dry_run"]))
    for k, (lo, hi) in WD_LIMITS.items():
        w[k] = _int(rw.get(k), lo, hi, w[k])
    w["method"] = "netselect"
    if strict and w["enabled"] and not any(t["watchdog"] for t in p["targets"]):
        raise ValueError("Der Watchdog braucht mindestens ein Ziel mit gesetztem Watchdog-Haken")
    if strict and w["enabled"] and not w["fail_rounds"] and not w["fail_seconds"]:
        raise ValueError("Bitte 'Runden' oder 'Sekunden' größer 0 setzen")
    rs, sm = raw.get("sms") or {}, d["sms"]
    sm["enabled"] = bool(rs.get("enabled", sm["enabled"]))
    sm["delete_on_router"] = bool(rs.get("delete_on_router", sm["delete_on_router"]))
    sm["interval_s"] = _int(rs.get("interval_s"), 10, 3600, sm["interval_s"])
    sm["send_limit_per_hour"] = _int(rs.get("send_limit_per_hour"), 1, 500, sm["send_limit_per_hour"])
    hook = str(rs.get("webhook_url") or "").strip()
    if hook and not re.match(r"^https?://[^\s]{3,480}$", hook):
        if strict:
            raise ValueError("Die Webhook-Adresse muss mit http:// oder https:// beginnen")
        hook = ""
    sm["webhook_url"] = hook
    d["general"] = sanitize_general(raw.get("general"), strict)
    return d


HOST_URL_RE = re.compile(r"^https?://[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?(?::\d{1,5})?$")
GENERAL_LIMITS = {"poll_s": (2, 3600), "usage_s": (10, 3600), "raw_days": (7, 3650), "billing_day": (1, 28),
                  "ui_refresh_s": (2, 300)}


def clean_host(value, strict=True):
    h = str(value or "").strip().rstrip("/")
    if not h:
        return None
    if not HOST_URL_RE.match(h):
        if strict:
            raise ValueError("Die Router-Adresse muss so aussehen: http://192.168.168.1")
        return None
    return h


def sanitize_general(raw, strict=False):
    """Allgemeine Einstellungen. Nur gesetzte Schlüssel werden gespeichert, sonst gelten die Startwerte."""
    raw = raw if isinstance(raw, dict) else {}
    out = {}
    host = clean_host(raw.get("host"), strict)
    if host:
        out["host"] = host
    for k, (lo, hi) in GENERAL_LIMITS.items():
        if raw.get(k) not in (None, ""):
            v = _int(raw[k], lo, hi, None)
            if v is None:
                if strict:
                    raise ValueError(f"Ungültiger Wert für {k}")
                continue
            out[k] = v
    if raw.get("limit_gb") not in (None, ""):
        try:
            out["limit_gb"] = round(max(0.0, min(100000.0, float(raw["limit_gb"]))), 1)
        except (TypeError, ValueError):
            if strict:
                raise ValueError("Ungültiges Datenlimit")
    return out


def load_settings(conn):
    return sanitize_settings(kv_get(conn, "settings"))


def load_secrets(conn):
    v = kv_get(conn, "secrets")
    return v if isinstance(v, dict) else {}


def apply_runtime(cfg, settings, secrets, collector=None, monitor=None):
    """Gespeicherte Einstellungen in die laufende Konfiguration übernehmen (ohne Neustart)."""
    g = (settings or {}).get("general") or {}
    d = cfg.defaults
    host = g.get("host") or d["host"]
    pw = (secrets or {}).get("router_password") or d["password"]
    changed = (host, pw) != (cfg.host, cfg.password)
    cfg.host, cfg.password = host, pw
    cfg.poll = g.get("poll_s", d["poll"])
    cfg.usage_s = g.get("usage_s", d["usage_s"])
    cfg.ui_refresh = g.get("ui_refresh_s", d["ui_refresh"])
    cfg.raw_days = g.get("raw_days", d["raw_days"])
    cfg.limit_gb = g.get("limit_gb", d["limit_gb"])
    cfg.billing_day = g.get("billing_day", d["billing_day"])
    if collector:
        if changed:
            collector.router.reconfigure()
            collector.request_usage_now()
        collector.wake.set()
    if monitor:
        monitor.wake.set()
    sms = getattr(collector, "sms", None)
    if sms:
        if changed:
            sms._last = 0.0
        sms.wake.set()
    return changed


def load_runtime(cfg):
    """Beim Start (auch für --probe / --test-reconnect): in der Datenbank gespeicherte Einstellungen anwenden."""
    if not Path(cfg.db).exists():
        return
    try:
        conn = connect(cfg.db)
        try:
            apply_runtime(cfg, load_settings(conn), load_secrets(conn))
        finally:
            conn.close()
    except sqlite3.Error as exc:
        log.warning("Gespeicherte Einstellungen nicht lesbar: %s", exc)


# --------------------------------------------------------------------------- #
# Dashboard-Anmeldung (optional): PBKDF2-Passwort, signiertes Cookie, Bremse gegen Ausprobieren
# --------------------------------------------------------------------------- #
class Auth:
    ITER = 200_000
    COOKIE = "zte_session"

    def __init__(self, db_path):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.fails = {}                       # ip -> [Anzahl, gesperrt bis]
        self.a = {}
        self.reload()

    def _secrets(self):
        conn = connect(self.db_path)
        try:
            return load_secrets(conn)
        finally:
            conn.close()

    def reload(self):
        self.a = (self._secrets().get("auth") or {})

    def _store(self, auth):
        conn = connect(self.db_path)
        try:
            sec = load_secrets(conn)
            sec["auth"] = auth
            kv_set(conn, "secrets", sec)
            conn.commit()
        finally:
            conn.close()
        self.a = auth

    @property
    def enabled(self):
        return bool(self.a.get("enabled") and self.a.get("hash"))

    @property
    def session_days(self):
        return int(self.a.get("session_days") or 30)

    @staticmethod
    def _hash(pw, salt_hex, iters):
        return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), iters).hex()

    def set_password(self, pw, session_days=None):
        if len(pw or "") < 8:
            raise ValueError("Das Passwort muss mindestens 8 Zeichen haben")
        if len(pw) > 200:
            raise ValueError("Das Passwort ist zu lang")
        salt = secrets.token_hex(16)
        days = _int(session_days, 1, 365, self.session_days)
        self._store({"enabled": True, "salt": salt, "iter": self.ITER, "hash": self._hash(pw, salt, self.ITER),
                     "secret": secrets.token_hex(32), "session_days": days})   # neues Geheimnis = alle alten Sitzungen ungültig

    def disable(self):
        self._store({"enabled": False, "session_days": self.session_days})

    def set_session_days(self, days):
        a = dict(self.a)
        a["session_days"] = _int(days, 1, 365, self.session_days)
        self._store(a)

    def verify(self, pw):
        if not self.a.get("hash"):
            return False
        h = self._hash(pw or "", self.a["salt"], int(self.a.get("iter") or self.ITER))
        return hmac.compare_digest(h, self.a["hash"])

    def _sig(self, exp):
        return hmac.new(bytes.fromhex(self.a["secret"]), str(exp).encode(), hashlib.sha256).hexdigest()

    def token(self):
        exp = int(time.time() + self.session_days * 86400)
        return f"{exp}.{self._sig(exp)}"

    def valid(self, token):
        try:
            exp, sig = (token or "").split(".", 1)
            return int(exp) > time.time() and hmac.compare_digest(sig, self._sig(int(exp)))
        except (ValueError, KeyError, TypeError):
            return False

    # Bremse: ab 5 Fehlversuchen je Adresse wächst die Sperrzeit (30 s, 60 s, ... max. 15 min)
    def wait_time(self, ip):
        with self.lock:
            f = self.fails.get(ip)
            return max(0, int((f[1] if f else 0) - time.time() + 0.999))

    def record(self, ip, ok):
        with self.lock:
            if ok:
                self.fails.pop(ip, None)
                return
            n = (self.fails.get(ip) or [0, 0])[0] + 1
            lock_until = time.time() + min(900, 30 * 2 ** (n - 5)) if n >= 5 else 0
            self.fails[ip] = [n, lock_until]
            if len(self.fails) > 500:
                self.fails.clear()


# --------------------------------------------------------------------------- #
# Empfangsbewertung (Setup-Seite): Rohwerte -> Punktzahl 0-100 -> Wort
# --------------------------------------------------------------------------- #
RSRP_PTS = [(-125, 0), (-115, 15), (-105, 35), (-95, 58), (-85, 80), (-75, 100)]
SNR_PTS = [(-10, 0), (-5, 5), (0, 25), (5, 45), (13, 70), (20, 90), (25, 100)]
RSRQ_PTS = [(-22, 0), (-18, 20), (-14, 50), (-10, 78), (-6, 100)]
RATING_WEIGHTS = {"rsrp": 0.40, "snr": 0.45, "rsrq": 0.15}
RATING_LEVELS = [(85, "excellent", "Hervorragend"), (70, "great", "Sehr gut"), (55, "good", "Gut"),
                 (40, "fair", "Mittel"), (20, "poor", "Schwach"), (0, "bad", "Sehr schwach")]
LIMIT_NAMES = {"rsrp": "Signalstärke (RSRP)", "snr": "Signalrauschabstand (SINR)", "rsrq": "Signalqualität (RSRQ)"}


def interp(x, pts):
    if x <= pts[0][0]:
        return float(pts[0][1])
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        if x <= x1:
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return float(pts[-1][1])


def level_for(score):
    for lo, lid, label in RATING_LEVELS:
        if score >= lo:
            return lid, label
    return RATING_LEVELS[-1][1], RATING_LEVELS[-1][2]


def rate(rsrp, snr, rsrq):
    """Gesamtbewertung: RSRP 40 %, SINR 45 %, RSRQ 15 % (SINR bestimmt die erreichbare Datenrate am stärksten).
    Fehlende Werte werden übersprungen. Ohne RSRP gibt es keine Bewertung."""
    if rsrp is None:
        return None
    parts = {"rsrp": interp(rsrp, RSRP_PTS)}
    if snr is not None:
        parts["snr"] = interp(snr, SNR_PTS)
    if rsrq is not None:
        parts["rsrq"] = interp(rsrq, RSRQ_PTS)
    wsum = sum(RATING_WEIGHTS[k] for k in parts)
    score = sum(parts[k] * RATING_WEIGHTS[k] for k in parts) / wsum
    lid, label = level_for(score)
    return {"score": round(score, 1), "level": lid, "label": label,
            "limiting": min(parts, key=parts.get), "parts": {k: round(v) for k, v in parts.items()}}


RATING_SPEC = {"rsrp": RSRP_PTS, "snr": SNR_PTS, "rsrq": RSRQ_PTS, "weights": RATING_WEIGHTS, "limit_names": LIMIT_NAMES,
               "levels": [{"lo": lo, "id": lid, "label": label} for lo, lid, label in reversed(RATING_LEVELS)]}
LEVEL_LABELS = {lid: label for _, lid, label in RATING_LEVELS}


def stability_label(rsrp_std, snr_std):
    w = max(rsrp_std or 0, (snr_std or 0))
    return "sehr stabil" if w < 1.5 else "stabil" if w < 3 else "schwankend" if w < 5 else "unruhig"


def target_label(t):
    return t["host"] if t["method"] == "icmp" else f"{t['host']}:{t['port']}/tcp"


# --------------------------------------------------------------------------- #
# Router-Client (ubus JSON-RPC)
# --------------------------------------------------------------------------- #
class RouterError(Exception):
    pass


class AccessDenied(RouterError):
    pass


class Router:
    # Parameter, die die Router-Weboberfläche selbst für zwrt_data.get_wwandst benutzt
    USAGE_ARGS = [{"source_module": "web", "cid": 1, "type": 4},
                  {"source_module": "web", "cid": 1, "type": 2},
                  {"source_module": "web", "cid": 1}]

    def __init__(self, cfg):
        self.cfg = cfg
        self.sid = cfg.session or None
        self.usage_args = None
        self.login_failures = 0
        self.login_paused_until = 0.0
        self.login_state = "none" if not (cfg.password or cfg.session) else "pending"
        self.login_error = None
        self.lock = threading.RLock()

    @property
    def base(self):
        return self.cfg.host

    @property
    def can_login(self):
        return bool(self.cfg.password or self.cfg.session)

    def reconfigure(self):
        """Host oder Passwort wurden geändert: Sitzung verwerfen, Sperrzähler zurücksetzen."""
        with self.lock:
            self.sid = self.cfg.session or None
            self.usage_args = None
            self.login_failures = 0
            self.login_paused_until = 0.0
            self.login_state = "none" if not (self.cfg.password or self.cfg.session) else "pending"
            self.login_error = None

    # -- Low level ----------------------------------------------------------- #
    def _post(self, payload):
        req = urllib.request.Request(
            f"{self.base}/ubus/?t={int(time.time() * 1000)}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Origin": self.base,
                     "Referer": self.base + "/index.html"})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RouterError(f"Router nicht erreichbar: {exc}") from exc

    def call(self, obj, method, args=None, sid=None):
        payload = [{"jsonrpc": "2.0", "id": 1, "method": "call",
                    "params": [sid or ANON_SID, obj, method, args or {}]}]
        resp = self._post(payload)
        item = resp[0] if isinstance(resp, list) and resp else resp
        if not isinstance(item, dict):
            raise RouterError("Unerwartete Antwort vom Router")
        if "error" in item:
            code = (item["error"] or {}).get("code")
            msg = (item["error"] or {}).get("message", "")
            if code == -32002:
                raise AccessDenied(f"{obj}.{method}: {msg}")
            raise RouterError(f"{obj}.{method}: {msg} ({code})")
        result = item.get("result")
        if not result:
            raise RouterError(f"{obj}.{method}: leere Antwort")
        if result[0] == 6:
            raise AccessDenied(f"{obj}.{method}: permission denied")
        if result[0] != 0:
            raise RouterError(f"{obj}.{method}: ubus-Status {result[0]}")
        return result[1] if len(result) > 1 and isinstance(result[1], dict) else {}

    def call_auth(self, obj, method, args=None):
        """Aufruf mit Login; bei abgelaufener Sitzung genau ein Re-Login."""
        with self.lock:
            if not self.sid:
                self.login()
            try:
                return self.call(obj, method, args, sid=self.sid)
            except AccessDenied:
                self.sid = None if not (self.cfg.session and not self.cfg.password) else self.sid
                self.login()
                return self.call(obj, method, args, sid=self.sid)

    # -- Login --------------------------------------------------------------- #
    def login(self):
        """Ein einzelner Login-Versuch. Nach 2 Fehlschlägen wird 30 min pausiert,
        damit der Router (Sperre nach 5 Fehlversuchen) nicht blockiert wird."""
        with self.lock:
            if self.cfg.session and not self.cfg.password:
                self.sid = self.cfg.session
                self.login_state = "ok"
                return
            if not self.cfg.password:
                raise RouterError("Kein Router-Passwort gesetzt (Einstellungen → Verbindung)")
            now = time.time()
            if now < self.login_paused_until:
                raise RouterError("Login pausiert (zu viele Fehlversuche)")
            info = self.call("zwrt_web", "web_login_info")
            if info.get("login_fail_lock_lefttime"):
                raise RouterError(f"Router sperrt Logins noch {info['login_fail_lock_lefttime']} s")
            salt = str(info.get("zte_web_sault", ""))
            h1 = hashlib.sha256(self.cfg.password.encode()).hexdigest().upper()
            pw = h1 if self.cfg.login_mode == "sha" else hashlib.sha256((h1 + salt).encode()).hexdigest().upper()
            res = self.call("zwrt_web", "web_login", {"password": pw})
            sid = res.get("ubus_rpc_session") or res.get("session") or res.get("sid")
            if not sid:
                self.login_failures += 1
                self.sid = None
                self.login_state = "failed"
                self.login_error = "Login abgelehnt (Passwort falsch?)"
                if self.login_failures >= 2:
                    self.login_paused_until = now + 1800
                    self.login_state = "paused"
                    self.login_error = ("Login 2x abgelehnt - Versuche 30 Minuten pausiert, damit der Router "
                                        "nicht sperrt. Passwort in den Einstellungen prüfen und neu speichern.")
                raise RouterError(self.login_error)
            self.sid = sid
            self.login_failures = 0
            self.login_state = "ok"
            self.login_error = None
            log.info("Router-Login erfolgreich")

    # -- Abfragen ------------------------------------------------------------ #
    def netinfo(self):
        return self.call("zte_nwinfo_api", "nwinfo_get_netinfo")   # geht ohne Login

    def usage(self):
        if not self.sid:
            raise AccessDenied("nicht eingeloggt")
        variants = self.usage_args if self.usage_args is not None else self.USAGE_ARGS
        merged, worked, last = {}, [], None
        for args in variants:
            try:
                data = self.call("zwrt_data", "get_wwandst", args, sid=self.sid)
            except AccessDenied:
                raise
            except RouterError as exc:
                last = exc
                continue
            worked.append(args)
            for k, v in data.items():
                merged.setdefault(k, v)
        if not any("byte" in k for k in merged):
            raise last or RouterError("get_wwandst lieferte keine Byte-Zähler")
        self.usage_args = worked
        return merged

    def set_netselect(self, value):
        return self.call_auth("zte_nwinfo_api", "nwinfo_set_netselect", {"net_select": value})

    def list_methods(self, obj):
        """ubus 'list': Methoden eines Objekts (nur für die Diagnose)."""
        resp = self._post([{"jsonrpc": "2.0", "id": 1, "method": "list", "params": [self.sid or ANON_SID, obj]}])
        item = resp[0] if isinstance(resp, list) and resp else resp
        return (item or {}).get("result") or []

    # -- SMS (ubus-Objekt zwrt_wms) --------------------------------------------------- #
    def sms_list(self):
        d = self.call_auth("zwrt_wms", "zte_libwms_get_sms_data",
                           {"page": 0, "data_per_page": 500, "mem_store": 1, "tags": 10, "order_by": "order by id desc"})
        for k in ("messages", "messages_data", "sms_data"):
            if isinstance(d.get(k), list):
                return d[k]
        return []

    def sms_send(self, number, text, plan, ts):
        lt = datetime.fromtimestamp(ts).astimezone()
        off = lt.utcoffset().total_seconds() / 3600
        tz = "0" if off == 0 else (f"+{off:g}" if off > 0 else f"{off:g}")
        sms_time = ";".join([lt.strftime("%y"), lt.strftime("%m"), lt.strftime("%d"), lt.strftime("%H"), lt.strftime("%M"),
                             lt.strftime("%S"), tz])
        return self.call_auth("zwrt_wms", "zte_libwms_send_sms",
                              {"number": number, "sms_time": sms_time, "message_body": sms_hex(text), "id": "-1",
                               "encode_type": plan["encoding"]})

    def sms_send_state(self, timeout=12):
        """Wartet auf den Versandstatus des Routers. True = gesendet, False = fehlgeschlagen, None = unklar."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                d = self.call_auth("zwrt_wms", "zwrt_wms_get_cmd_status", {"sms_cmd": 4})
            except RouterError:
                return None
            v = str(d.get("sms_cmd_status_result", d.get("result", ""))).strip().lower()
            if v in ("3", "success"):
                return True
            if v in ("2", "fail", "failed", "-1"):
                return False
            time.sleep(1.0)
        return None

    def sms_delete(self, ids):
        ids = [str(i) for i in ids if str(i).strip()]
        if ids:
            return self.call_auth("zwrt_wms", "zwrt_wms_delete_sms", {"id": ";".join(ids) + ";"})
        return {}


def perform_reconnect(router, grace_s=60, progress=None, on_pending=None):
    """Verbindung neu aufbauen: Netzwerkmodus kurz umschalten und zurücksetzen (Modem meldet sich neu
    im Netz an). Stellt den ursprünglichen Modus in jedem Fall wieder her.
    Rückgabe: {"ok": bool, "seconds": int, "detail": str}"""
    say = progress or (lambda m: log.info("%s", m))
    t0 = time.time()
    try:
        cur = router.netinfo().get("net_select") or "4G_AND_5G"
    except RouterError as exc:
        return {"ok": False, "seconds": 0, "detail": f"Router nicht erreichbar: {exc}"}
    alt = "Only_LTE" if cur != "Only_LTE" else "4G_AND_5G"
    if on_pending:
        on_pending(cur)
    say(f"Netzwerkmodus {cur} -> {alt}")
    try:
        router.set_netselect(alt)
    except RouterError as exc:
        if on_pending:
            on_pending(None)
        return {"ok": False, "seconds": int(time.time() - t0), "detail": f"Umschalten fehlgeschlagen: {exc}"}
    time.sleep(4)
    restored = False
    for attempt in range(4):
        try:
            say(f"Netzwerkmodus {alt} -> {cur} (Versuch {attempt + 1})")
            router.set_netselect(cur)
            restored = True
            break
        except RouterError as exc:
            log.warning("Zurücksetzen des Netzwerkmodus fehlgeschlagen: %s", exc)
            time.sleep(3)
    if not restored:
        return {"ok": False, "seconds": int(time.time() - t0),
                "detail": f"Netzwerkmodus konnte nicht auf {cur} zurückgesetzt werden - bitte in der Router-Oberfläche prüfen"}
    if on_pending:
        on_pending(None)
    deadline = time.time() + grace_s
    time.sleep(2)
    while time.time() < deadline:
        try:
            d = router.netinfo()
            if d.get("network_type") and (sig(d.get("nr5g_rsrp")) is not None or sig(d.get("lte_rsrp")) is not None):
                secs = int(time.time() - t0)
                return {"ok": True, "seconds": secs, "detail": f"Modem wieder im Netz ({d.get('network_type')}), {secs} s"}
        except RouterError:
            pass
        time.sleep(2)
    return {"ok": False, "seconds": int(time.time() - t0),
            "detail": f"Modem meldete sich innerhalb von {grace_s} s nicht wieder im Netz an"}


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def num(value):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def sig(value):
    """Signalwerte: der Router liefert 0/leer, wenn die Technologie nicht aktiv ist."""
    f = num(value)
    return None if f is None or f == 0 else f


def parse_nr_ca(raw):
    out = []
    for part in (raw or "").split(";"):
        f = [x.strip() for x in part.split(",")]
        if len(f) < 11:
            continue
        try:
            out.append({"pci": int(f[1]), "band": "n" + f[3], "arfcn": int(f[4]), "bw": int(f[5]),
                        "rsrp": float(f[7]), "rsrq": float(f[8]), "snr": float(f[9]), "rssi": float(f[10])})
        except ValueError:
            continue
    return out


def parse_sample(ts, d):
    nr = sig(d.get("nr5g_rsrp"))
    lte = sig(d.get("lte_rsrp"))
    band = d.get("nr5g_action_band") if nr is not None else d.get("wan_active_band")
    intv = lambda v: int(v) if str(v).strip().lstrip("-").isdigit() else None
    return {
        "ts": ts,
        "net_type": d.get("network_type") or "",
        "provider": d.get("network_provider_fullname") or d.get("network_provider") or "",
        "bars": intv(d.get("signalbar")),
        "band": band or d.get("wan_active_band") or "",
        "pci": intv(d.get("nr5g_pci")) if nr is not None else None,
        "cell_id": d.get("nr5g_cell_id") or None,
        "arfcn": intv(d.get("nr5g_action_channel")) if nr is not None else None,
        "bw": intv(d.get("nr5g_bandwidth")) if nr is not None else None,
        "nr_rsrp": nr, "nr_rsrq": sig(d.get("nr5g_rsrq")) if nr is not None else None,
        "nr_snr": num(d.get("nr5g_snr")) if nr is not None else None,
        "nr_rssi": sig(d.get("nr5g_rssi")) if nr is not None else None,
        "lte_rsrp": lte, "lte_rsrq": sig(d.get("lte_rsrq")) if lte is not None else None,
        "lte_snr": num(d.get("lte_snr")) if lte is not None else None,
        "lte_rssi": sig(d.get("lte_rssi")) if lte is not None else None,
        "ca": json.dumps(parse_nr_ca(d.get("nrca"))),
    }


def pick(d, *names):
    for n in names:
        if n in d:
            v = num(d[n])
            if v is not None:
                return v
    return None


def parse_usage(d):
    """Feldnamen des G5TS (zwrt_data.get_wwandst, type 4); ältere Namen als Fallback."""
    return {
        "rx_total": pick(d, "real_rx_bytes", "realtime_rx_bytes"), "tx_total": pick(d, "real_tx_bytes", "realtime_tx_bytes"),
        "rx_month": pick(d, "month_rx_bytes", "monthly_rx_bytes"), "tx_month": pick(d, "month_tx_bytes", "monthly_tx_bytes"),
        "rx_speed": pick(d, "real_rx_speed", "realtime_rx_thrpt", "rx_speed"),
        "tx_speed": pick(d, "real_tx_speed", "realtime_tx_thrpt", "tx_speed"),
        "rx_day": pick(d, "day_rx_bytes"), "tx_day": pick(d, "day_tx_bytes"),
    }


def counter_delta(cur, prev):
    """Differenz eines Router-Zählers; nach einem Reset zählt der neue Wert."""
    if cur is None or prev is None:
        return 0
    return int(cur - prev) if cur >= prev else int(cur)


# --------------------------------------------------------------------------- #
# SMS: Kodierung, Router-Schnittstelle (ubus zwrt_wms), Archiv, Abgleich, Versand
# --------------------------------------------------------------------------- #
# GSM-7-Zeichensatz (Standard + Erweiterungstabelle, die je 2 Zeichen belegt)
GSM7_BASIC = ("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
              "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")
GSM7_EXT = "^{}\\[~]|€"
SMS_MAX_SEGMENTS = 6
NUM_CLEAN_RE = re.compile(r"[\s\-\(\)/.]")
NUM_RE = re.compile(r"^\+?[0-9]{3,20}$")
NONDIGIT_RE = re.compile(r"\D")


class SmsError(Exception):
    """Fehler mit passendem HTTP-Status (400 Eingabe, 403 Recht, 404 unbekannt, 429 Limit, 502 Router)."""

    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


def sms_plan(text):
    """Kodierung und Anzahl der SMS-Teile: GSM-7 (160/153 Zeichen) oder Unicode (70/67 Zeichen)."""
    gsm = all(c in GSM7_BASIC or c in GSM7_EXT for c in text)
    if gsm:
        n = sum(2 if c in GSM7_EXT else 1 for c in text)
        seg = 1 if n <= 160 else -(-n // 153)
        return {"encoding": "GSM7_default", "length": len(text), "units": n, "segments": seg if n else 0}
    n = len(text.encode("utf-16-le")) // 2
    seg = 1 if n <= 70 else -(-n // 67)
    return {"encoding": "UNICODE", "length": len(text), "units": n, "segments": seg}


def sms_hex(text):
    return text.encode("utf-16-be", "surrogatepass").hex().upper()


def sms_unhex(content):
    """Router liefert den Text als UTF-16BE-Hex; reiner Klartext wird unverändert übernommen."""
    c = str(content or "")
    if c and len(c) % 4 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", c):
        try:
            return bytes.fromhex(c).decode("utf-16-be", "replace")
        except ValueError:
            pass
    return c


def sms_number(raw, strict=True):
    n = NUM_CLEAN_RE.sub("", str(raw or ""))
    if n.startswith("00"):
        n = "+" + n[2:]
    if not NUM_RE.match(n):
        if strict:
            raise SmsError("Ungültige Rufnummer – erlaubt sind Ziffern mit optionalem + (z. B. +491701234567)")
        return str(raw or "").strip()
    return n


def sms_nkey(number):
    return NONDIGIT_RE.sub("", str(number or ""))[-9:]


def sms_fp(box, number, ts, text):
    return hashlib.sha1(f"{box}|{NONDIGIT_RE.sub('', str(number))}|{int(ts)}|{text}".encode()).hexdigest()


def parse_sms_date(raw, default):
    """'24,05,12,14,30,00,+2' (auch mit ;) -> Unix-Zeit. Die Zeitzone gilt in Stunden (Viertelstunden werden erkannt)."""
    try:
        p = [x.strip() for x in re.split(r"[,;]", str(raw)) if x.strip() != ""]
        y, mo, d, h, mi, se = (int(p[i]) for i in range(6))
        dt = datetime(y + 2000 if y < 100 else y, mo, d, h, mi, se)
        if len(p) > 6:
            tz = float(p[6])
            if abs(tz) > 14:
                tz /= 4
            return int(calendar.timegm(dt.timetuple()) - tz * 3600)
        return int(dt.timestamp())
    except (ValueError, IndexError, OverflowError, OSError):
        return default


def sms_iso(ts):
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def sms_json(r):
    d = {"id": r["id"], "box": "inbox" if r["box"] == "in" else "sent", "number": r["number"], "text": r["text"],
         "timestamp": r["ts"], "time": sms_iso(r["ts"]), "read": bool(r["read"])}
    if r["box"] == "out":
        d["status"] = r["status"]
        if r["detail"]:
            d["detail"] = r["detail"]
    return d


def sms_accepted(res):
    """Antwort auf einen Schreibaufruf: True = angenommen, False = abgelehnt, None = unklar."""
    v = (res or {}).get("result")
    if isinstance(v, str):
        v = v.strip().lower()
        if v == "success":
            return True
        try:
            v = float(v)
        except ValueError:
            return None
    if isinstance(v, (int, float)):
        return True if v in (0, 3) else False if v in (2, -1) else None
    return None


def sms_query(conn, box="inbox", unread=False, number=None, since_id=None, since_ts=None, before_id=None,
              limit=50, order=None, q=None):
    where, args = ["deleted=0"], []
    if box in ("inbox", "in"):
        where.append("box='in'")
    elif box in ("sent", "out"):
        where.append("box='out'")
    elif box != "all":
        raise SmsError("box muss inbox, sent oder all sein")
    if unread:
        where.append("box='in' AND read=0")
    if number:
        key = sms_nkey(number)
        if not key:
            raise SmsError("Ungültige Rufnummer im Filter")
        where.append("nkey=?")
        args.append(key)
    if since_id is not None:
        where.append("id>?")
        args.append(since_id)
    if since_ts is not None:
        where.append("ts>=?")
        args.append(since_ts)
    if before_id is not None:
        where.append("id<?")
        args.append(before_id)
    if q:
        where.append("(text LIKE ? OR number LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    order = order or ("asc" if since_id is not None else "desc")
    limit = max(1, min(500, int(limit)))
    rows = conn.execute(f"SELECT * FROM sms WHERE {' AND '.join(where)} ORDER BY ts {'ASC' if order == 'asc' else 'DESC'}, "
                        f"id {'ASC' if order == 'asc' else 'DESC'} LIMIT ?", (*args, limit)).fetchall()
    return rows


# --------------------------------------------------------------------------- #
# Collector (Signal + Datenverbrauch)
# --------------------------------------------------------------------------- #
class Collector(threading.Thread):
    def __init__(self, cfg):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.router = Router(cfg)
        self.stop_flag = threading.Event()
        self.wake = threading.Event()          # weckt die Schlafpause, wenn Intervalle geändert wurden
        self.lock = threading.Lock()
        self.status = {"started": int(time.time()), "online": None, "last_ok": None, "last_error": None,
                       "usage_ok": None, "usage_error": None, "usage_last_ok": None}
        self._last_usage = 0.0
        self._last_maint = 0.0

    def snapshot_status(self):
        with self.lock:
            st = dict(self.status)
        st["login"] = self.router.login_state
        st["login_error"] = self.router.login_error
        st["usage_configured"] = self.router.can_login
        return st

    def _set(self, **kw):
        with self.lock:
            self.status.update(kw)

    def run(self):
        while not self.stop_flag.is_set():
            started = time.time()
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001 - der Loop darf nie sterben
                log.exception("Unerwarteter Fehler im Poll-Loop")
            self.wake.wait(max(0.5, self.cfg.poll - (time.time() - started)))
            self.wake.clear()

    def request_usage_now(self):
        self._last_usage = 0.0

    def poll_once(self):
        ts = int(time.time())
        conn = connect(self.cfg.db)
        try:
            self._poll_signal(conn, ts)
            if self.router.can_login and time.time() - self._last_usage >= self.cfg.usage_every:
                self._last_usage = time.time()
                self._poll_usage(conn, ts)
            if time.time() - self._last_maint > 600:
                self._last_maint = time.time()
                self.maintenance(conn)
            conn.commit()
        finally:
            conn.close()

    def maintenance(self, conn, startup=False):
        """Stundenwerte fortschreiben; Rohdaten erst nach dem Aggregieren aufräumen. Endgültig gelöscht wird nichts."""
        now = int(time.time())
        cutoff = now - self.cfg.raw_days * 86400
        if startup:
            first = conn.execute("SELECT MIN(ts) FROM samples").fetchone()[0]
            rollup(conn, first if first is not None else now)     # alles Vorhandene aggregieren, dann erst aufräumen
        else:
            rollup(conn, now - 3 * HOUR)
        edge = (cutoff // HOUR + 1) * HOUR
        for table in ("samples", "traffic", "pings"):
            conn.execute(f"DELETE FROM {table} WHERE ts < ?", (edge,))
        conn.commit()

    def _poll_signal(self, conn, ts):
        try:
            data = self.router.netinfo()
        except RouterError as exc:
            if self.status["online"] is not False:
                add_event(conn, ts, "offline", "Router nicht erreichbar")
                log.warning("%s", exc)
            self._set(online=False, last_error=str(exc))
            return
        if self.status["online"] is False:
            add_event(conn, ts, "online", "Router wieder erreichbar")
        s = parse_sample(ts, data)
        cols = list(s)
        conn.execute(f"INSERT OR REPLACE INTO samples({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                     [s[c] for c in cols])
        cfg_key = f"{s['net_type']}|{s['band']}|{s['pci']}"
        prev = kv_get(conn, "last_cfg")
        if not s["net_type"]:
            pass                     # Modem meldet sich gerade neu an (z. B. nach einem Neustart): kein Zellwechsel
        elif prev is not None and prev != cfg_key:
            p = prev.split("|")
            pretty = lambda a: f"{a[0]} {a[1]}" + (f" (PCI {a[2]})" if len(a) > 2 and a[2] not in ("", "None") else "")
            add_event(conn, ts, "cell", f"{pretty(p)} → {pretty([s['net_type'], s['band'], s['pci']])}")
        if s["net_type"]:
            kv_set(conn, "last_cfg", cfg_key)
        self._set(online=True, last_ok=ts, last_error=None)

    def _poll_usage(self, conn, ts):
        r = self.router
        try:
            if not r.sid:
                r.login()
            try:
                raw = r.usage()
            except AccessDenied:            # Session abgelaufen -> genau ein Re-Login
                r.sid = None if not (self.cfg.session and not self.cfg.password) else r.sid
                r.login()
                raw = r.usage()
        except RouterError as exc:
            if self.status["usage_ok"] is not False:
                log.warning("Datenverbrauch nicht abrufbar: %s", exc)
                add_event(conn, ts, "usage", f"Datenverbrauch nicht abrufbar: {exc}")
            self._set(usage_ok=False, usage_error=str(exc))
            return
        u = parse_usage(raw)
        last = kv_get(conn, "last_usage") or {}
        dt = max(1, ts - last.get("ts", ts)) if last else None
        # Bevorzugt den Monatszähler (überlebt Reconnects), sonst den Sitzungszähler
        if u["rx_month"] is not None or u["tx_month"] is not None:
            rx_d = counter_delta(u["rx_month"], last.get("rx_month"))
            tx_d = counter_delta(u["tx_month"], last.get("tx_month"))
        else:
            rx_d = counter_delta(u["rx_total"], last.get("rx_total"))
            tx_d = counter_delta(u["tx_total"], last.get("tx_total"))
        rx_speed, tx_speed = u["rx_speed"], u["tx_speed"]
        if rx_speed is None and dt:
            rx_speed, tx_speed = rx_d / dt, tx_d / dt
        conn.execute("INSERT OR REPLACE INTO traffic VALUES(?,?,?,?,?,?,?,?,?)",
                     (ts, u["rx_total"], u["tx_total"], u["rx_month"], u["tx_month"], rx_speed, tx_speed, rx_d, tx_d))
        if not last and u["rx_day"] is not None:      # erster Abruf: bisherigen Tagesverbrauch vom Router übernehmen
            conn.execute("INSERT OR IGNORE INTO daily(day,rx,tx) VALUES(?,?,?)",
                         (datetime.fromtimestamp(ts).strftime("%Y-%m-%d"), int(u["rx_day"]), int(u["tx_day"] or 0)))
        if rx_d or tx_d:
            day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
            conn.execute("INSERT INTO daily(day,rx,tx) VALUES(?,?,?) ON CONFLICT(day) DO UPDATE SET "
                         "rx=rx+excluded.rx, tx=tx+excluded.tx", (day, rx_d, tx_d))
        kv_set(conn, "last_usage", {"ts": ts, **{k: u[k] for k in ("rx_total", "tx_total", "rx_month", "tx_month")}})
        if self.status["usage_ok"] is False:
            add_event(conn, ts, "usage", "Datenverbrauch wieder verfügbar")
        self._set(usage_ok=True, usage_error=None, usage_last_ok=ts)


# --------------------------------------------------------------------------- #
# Ping-Messung
# --------------------------------------------------------------------------- #
PING_RE = re.compile(r"[A-Za-zÀ-ÿ]+\s*([=<])\s*([\d.,]+)\s*ms", re.I)
TTL_RE = re.compile(r"\bttl\s*[=:]", re.I)
PING_FATAL_RE = re.compile(r"operation not permitted|permission denied|not permitted|Berechtigung", re.I)
ICMP_STATE = {"ok": shutil.which("ping") is not None, "warned": False}


def parse_ping_output(text):
    """Antwortzeit in ms oder None. Sprachunabhängig (Windows deutsch/englisch, Linux, macOS)."""
    if not TTL_RE.search(text):
        return None                      # z. B. "Zielhost nicht erreichbar" (Antwort vom Gateway ohne TTL)
    m = PING_RE.search(text)
    if not m:
        return None
    v = float(m.group(2).replace(",", "."))
    return v / 2 if m.group(1) == "<" else v


def ping_icmp(host, timeout_ms):
    if os.name == "nt":
        cmd, flags = ["ping", "-n", "1", "-w", str(timeout_ms), host], 0x08000000     # CREATE_NO_WINDOW
    elif sys.platform == "darwin":
        cmd, flags = ["ping", "-c", "1", "-W", str(timeout_ms), host], 0
    else:
        cmd, flags = ["ping", "-c", "1", "-W", str(max(1, math.ceil(timeout_ms / 1000))), host], 0
    try:
        kw = {"creationflags": flags} if flags else {}
        p = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 4, **kw)
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        ICMP_STATE["ok"] = False
        return None
    text = (p.stdout + b"\n" + p.stderr).decode("latin-1", "replace")
    if PING_FATAL_RE.search(text):
        ICMP_STATE["ok"] = False        # ICMP im System nicht nutzbar -> nicht als Ausfall werten
        return None
    return parse_ping_output(text)


def ping_tcp(host, port, timeout_ms):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for family, stype, proto, _, addr in infos[:2]:
        s = socket.socket(family, stype, proto)
        s.settimeout(timeout_ms / 1000)
        t0 = time.perf_counter()
        try:
            s.connect(addr)
            return (time.perf_counter() - t0) * 1000
        except OSError:
            continue
        finally:
            s.close()
    return None


def ping_target(t, timeout_ms):
    if t["method"] == "tcp":
        return ping_tcp(t["host"], t["port"], timeout_ms)
    if not ICMP_STATE["ok"]:            # kein ping-Programm / keine Rechte: TCP auf 443 als Ersatz
        if not ICMP_STATE["warned"]:
            ICMP_STATE["warned"] = True
            log.warning("ICMP-Ping nicht verfügbar - verwende TCP-Verbindungstest auf Port 443")
        return ping_tcp(t["host"], 443, timeout_ms)
    return ping_icmp(t["host"], timeout_ms)


# --------------------------------------------------------------------------- #
# Monitor: Ping-Runden, Ausfallerkennung, Watchdog
# --------------------------------------------------------------------------- #
class Monitor(threading.Thread):
    def __init__(self, cfg, collector):
        super().__init__(daemon=True)
        self.cfg, self.collector = cfg, collector
        self.stop_flag = threading.Event()
        self.wake = threading.Event()
        self.lock = threading.Lock()
        self.reconnecting = False
        self.st = {"last_round": None, "consecutive": 0, "down_since": None, "fail_since": None, "outage_id": None,
                   "grace_until": 0.0, "last_reconnect": None, "reconnects": [], "last_result": None,
                   "round_ok": None}

    # -- Status für die API --------------------------------------------------- #
    def snapshot(self):
        with self.lock:
            s = dict(self.st)
        now = time.time()
        s["reconnects_1h"] = len([t for t in s.pop("reconnects") if now - t < HOUR])
        s["in_grace"] = now < s.pop("grace_until")
        s["reconnecting"] = self.reconnecting
        return s

    def _reconnects_last_hour(self):
        now = time.time()
        self.st["reconnects"] = [t for t in self.st["reconnects"] if now - t < HOUR]
        return len(self.st["reconnects"])

    # -- Start: unterbrochene Umschaltung reparieren, offene Ausfälle schließen ----------------- #
    def startup(self):
        conn = connect(self.cfg.db)
        try:
            last_ping = conn.execute("SELECT MAX(ts) FROM pings").fetchone()[0]
            for row in conn.execute("SELECT id, start FROM outages WHERE end IS NULL").fetchall():
                conn.execute("UPDATE outages SET end=? WHERE id=?", (max(row["start"], last_ping or row["start"]), row["id"]))
            pending = kv_get(conn, "pending_netselect")
            conn.commit()
        finally:
            conn.close()
        if pending and self.collector.router.can_login:
            log.warning("Netzwerkmodus stand noch auf Umschaltung - stelle %s wieder her", pending)
            try:
                self.collector.router.set_netselect(pending)
                conn = connect(self.cfg.db)
                kv_del(conn, "pending_netselect")
                add_event(conn, int(time.time()), "reconnect_fail", f"Netzwerkmodus nach Neustart des Dashboards auf {pending} zurückgesetzt")
                conn.commit()
                conn.close()
            except RouterError as exc:
                log.error("Wiederherstellen des Netzwerkmodus fehlgeschlagen: %s", exc)

    # -- Hauptschleife ---------------------------------------------------------- #
    def run(self):
        self.startup()
        while not self.stop_flag.is_set():
            started = time.time()
            interval = 10
            try:
                conn = connect(self.cfg.db)
                try:
                    settings = load_settings(conn)
                    interval = settings["ping"]["interval_s"]
                    if settings["ping"]["enabled"] and settings["ping"]["targets"]:
                        self.round(conn, settings)
                    conn.commit()
                finally:
                    conn.close()
            except Exception:  # noqa: BLE001
                log.exception("Fehler in der Ping-Runde")
            self.wake.wait(max(1.0, interval - (time.time() - started)))
            self.wake.clear()

    def round(self, conn, settings):
        ps, ws = settings["ping"], settings["watchdog"]
        ts = int(time.time())
        targets = ps["targets"]
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            rtts = list(pool.map(lambda t: ping_target(t, ps["timeout_ms"]), targets))
        conn.executemany("INSERT OR REPLACE INTO pings(ts,target,rtt) VALUES(?,?,?)",
                         [(ts, target_label(t), r) for t, r in zip(targets, rtts)])
        wd = [(t, r) for t, r in zip(targets, rtts) if t["watchdog"]]
        with self.lock:
            self.st["last_round"] = ts
        if not wd:
            return
        failed = sum(1 for _, r in wd if r is None)
        need = ws["min_failed_targets"] or len(wd)
        down = failed >= min(need, len(wd))
        self.evaluate(conn, ts, down, ws, failed, len(wd))

    # -- Ausfall-/Watchdog-Logik ------------------------------------------------ #
    def evaluate(self, conn, ts, down, ws, failed, total):
        now = time.time()
        st = self.st
        router_ok = self.collector.status.get("online") is True
        with self.lock:
            st["round_ok"] = not down
            if not down:
                if st["outage_id"] is not None:
                    dur = ts - st["down_since"]
                    conn.execute("UPDATE outages SET end=? WHERE id=?", (ts, st["outage_id"]))
                    n = conn.execute("SELECT reconnects FROM outages WHERE id=?", (st["outage_id"],)).fetchone()["reconnects"]
                    add_event(conn, ts, "outage_end", f"Verbindung wieder da nach {fmt_dur(dur)}" + (f" ({n} Neustart{'s' if n != 1 else ''})" if n else ""))
                    log.info("Verbindung wieder erreichbar nach %s", fmt_dur(dur))
                st.update(consecutive=0, down_since=None, fail_since=None, outage_id=None)
                return
            if not router_ok:
                # Router selbst nicht erreichbar: eher ein lokales Netzproblem als ein Mobilfunkproblem -> nichts unternehmen
                st.update(consecutive=0, fail_since=None)
                return
            if now < st["grace_until"]:
                return
            st["consecutive"] += 1
            st["fail_since"] = st["fail_since"] or ts
            if st["down_since"] is None:
                st["down_since"] = ts
            if st["outage_id"] is None and st["consecutive"] >= ws["outage_rounds"]:
                cur = conn.execute("INSERT INTO outages(start) VALUES(?)", (st["down_since"],))
                st["outage_id"] = cur.lastrowid
                add_event(conn, st["down_since"], "outage", f"Ziele nicht erreichbar ({failed}/{total} Watchdog-Ziele ohne Antwort)")
                log.warning("Ausfall erkannt: %d/%d Ziele ohne Antwort", failed, total)
            fails, secs = st["consecutive"], ts - st["fail_since"]
            reason = None
            if ws["fail_rounds"] and fails >= ws["fail_rounds"]:
                reason = f"{fails} Ping-Runden ohne Antwort"
            elif ws["fail_seconds"] and secs >= ws["fail_seconds"]:
                reason = f"{secs} s ohne Antwort"
            if not (reason and ws["enabled"]):
                return
            cool = now - (st["last_reconnect"] or 0) >= ws["cooldown_s"]
            if not cool or self._reconnects_last_hour() >= ws["max_per_hour"]:
                return
        self.start_reconnect(reason, dry_run=ws["dry_run"], grace_s=ws["grace_s"])

    # -- Neuverbinden ------------------------------------------------------------ #
    def start_reconnect(self, reason, dry_run=False, grace_s=60):
        with self.lock:
            if self.reconnecting:
                return False
            self.reconnecting = True
            self.st["last_reconnect"] = time.time()
            self.st["grace_until"] = time.time() + grace_s
            self.st["consecutive"] = 0
            self.st["fail_since"] = None
        threading.Thread(target=self._reconnect_thread, args=(reason, dry_run, grace_s), daemon=True).start()
        return True

    def _reconnect_thread(self, reason, dry_run, grace_s):
        ts = int(time.time())
        conn = connect(self.cfg.db)
        try:
            with self.lock:
                oid = self.st["outage_id"]
                if oid is not None:
                    conn.execute("UPDATE outages SET reconnects=reconnects+1 WHERE id=?", (oid,))
                    conn.commit()          # Schreibsperre sofort freigeben (pending-Marker nutzt eine eigene Verbindung)
            if dry_run:
                add_event(conn, ts, "reconnect_dry", f"Testmodus: Neustart wäre ausgelöst worden ({reason})")
                log.warning("Watchdog (Testmodus): Neustart wäre ausgelöst worden (%s)", reason)
                result = {"ok": True, "seconds": 0, "detail": "Testmodus"}
            else:
                log.warning("Watchdog: starte Verbindung neu (%s)", reason)

                def pending(v):
                    c = connect(self.cfg.db)
                    kv_set(c, "pending_netselect", v) if v else kv_del(c, "pending_netselect")
                    c.commit()
                    c.close()
                try:
                    result = perform_reconnect(self.collector.router, grace_s=grace_s, on_pending=pending)
                except RouterError as exc:
                    result = {"ok": False, "seconds": 0, "detail": str(exc)}
                kind = "reconnect" if result["ok"] else "reconnect_fail"
                add_event(conn, ts, kind, f"Verbindung neu gestartet ({reason}): {result['detail']}" if result["ok"]
                          else f"Neustart der Verbindung fehlgeschlagen ({reason}): {result['detail']}")
                log.info("Reconnect: %s", result)
            with self.lock:
                self.st["reconnects"].append(time.time())
                self.st["last_result"] = {"ts": ts, **result}
            conn.commit()
        except Exception:  # noqa: BLE001
            log.exception("Fehler beim Neuverbinden")
        finally:
            conn.close()
            with self.lock:
                self.reconnecting = False
                self.st["grace_until"] = max(self.st["grace_until"], time.time() + 10)


class SmsService(threading.Thread):
    """Holt SMS regelmäßig vom Router ins lokale Archiv, versendet SMS und meldet neue Nachrichten (Long-Poll, Webhook)."""

    def __init__(self, cfg, collector):
        super().__init__(daemon=True)
        self.cfg, self.router = cfg, collector.router
        self.stop_flag = threading.Event()
        self.wake = threading.Event()
        self.cond = threading.Condition()
        self.send_lock = threading.Lock()
        self.sync_lock = threading.Lock()
        self.lock = threading.Lock()
        self.status = {"ok": None, "last_sync": None, "last_error": None, "last_import": 0}
        self._last = 0.0
        self._force = False
        try:
            conn = connect(cfg.db)
            self.last_in_id = conn.execute("SELECT COALESCE(MAX(id),0) FROM sms WHERE box='in'").fetchone()[0]
            conn.close()
        except sqlite3.Error:
            self.last_in_id = 0

    # -- Steuerung ---------------------------------------------------------------- #
    def snapshot(self):
        with self.lock:
            return dict(self.status)

    def _set(self, **kw):
        with self.lock:
            self.status.update(kw)

    def sync_now(self):
        self._force = True
        self.wake.set()

    def run(self):
        while not self.stop_flag.is_set():
            wait = 5.0
            try:
                wait = self.tick()
            except Exception:  # noqa: BLE001
                log.exception("Unerwarteter Fehler im SMS-Dienst")
            self.wake.wait(max(1.0, wait))
            self.wake.clear()

    def tick(self):
        conn = connect(self.cfg.db)
        try:
            st = load_settings(conn)["sms"]
        finally:
            conn.close()
        if not st["enabled"] or not self.router.can_login:
            self._set(ok=None, last_error=None if not st["enabled"] else "Router-Passwort fehlt")
            return 10.0
        due = self._last + st["interval_s"] - time.time()
        if due > 0 and not self._force:
            return min(due, 15.0)
        self._force = False
        self._last = time.time()
        try:
            self.sync()
        except RouterError as exc:
            msg = str(exc)
            if self.status.get("last_error") != msg:
                log.warning("SMS-Abruf nicht möglich: %s", msg)
            self._set(ok=False, last_error=msg)
        return min(st["interval_s"], 15.0)

    # -- Abgleich Router -> Archiv --------------------------------------------------- #
    def sync(self):
        with self.sync_lock:
            msgs = self.router.sms_list()
            conn = connect(self.cfg.db)
            new_in, kept_ids, imported = [], [], 0
            try:
                st = load_settings(conn)["sms"]
                first = conn.execute("SELECT COUNT(*) FROM sms").fetchone()[0] == 0
                now = int(time.time())
                for m in msgs:
                    try:
                        tag = int(str(m.get("tag")).strip())
                    except ValueError:
                        continue
                    if tag not in (0, 1, 2, 3):        # Entwürfe u. a. ignorieren
                        continue
                    box = "in" if tag < 2 else "out"
                    number, text = str(m.get("number") or "").strip(), sms_unhex(m.get("content"))
                    ts = parse_sms_date(m.get("date"), now)
                    rid = str(m.get("id") or "")
                    fp = sms_fp(box, number, ts, text)
                    row = conn.execute("SELECT id, status FROM sms WHERE fp=?", (fp,)).fetchone()
                    if not row and box == "out":       # eigene, über das Dashboard gesendete Nachricht wiedererkennen
                        row = conn.execute("SELECT id, status FROM sms WHERE box='out' AND nkey=? AND text=? AND ABS(ts-?)<=180 "
                                           "AND router_id IS NULL ORDER BY ABS(ts-?) LIMIT 1", (sms_nkey(number), text, ts, ts)).fetchone()
                    if row:
                        conn.execute("UPDATE sms SET router_id=?, fp=? WHERE id=?", (rid, fp, row["id"]))   # ab jetzt exakt wiedererkennbar
                        if box == "out" and row["status"] in ("sending", "unconfirmed"):
                            conn.execute("UPDATE sms SET status=? WHERE id=?", ("failed" if tag == 3 else "sent", row["id"]))
                        kept_ids.append(rid)
                        continue
                    cur = conn.execute(
                        "INSERT INTO sms(box,number,nkey,text,ts,created,read,status,router_id,source,fp) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (box, number, sms_nkey(number), text, ts, now, 0 if tag == 1 else 1,
                         None if box == "in" else ("failed" if tag == 3 else "sent"), rid, "router", fp))
                    imported += 1
                    kept_ids.append(rid)
                    if box == "in":
                        new_in.append(conn.execute("SELECT * FROM sms WHERE id=?", (cur.lastrowid,)).fetchone())
                if imported and first:
                    add_event(conn, now, "sms_in", f"{imported} vorhandene SMS aus dem Router übernommen")
                elif new_in:
                    for r in new_in:
                        add_event(conn, now, "sms_in", f"SMS von {r['number']}")
                conn.commit()
            finally:
                conn.close()
            self._set(ok=True, last_sync=int(time.time()), last_error=None, last_import=imported)
            if new_in:
                with self.cond:
                    self.last_in_id = max(self.last_in_id, max(r["id"] for r in new_in))
                    self.cond.notify_all()
                if st["webhook_url"] and not first:
                    threading.Thread(target=self._webhook, args=(st["webhook_url"], [dict(r) for r in new_in]), daemon=True).start()
            if st["delete_on_router"] and kept_ids:
                try:
                    for i in range(0, len(kept_ids), 20):
                        self.router.sms_delete(kept_ids[i:i + 20])
                except RouterError as exc:
                    log.warning("SMS im Router löschen fehlgeschlagen: %s", exc)
            return imported

    @staticmethod
    def _webhook(url, rows):
        for r in rows:
            body = json.dumps({"event": "sms_received", "message": sms_json(r)}).encode()
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "User-Agent": "zte-dash"})
            try:
                urllib.request.urlopen(req, timeout=6).read(200)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                log.warning("Webhook nicht erreichbar (%s): %s", url, exc)

    def wait_new(self, since_id, timeout):
        """Long-Poll: wartet bis eine SMS mit größerer ID im Eingang liegt (max. timeout Sekunden)."""
        end = time.time() + max(0, min(60, timeout))
        with self.cond:
            while self.last_in_id <= since_id and time.time() < end and not self.stop_flag.is_set():
                self.cond.wait(min(1.0, end - time.time()))
            return self.last_in_id > since_id

    # -- Versand --------------------------------------------------------------------- #
    def send(self, number, text, source="dashboard"):
        number = sms_number(number)
        text = str(text or "").replace("\r\n", "\n")
        if not text.strip():
            raise SmsError("Der Text darf nicht leer sein")
        plan = sms_plan(text)
        if plan["segments"] > SMS_MAX_SEGMENTS:
            raise SmsError(f"Der Text ist zu lang ({plan['segments']} SMS-Teile, erlaubt sind {SMS_MAX_SEGMENTS}). "
                           f"Mit Sonderzeichen passen nur 67 Zeichen je Teil.")
        if not self.router.can_login:
            raise SmsError("Zum Senden wird das Router-Passwort benötigt (Einstellungen → Verbindung)", 409)
        conn = connect(self.cfg.db)
        try:
            st = load_settings(conn)["sms"]
            now = int(time.time())
            used = conn.execute("SELECT COUNT(*) FROM sms WHERE box='out' AND source!='router' AND created>?", (now - 3600,)).fetchone()[0]
            if used >= st["send_limit_per_hour"]:
                raise SmsError(f"Sendelimit erreicht: höchstens {st['send_limit_per_hour']} SMS pro Stunde "
                               f"(einstellbar unter Einstellungen → SMS)", 429)
            with self.send_lock:
                ts = int(time.time())
                cur = conn.execute("INSERT INTO sms(box,number,nkey,text,ts,created,read,status,source,fp) VALUES('out',?,?,?,?,?,1,'sending',?,?)",
                                   (number, sms_nkey(number), text, ts, ts, source, sms_fp("out", number, ts, text) + f"-{secrets.token_hex(3)}"))
                rid = cur.lastrowid
                conn.commit()
                status, detail = "sent", None
                try:
                    res = self.router.sms_send(number, text, plan, ts)
                    ok = sms_accepted(res)
                    if ok is False:
                        status, detail = "failed", "Der Router hat die SMS abgelehnt"
                    else:
                        state = self.router.sms_send_state()
                        if state is False:
                            status, detail = "failed", "Der Versand ist fehlgeschlagen (Router-Status)"
                        elif state is None or ok is None:
                            status, detail = "unconfirmed", "Vom Router angenommen, Zustellung nicht bestätigt"
                except RouterError as exc:
                    status, detail = "failed", str(exc)
                conn.execute("UPDATE sms SET status=?, detail=? WHERE id=?", (status, detail, rid))
                add_event(conn, int(time.time()), "sms_out" if status != "failed" else "sms_fail",
                          f"SMS an {number}" + ("" if status != "failed" else f" fehlgeschlagen: {detail}"))
                conn.commit()
                row = conn.execute("SELECT * FROM sms WHERE id=?", (rid,)).fetchone()
        finally:
            conn.close()
        self._force = True
        self.wake.set()
        out = sms_json(row)
        out["segments"], out["encoding"] = plan["segments"], plan["encoding"]
        if row["status"] == "failed":
            raise SmsError(detail or "SMS konnte nicht gesendet werden", 502)
        return out

    # -- Löschen ---------------------------------------------------------------------- #
    def delete(self, ids, on_router=True):
        conn = connect(self.cfg.db)
        try:
            ids = [int(i) for i in ids][:500]
            rows = [r for r in conn.execute(f"SELECT * FROM sms WHERE deleted=0 AND id IN ({','.join('?' * len(ids)) or 'NULL'})", ids)]
            conn.executemany("UPDATE sms SET deleted=1 WHERE id=?", [(r["id"],) for r in rows])
            conn.commit()
        finally:
            conn.close()
        removed_router = 0
        if on_router and rows and self.router.can_login:
            try:
                have = {str(m.get("id")): (str(m.get("number") or "").strip(), sms_unhex(m.get("content"))) for m in self.router.sms_list()}
                rids = [r["router_id"] for r in rows if r["router_id"] and have.get(r["router_id"]) == (r["number"], r["text"])]
                for i in range(0, len(rids), 20):
                    self.router.sms_delete(rids[i:i + 20])
                removed_router = len(rids)
            except RouterError as exc:
                log.warning("SMS im Router löschen fehlgeschlagen: %s", exc)
        return {"deleted": len(rows), "deleted_on_router": removed_router}


def fmt_bytes(b):
    if b is None:
        return "–"
    v = float(b)
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if abs(v) < 1000 or unit == "TB":
            return f"{v:.1f} {unit}".replace(".", ",") if unit != "B" else f"{int(v)} B"
        v /= 1000


def fmt_dur(sec):
    sec = int(sec)
    if sec < 90:
        return f"{sec} s"
    if sec < 5400:
        return f"{sec // 60} min {sec % 60:02d} s"
    return f"{sec // 3600} h {sec % 3600 // 60:02d} min"


# --------------------------------------------------------------------------- #
# API
# --------------------------------------------------------------------------- #
RANGES = {"1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400,
          "90d": 90 * 86400, "365d": 365 * 86400}
SIGNAL_COLS = ["nr_rsrp", "nr_rsrq", "nr_snr", "nr_rssi", "lte_rsrp", "lte_rsrq", "lte_snr", "lte_rssi"]
MARK_KINDS = ("reconnect", "reconnect_dry", "reconnect_fail")


def row_dict(row):
    if row is None:
        return None
    d = dict(row)
    if "ca" in d:
        try:
            d["ca"] = json.loads(d["ca"] or "[]")
        except ValueError:
            d["ca"] = []
    return d


def billing_start(today, billing_day):
    if today.day >= billing_day:
        return today.replace(day=billing_day)
    first = today.replace(day=1) - timedelta(days=1)
    return first.replace(day=billing_day)


def quantile(sorted_vals, q):
    if not sorted_vals:
        return 0
    pos = (len(sorted_vals) - 1) * q
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def live_sample(d, t):
    """Ein Messpunkt für die Setup-Seite: Werte der aktiven Verbindung (5G, sonst LTE) plus Bewertung."""
    s = parse_sample(int(t), d)
    nr = s["nr_rsrp"] is not None
    k = "nr" if nr else "lte"
    rsrp, rsrq, snr, rssi = s[f"{k}_rsrp"], s[f"{k}_rsrq"], s[f"{k}_snr"], s[f"{k}_rssi"]
    r = rate(rsrp, snr, rsrq)
    return {"t": round(t, 2), "net": s["net_type"], "band": s["band"], "pci": s["pci"], "bw": s["bw"], "nr": nr,
            "bars": s["bars"], "rsrp": rsrp, "rsrq": rsrq, "snr": snr, "rssi": rssi,
            "cells": 1 + len(parse_nr_ca(d.get("nrca"))), "provider": s["provider"],
            "score": r["score"] if r else None, "level": r["level"] if r else None, "label": r["label"] if r else None,
            "limiting": r["limiting"] if r else None}


class LiveFeed:
    """Hochfrequente Abfrage für die Setup-Seite. Es gibt keinen Hintergrund-Thread: gemessen wird nur, wenn ein
    Browser die Seite offen hat. Mehrere Browser teilen sich dieselben Messungen (Mindestabstand 0,4 s)."""

    def __init__(self, router):
        self.router = router
        self.lock = threading.Lock()
        self.buf = deque(maxlen=1500)
        self.seq = 0
        self.last = 0.0
        self.error = None

    def poll(self, since=0, keep=300):
        with self.lock:
            now = time.time()
            if now - self.last >= 0.4:
                self.last = now
                try:
                    smp = live_sample(self.router.netinfo(), now)
                    self.seq += 1
                    smp["seq"] = self.seq
                    self.buf.append(smp)
                    self.error = None
                except RouterError as exc:
                    self.error = str(exc)
            out = [x for x in self.buf if x["seq"] > since]
            return {"now": round(now, 2), "seq": self.seq, "samples": out[-keep:], "error": self.error, "spec": RATING_SPEC}


class Api:
    def __init__(self, cfg, collector, monitor=None, auth=None, sms=None):
        self.cfg, self.collector, self.monitor, self.auth, self.sms = cfg, collector, monitor, auth, sms
        self.live_feed = LiveFeed(collector.router) if collector else None
        self._last_test = 0.0

    def conn(self):
        return connect(self.cfg.db)

    # -- Aktueller Stand --------------------------------------------------------- #
    def current(self):
        conn = self.conn()
        try:
            sample = row_dict(conn.execute("SELECT * FROM samples ORDER BY ts DESC LIMIT 1").fetchone())
            usage = row_dict(conn.execute("SELECT * FROM traffic ORDER BY ts DESC LIMIT 1").fetchone())
            today = datetime.now().strftime("%Y-%m-%d")
            t = conn.execute("SELECT rx, tx FROM daily WHERE day=?", (today,)).fetchone()
            n = conn.execute("SELECT COUNT(*) c, MIN(ts) m FROM samples").fetchone()
            first_h = conn.execute("SELECT MIN(ts) FROM samples_h").fetchone()[0]
            settings = load_settings(conn)
            since24 = int(time.time()) - 86400
            rc24 = conn.execute("SELECT COUNT(*) FROM events WHERE ts>=? AND kind='reconnect'", (since24,)).fetchone()[0]
            oc24 = conn.execute("SELECT COUNT(*) FROM outages WHERE start>=?", (since24,)).fetchone()[0]
            conf = {target_label(t) for t in settings["ping"]["targets"]}
            last_ping = [r for r in conn.execute("SELECT ts, target, rtt FROM pings WHERE ts=(SELECT MAX(ts) FROM pings)").fetchall()
                         if r["target"] in conf]
            return {"now": int(time.time()), "sample": sample, "usage": usage,
                    "today": {"rx": t["rx"], "tx": t["tx"]} if t else {"rx": 0, "tx": 0},
                    "status": self.collector.snapshot_status() if self.collector else {},
                    "monitor": {**(self.monitor.snapshot() if self.monitor else {}),
                                "ping_enabled": settings["ping"]["enabled"], "watchdog_enabled": settings["watchdog"]["enabled"],
                                "dry_run": settings["watchdog"]["dry_run"], "reconnects_24h": rc24, "outages_24h": oc24,
                                "last_ping": [{"target": r["target"], "rtt": r["rtt"]} for r in last_ping],
                                "last_ping_ts": last_ping[0]["ts"] if last_ping else None},
                    "auth": {"enabled": bool(self.auth and self.auth.enabled)},
                    "sms": {"unread": self.sms_counts(conn)[0], "enabled": settings["sms"]["enabled"]},
                    "config": {"poll": self.cfg.poll, "usage": self.cfg.usage_every, "limit_gb": self.cfg.limit_gb,
                               "billing_day": self.cfg.billing_day, "raw_days": self.cfg.raw_days, "host": self.cfg.host,
                               "ui_refresh": self.cfg.ui_refresh},
                    "db": {"samples": n["c"], "since": first_h or n["m"]}}
        finally:
            conn.close()

    # -- Zeitfenster (Voreinstellung oder freier Ausschnitt per Zoom) ---------------------- #
    def window(self, rng, t_from=None, t_to=None):
        now = int(time.time())
        if t_from is not None and t_to is not None:
            until = min(int(t_to), now)
            since = max(int(t_from), now - 800 * 86400)
            if until - since < 30:
                since = until - 30
            return since, until, now, True
        return now - RANGES.get(rng, RANGES["24h"]), now, now, False

    def _hourly(self, since, until):
        return until - since >= 15 * 86400 or since < time.time() - self.cfg.raw_days * 86400

    def _bucket(self, since, until, hourly):
        span = until - since
        return max(HOUR, (span // 360) // HOUR * HOUR) if hourly else max(self.cfg.poll, span // 360)

    # -- Marker (Neustarts, Ausfälle) ------------------------------------------- #
    def marks(self, conn, since, until, now=None):
        now = now or until
        q = ",".join("?" * len(MARK_KINDS))
        rec = conn.execute(f"SELECT ts, kind, detail FROM events WHERE ts>=? AND ts<=? AND kind IN ({q}) ORDER BY ts",
                           (since, until, *MARK_KINDS)).fetchall()
        out = conn.execute("SELECT start, end, reconnects FROM outages WHERE start<=? AND COALESCE(end, ?)>=? ORDER BY start",
                           (until, now, since)).fetchall()
        return {"reconnects": [{"ts": r["ts"], "kind": r["kind"], "detail": r["detail"]} for r in rec],
                "outages": [{"start": o["start"], "end": o["end"], "reconnects": o["reconnects"]} for o in out]}

    # -- Verlauf Signal/Traffic ---------------------------------------------------- #
    def history(self, rng, t_from=None, t_to=None):
        since, until, now, custom = self.window(rng, t_from, t_to)
        hourly = self._hourly(since, until)
        bucket = self._bucket(since, until, hourly)
        h0, h1 = since // HOUR * HOUR, until
        conn = self.conn()
        try:
            if hourly:
                sel = ",".join(f"AVG({c})" for c in SIGNAL_COLS)
                rows = conn.execute(f"SELECT (ts/{bucket})*{bucket} AS t, {sel}, AVG(bars) FROM samples_h "
                                    f"WHERE ts>=? AND ts<=? GROUP BY t ORDER BY t", (h0, h1)).fetchall()
                trows = conn.execute(
                    f"SELECT (ts/{bucket})*{bucket} AS t, AVG(rx_speed), AVG(tx_speed), SUM(rx_delta), SUM(tx_delta) "
                    f"FROM traffic_h WHERE ts>=? AND ts<=? GROUP BY t ORDER BY t", (h0, h1)).fetchall()
                tot = conn.execute("SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0) FROM traffic_h WHERE ts>=? AND ts<=?",
                                   (h0, h1)).fetchone()
                stats = {}
                for c, lo, hi in (("nr_rsrp", "nr_rsrp_min", "nr_rsrp_max"), ("lte_rsrp", "lte_rsrp_min", "lte_rsrp_max")):
                    r = conn.execute(f"SELECT MIN({lo}), SUM({c}*n)/SUM(n), MAX({hi}) FROM samples_h WHERE ts>=? AND ts<=? AND {c} IS NOT NULL",
                                     (h0, h1)).fetchone()
                    stats[c] = None if r[1] is None else {"min": r[0], "avg": round(r[1], 1), "max": r[2]}
                r = conn.execute("SELECT AVG(nr_snr) FROM samples_h WHERE ts>=? AND ts<=? AND nr_snr IS NOT NULL", (h0, h1)).fetchone()
                stats["nr_snr"] = None if r[0] is None else {"min": None, "avg": round(r[0], 1), "max": None}
                q = conn.execute("SELECT SUM(q0), SUM(q1), SUM(q2), SUM(q3) FROM samples_h WHERE ts>=? AND ts<=?", (h0, h1)).fetchone()
            else:
                sel = ",".join(f"AVG({c})" for c in SIGNAL_COLS)
                rows = conn.execute(f"SELECT (ts/{bucket})*{bucket} AS t, {sel}, AVG(bars) FROM samples "
                                    f"WHERE ts>=? AND ts<=? GROUP BY t ORDER BY t", (since, until)).fetchall()
                trows = conn.execute(
                    f"SELECT (ts/{bucket})*{bucket} AS t, AVG(rx_speed), AVG(tx_speed), SUM(rx_delta), SUM(tx_delta) "
                    f"FROM traffic WHERE ts>=? AND ts<=? GROUP BY t ORDER BY t", (since, until)).fetchall()
                tot = conn.execute("SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0) FROM traffic WHERE ts>=? AND ts<=?",
                                   (since, until)).fetchone()
                stats = {}
                for c in ("nr_rsrp", "nr_snr", "lte_rsrp"):
                    r = conn.execute(f"SELECT MIN({c}), AVG({c}), MAX({c}) FROM samples WHERE ts>=? AND ts<=? AND {c} IS NOT NULL",
                                     (since, until)).fetchone()
                    stats[c] = None if r[1] is None else {"min": r[0], "avg": round(r[1], 1), "max": r[2]}
                q = conn.execute(
                    "SELECT SUM(CASE WHEN p>=-90 THEN 1 ELSE 0 END), SUM(CASE WHEN p<-90 AND p>=-100 THEN 1 ELSE 0 END), "
                    "SUM(CASE WHEN p<-100 AND p>=-110 THEN 1 ELSE 0 END), SUM(CASE WHEN p<-110 THEN 1 ELSE 0 END) FROM "
                    "(SELECT COALESCE(nr_rsrp, lte_rsrp) AS p FROM samples WHERE ts>=? AND ts<=?) WHERE p IS NOT NULL", (since, until)).fetchone()
            signal = {"t": [r[0] for r in rows]}
            for i, c in enumerate(SIGNAL_COLS):
                signal[c] = [None if r[i + 1] is None else round(r[i + 1], 2) for r in rows]
            traffic = {"t": [r[0] for r in trows],
                       "rx_speed": [None if r[1] is None else round(r[1]) for r in trows],
                       "tx_speed": [None if r[2] is None else round(r[2]) for r in trows]}
            ev = conn.execute("SELECT ts, kind, detail FROM events WHERE ts>=? AND ts<=? ORDER BY ts DESC LIMIT 80", (since, until)).fetchall()
            return {"range": "custom" if custom else rng, "since": since, "now": until, "custom": custom, "bucket": bucket, "hourly": hourly,
                    "signal": signal, "traffic": traffic, "range_rx": tot[0], "range_tx": tot[1], "stats": stats,
                    "quality": [int(v or 0) for v in q], "events": [dict(e) for e in ev],
                    "marks": self.marks(conn, since, until, now)}
        finally:
            conn.close()

    # -- Ping-Statistik ------------------------------------------------------------- #
    def ping(self, rng, t_from=None, t_to=None):
        """Nur die aktuell in den Einstellungen konfigurierten Ziele werden ausgewertet und angezeigt;
        Messwerte früherer Ziele bleiben in der Datenbank, erscheinen aber nirgends."""
        since, until, now, custom = self.window(rng, t_from, t_to)
        hourly = self._hourly(since, until)
        bucket = self._bucket(since, until, hourly)
        conn = self.conn()
        try:
            settings = load_settings(conn)
            names = [target_label(t) for t in settings["ping"]["targets"]]
            wd_flags = {target_label(t): t["watchdog"] for t in settings["ping"]["targets"]}
            ph = ",".join("?" * len(names)) or "''"
            if hourly:
                s0 = since // HOUR * HOUR
                rows = conn.execute(
                    f"SELECT (ts/{bucket})*{bucket} t, target, SUM(rtt_sum)/NULLIF(SUM(rtt_n),0), SUM(n), SUM(lost) "
                    f"FROM pings_h WHERE ts>=? AND ts<=? AND target IN ({ph}) GROUP BY t, target ORDER BY t", (s0, until, *names)).fetchall()
                summ = conn.execute(
                    "SELECT target, SUM(n), SUM(lost), SUM(rtt_n), SUM(rtt_sum), SUM(rtt_sq), MIN(rtt_min), MAX(rtt_max) "
                    f"FROM pings_h WHERE ts>=? AND ts<=? AND target IN ({ph}) GROUP BY target", (s0, until, *names)).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT (ts/{bucket})*{bucket} t, target, AVG(rtt), COUNT(*), SUM(CASE WHEN rtt IS NULL THEN 1 ELSE 0 END) "
                    f"FROM pings WHERE ts>=? AND ts<=? AND target IN ({ph}) GROUP BY t, target ORDER BY t", (since, until, *names)).fetchall()
                summ = conn.execute(
                    "SELECT target, COUNT(*), SUM(CASE WHEN rtt IS NULL THEN 1 ELSE 0 END), COUNT(rtt), SUM(rtt), SUM(rtt*rtt), MIN(rtt), MAX(rtt) "
                    f"FROM pings WHERE ts>=? AND ts<=? AND target IN ({ph}) GROUP BY target", (since, until, *names)).fetchall()
            ts_sorted = sorted({r[0] for r in rows})
            pos = {t: i for i, t in enumerate(ts_sorted)}
            series = {n: {"avg": [None] * len(ts_sorted), "loss": [None] * len(ts_sorted)} for n in names}
            for t, target, avg, n, lost in rows:
                s = series[target]
                s["avg"][pos[t]] = None if avg is None else round(avg, 2)
                s["loss"][pos[t]] = round(100.0 * (lost or 0) / n, 1) if n else None
            summary = []
            by_target = {r[0]: r for r in summ}
            for n in names:
                r = by_target.get(n)
                if not r or not r[1]:
                    summary.append({"target": n, "watchdog": wd_flags.get(n), "n": 0})
                    continue
                _, cnt, lost, rn, rsum, rsq, rmin, rmax = r
                avg = rsum / rn if rn else None
                jit = math.sqrt(max(0.0, rsq / rn - avg * avg)) if rn else None
                summary.append({"target": n, "watchdog": wd_flags.get(n), "n": cnt, "lost": lost or 0,
                                "loss_pct": round(100.0 * (lost or 0) / cnt, 2), "avg": None if avg is None else round(avg, 1),
                                "min": None if rmin is None else round(rmin, 1), "max": None if rmax is None else round(rmax, 1),
                                "jitter": None if jit is None else round(jit, 1)})
            marks = self.marks(conn, since, until, now)
            down = sum(min(o["end"] or now, until) - max(o["start"], since) for o in marks["outages"])
            return {"range": "custom" if custom else rng, "custom": custom, "since": since, "now": until, "bucket": bucket,
                    "hourly": hourly, "t": ts_sorted,
                    "targets": [{"name": n, "watchdog": wd_flags.get(n), **series[n]} for n in names],
                    "summary": summary, "marks": marks, "outage_count": len(marks["outages"]),
                    "outage_seconds": max(0, down), "reconnect_count": sum(1 for r in marks["reconnects"] if r["kind"] == "reconnect")}
        finally:
            conn.close()

    # -- Verbrauch in wählbarer Auflösung ------------------------------------------------- #
    BUCKETS = ("10m", "1h", "1d", "1w", "1M")
    BUCKET_DEFAULT = {"10m": 144, "1h": 168, "1d": 30, "1w": 26, "1M": 12}
    BUCKET_STEP = {"10m": 600, "1h": 3600, "1d": 86400, "1w": 7 * 86400, "1M": 30.44 * 86400}

    @staticmethod
    def _bucket_start(bucket, ts):
        """Beginn des Abschnitts, in den ts fällt (Tage/Wochen/Monate nach Ortszeit, Woche beginnt am Montag)."""
        if bucket == "10m":
            return int(ts) // 600 * 600
        if bucket == "1h":
            return int(ts) // 3600 * 3600
        d = datetime.fromtimestamp(ts).replace(hour=0, minute=0, second=0, microsecond=0)
        if bucket == "1w":
            d -= timedelta(days=d.weekday())
        elif bucket == "1M":
            d = d.replace(day=1)
        return int(d.timestamp())

    @staticmethod
    def _bucket_next(bucket, ts, k=1):
        """Beginn des k-ten folgenden (k<0: vorherigen) Abschnitts."""
        if bucket == "10m":
            return int(ts) + 600 * k
        if bucket == "1h":
            return int(ts) + 3600 * k
        d = datetime.fromtimestamp(ts)
        if bucket == "1d":
            d += timedelta(days=k)
        elif bucket == "1w":
            d += timedelta(days=7 * k)
        else:
            m = d.year * 12 + d.month - 1 + k
            d = d.replace(year=m // 12, month=m % 12 + 1, day=1)
        return int(d.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())

    def usage_series(self, bucket="1d", count=None, t_from=None, t_to=None):
        """Datenverbrauch (Download/Upload) je Abschnitt. Entweder die letzten `count` Abschnitte oder ein Zeitfenster
        (Zoom); dort wird die Auflösung bei Bedarf automatisch vergröbert bzw. verfeinert."""
        if bucket not in self.BUCKETS:
            raise ValueError("bucket muss 10m, 1h, 1d, 1w oder 1M sein")
        now = int(time.time())
        requested, adjusted = bucket, False
        if t_from is not None and t_to is not None:
            until, since = min(int(t_to), now), max(int(t_from), now - 800 * 86400)
            if until - since < 30:
                since = until - 30
            span, i = until - since, self.BUCKETS.index(bucket)
            while i < len(self.BUCKETS) - 1 and span / self.BUCKET_STEP[self.BUCKETS[i]] > 600:
                i += 1
            while i > 0 and span / self.BUCKET_STEP[self.BUCKETS[i]] < 6:
                i -= 1
            bucket = self.BUCKETS[i]
            adjusted = bucket != requested
            first = self._bucket_start(bucket, since)
            starts, t = [], first
            while t <= until and len(starts) < 700:
                starts.append(t)
                t = self._bucket_next(bucket, t)
        else:
            n = max(1, min(800, int(count or self.BUCKET_DEFAULT[bucket])))
            cur = self._bucket_start(bucket, now)
            first = self._bucket_next(bucket, cur, -(n - 1))
            starts = [first]
            for _ in range(n - 1):
                starts.append(self._bucket_next(bucket, starts[-1]))
        end_all = self._bucket_next(bucket, starts[-1])
        conn = self.conn()
        try:
            sums = {}
            if bucket == "10m":
                for r in conn.execute("SELECT (ts/600)*600 b, SUM(rx_delta) rx, SUM(tx_delta) tx FROM traffic WHERE ts>=? AND ts<? GROUP BY b",
                                      (starts[0], end_all)):
                    sums[r["b"]] = (r["rx"] or 0, r["tx"] or 0)
                cov = conn.execute("SELECT MIN(ts) FROM traffic").fetchone()[0]
            elif bucket == "1h":
                for r in conn.execute("SELECT ts b, rx_delta rx, tx_delta tx FROM traffic_h WHERE ts>=? AND ts<?", (starts[0], end_all)):
                    sums[r["b"]] = (r["rx"] or 0, r["tx"] or 0)
                for r in conn.execute("SELECT (ts/3600)*3600 b, SUM(rx_delta) rx, SUM(tx_delta) tx FROM traffic WHERE ts>=? AND ts<? GROUP BY b",
                                      (starts[0], end_all)):
                    sums[r["b"]] = (r["rx"] or 0, r["tx"] or 0)       # Rohwerte sind genauer, solange vorhanden
                cov = conn.execute("SELECT MIN(ts) FROM traffic_h").fetchone()[0]
            else:
                d0 = datetime.fromtimestamp(starts[0]).strftime("%Y-%m-%d")
                by_day = {r["day"]: (r["rx"], r["tx"]) for r in conn.execute("SELECT day, rx, tx FROM daily WHERE day>=?", (d0,))}
                idx = {}
                for day, (rx, tx) in by_day.items():
                    b = self._bucket_start(bucket, datetime.strptime(day, "%Y-%m-%d").timestamp() + 43200)
                    a = idx.get(b, (0, 0))
                    idx[b] = (a[0] + rx, a[1] + tx)
                sums = idx
                m = conn.execute("SELECT MIN(day) FROM daily").fetchone()[0]
                cov = int(datetime.strptime(m, "%Y-%m-%d").timestamp()) if m else None
        finally:
            conn.close()
        pts, tot_rx, tot_tx = [], 0, 0
        for i, t in enumerate(starts):
            te = starts[i + 1] if i + 1 < len(starts) else end_all
            rx, tx = sums.get(t, (0, 0))
            tot_rx += rx
            tot_tx += tx
            pts.append({"t": t, "t_end": te, "rx": int(rx), "tx": int(tx), "partial": te > now})
        return {"bucket": bucket, "requested": requested, "adjusted": adjusted, "points": pts, "since": starts[0],
                "until": min(end_all, now), "now": now, "rx": int(tot_rx), "tx": int(tot_tx), "coverage_from": cov}

    # -- SMS ---------------------------------------------------------------------------- #
    def sms_counts(self, conn):
        r = conn.execute("SELECT SUM(box='in' AND read=0) u, SUM(box='in') i, SUM(box='out') o FROM sms WHERE deleted=0").fetchone()
        return int(r["u"] or 0), int(r["i"] or 0), int(r["o"] or 0)

    def sms_status(self):
        conn = self.conn()
        try:
            unread, n_in, n_out = self.sms_counts(conn)
            st = load_settings(conn)["sms"]
            used = conn.execute("SELECT COUNT(*) FROM sms WHERE box='out' AND source!='router' AND created>?", (int(time.time()) - 3600,)).fetchone()[0]
            last_id = conn.execute("SELECT COALESCE(MAX(id),0) FROM sms WHERE box='in' AND deleted=0").fetchone()[0]
        finally:
            conn.close()
        s = self.sms.snapshot() if self.sms else {}
        return {"enabled": st["enabled"], "router_ok": s.get("ok"), "last_sync": s.get("last_sync"), "last_error": s.get("last_error"),
                "can_send": bool(self.collector.router.can_login and st["enabled"]), "unread": unread, "inbox": n_in, "sent": n_out,
                "sent_last_hour": used, "send_limit_per_hour": st["send_limit_per_hour"], "last_inbox_id": last_id,
                "interval_s": st["interval_s"]}

    def sms_list(self, box="inbox", unread=False, number=None, since_id=None, since_ts=None, before_id=None, limit=50,
                 order=None, q=None, mark_read=False, wait=0):
        if wait and since_id is not None and self.sms:
            self.sms.wait_new(since_id, wait)
        conn = self.conn()
        try:
            rows = sms_query(conn, box, unread, number, since_id, since_ts, before_id, limit, order, q)
            if mark_read:
                ids = [r["id"] for r in rows if r["box"] == "in" and not r["read"]]
                if ids:
                    conn.execute(f"UPDATE sms SET read=1 WHERE id IN ({','.join('?' * len(ids))})", ids)
                    conn.commit()
            unread_n, n_in, n_out = self.sms_counts(conn)
            out = []
            for r in rows:
                j = sms_json(r)
                if mark_read and r["box"] == "in":
                    j["read"] = True
                j["plan"] = sms_plan(r["text"])["segments"]
                out.append(j)
            return {"count": len(out), "messages": out, "unread": unread_n,
                    "total_inbox": n_in, "total_sent": n_out, "last_id": max([r["id"] for r in rows], default=None)}
        finally:
            conn.close()

    def sms_get(self, sid):
        conn = self.conn()
        try:
            r = conn.execute("SELECT * FROM sms WHERE id=? AND deleted=0", (int(sid),)).fetchone()
        finally:
            conn.close()
        if not r:
            raise SmsError("SMS nicht gefunden", 404)
        return sms_json(r)

    def sms_send(self, number, text, source="dashboard"):
        if not self.sms:
            raise SmsError("SMS-Dienst nicht aktiv", 503)
        return self.sms.send(number, text, source)

    def sms_preview(self, text):
        return sms_plan(str(text or ""))

    def sms_mark_read(self, ids=None, all_=False, unread=True):
        conn = self.conn()
        try:
            if all_:
                cur = conn.execute("UPDATE sms SET read=? WHERE box='in' AND deleted=0", (0 if not unread else 1,))
            else:
                ids = [int(i) for i in (ids or [])][:500]
                cur = conn.execute(f"UPDATE sms SET read=? WHERE box='in' AND deleted=0 AND id IN ({','.join('?' * len(ids)) or 'NULL'})",
                                   (1 if unread else 0, *ids))
            conn.commit()
            return {"updated": cur.rowcount}
        finally:
            conn.close()

    def sms_delete(self, ids):
        if not self.sms:
            raise SmsError("SMS-Dienst nicht aktiv", 503)
        return self.sms.delete(ids)

    def sms_sync(self):
        if not self.sms:
            raise SmsError("SMS-Dienst nicht aktiv", 503)
        if not self.collector.router.can_login:
            raise SmsError("Router-Passwort fehlt (Einstellungen → Verbindung)", 409)
        try:
            n = self.sms.sync()
        except RouterError as exc:
            self.sms._set(ok=False, last_error=str(exc))
            raise SmsError(f"Router: {exc}", 502)
        return {"imported": n, **self.sms_status()}

    # -- API-Tokens (für Skripte und andere Programme) -------------------------------------- #
    @staticmethod
    def _token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def tokens_list(self):
        conn = self.conn()
        try:
            rows = conn.execute("SELECT * FROM api_tokens ORDER BY id").fetchall()
        finally:
            conn.close()
        return {"tokens": [{"id": r["id"], "name": r["name"], "prefix": r["prefix"], "can_read": bool(r["can_read"]),
                            "can_send": bool(r["can_send"]), "can_delete": bool(r["can_delete"]), "created": r["created"],
                            "last_used": r["last_used"], "uses": r["uses"]} for r in rows]}

    def token_create(self, body):
        name = str(body.get("name") or "").strip()[:40]
        if not name:
            raise ValueError("Bitte einen Namen für den Token angeben (z. B. Home Assistant)")
        perms = body.get("perms") if isinstance(body.get("perms"), list) else ["read"]
        can = {k: 1 if k in perms else 0 for k in ("read", "send", "delete")}
        if not any(can.values()):
            raise ValueError("Mindestens ein Recht auswählen")
        conn = self.conn()
        try:
            if conn.execute("SELECT COUNT(*) FROM api_tokens").fetchone()[0] >= 20:
                raise ValueError("Höchstens 20 Tokens")
            token = "zte_" + secrets.token_urlsafe(30)
            conn.execute("INSERT INTO api_tokens(name,hash,prefix,can_read,can_send,can_delete,created) VALUES(?,?,?,?,?,?,?)",
                         (name, self._token_hash(token), token[:9], can["read"], can["send"], can["delete"], int(time.time())))
            conn.commit()
        finally:
            conn.close()
        return {"token": token, **self.tokens_list()}

    def token_delete(self, body):
        conn = self.conn()
        try:
            conn.execute("DELETE FROM api_tokens WHERE id=?", (int(body.get("id") or 0),))
            conn.commit()
        finally:
            conn.close()
        return self.tokens_list()

    def token_verify(self, token):
        """Gültiger Token -> Zeile (mit Rechten), sonst None. Nutzung wird mitgezählt."""
        if not token or len(token) > 200:
            return None
        conn = self.conn()
        try:
            r = conn.execute("SELECT * FROM api_tokens WHERE hash=?", (self._token_hash(token),)).fetchone()
            if r:
                now = int(time.time())
                conn.execute("UPDATE api_tokens SET uses=uses+1, last_used=? WHERE id=?", (now, r["id"]))
                conn.commit()
            return dict(r) if r else None
        finally:
            conn.close()

    # -- Tagesverbrauch + Prognose ---------------------------------------------------- #
    def daily(self, days, end=None):
        days = max(1, min(800, days))
        conn = self.conn()
        try:
            today = date.today()
            try:
                last_day = min(today, date.fromisoformat(end)) if end else today    # Zoom: Diagramm endet am gewählten Tag
            except ValueError:
                last_day = today
            start = last_day - timedelta(days=days - 1)
            got = {r["day"]: (r["rx"], r["tx"]) for r in
                   conn.execute("SELECT day, rx, tx FROM daily WHERE day>=?", (start.isoformat(),))}
            out = []
            for i in range(days):
                d = (start + timedelta(days=i)).isoformat()
                rx, tx = got.get(d, (0, 0))
                out.append({"day": d, "rx": rx, "tx": tx})
            bs = billing_start(today, self.cfg.billing_day)
            m = conn.execute("SELECT COALESCE(SUM(rx),0) rx, COALESCE(SUM(tx),0) tx FROM daily WHERE day>=?",
                             (bs.isoformat(),)).fetchone()
            nxt = (bs.replace(day=1) + timedelta(days=32)).replace(day=self.cfg.billing_day)
            last = conn.execute("SELECT rx_month, tx_month FROM traffic WHERE rx_month IS NOT NULL "
                                "ORDER BY ts DESC LIMIT 1").fetchone()
            period = {"start": bs.isoformat(), "end": nxt.isoformat(), "rx": m["rx"], "tx": m["tx"], "source": "collector"}
            if last:   # Monatszähler des Routers = Datenverbrauch seit dessen letztem Zurücksetzen
                period.update(rx=int(last["rx_month"]), tx=int(last["tx_month"] or 0), source="router")
            return {"days": out, "period": period, "end": last_day.isoformat(), "limit_gb": self.cfg.limit_gb,
                    "forecast": self.forecast(conn, today, bs, nxt, period["rx"] + period["tx"])}
        finally:
            conn.close()

    def forecast(self, conn, today, bs, nxt, used):
        """Prognose des Verbrauchs zum Periodenende.
        Basis: Durchschnitt der letzten (bis zu 7) vollständigen Tage mit Daten - unabhängig von der Periodengrenze,
        weil sich Nutzungsgewohnheiten nicht am Monatsersten ändern. Heute zählt mindestens den Durchschnitt.
        Mit weniger als 2 Tagen Historie: linear hochgerechnet wie vnStat (bisher / vergangene Zeit x Periodenlänge)."""
        total_days = (nxt - bs).days
        now = datetime.now()
        frac_today = (now.hour * 3600 + now.minute * 60 + now.second) / 86400
        full_days_left = max(0, (nxt - today).days - 1)
        elapsed = max(0.25, (today - bs).days + frac_today)
        today_row = conn.execute("SELECT rx+tx FROM daily WHERE day=?", (today.isoformat(),)).fetchone()
        today_used = today_row[0] if today_row else 0
        past = [r[0] for r in conn.execute(
            "SELECT rx+tx FROM daily WHERE day<? AND day>=? AND rx+tx>0 ORDER BY day DESC LIMIT 7",
            (today.isoformat(), (today - timedelta(days=21)).isoformat()))]
        used_before_today = max(0, used - today_used)
        linear = used / elapsed * total_days if used else 0
        if len(past) >= 2:
            vals = sorted(past)
            avg = sum(past) / len(past)
            lo, hi = quantile(vals, 0.25), quantile(vals, 0.75)
            basis, quality = f"Ø der letzten {len(past)} Tage", ("gut" if len(past) >= 5 else "mittel")
        else:
            avg = used / elapsed
            lo, hi = avg * 0.8, avg * 1.25
            basis, quality = "linear hochgerechnet (noch wenig Verlauf)", "grob"

        def est(per_day):
            return used_before_today + max(today_used, per_day) + per_day * full_days_left
        mid, low, high = est(avg), est(min(lo, avg)), est(max(hi, avg))
        res = {"period_start": bs.isoformat(), "period_end": nxt.isoformat(), "total_days": total_days,
               "elapsed_days": round(elapsed, 2), "used": used, "today": today_used, "avg_per_day": avg,
               "estimate": mid, "low": low, "high": high, "linear": linear, "basis": basis, "quality": quality,
               "basis_days": len(past), "limit_reached_on": None}
        lim = self.cfg.limit_gb * 1e9
        if lim > 0 and avg > 0:
            if used >= lim:
                res["limit_reached_on"] = today.isoformat()
            elif mid > lim:
                days_needed = (lim - used) / avg
                res["limit_reached_on"] = (today + timedelta(days=int(days_needed))).isoformat()
        return res

    # -- Einstellungen ---------------------------------------------------------------- #
    def get_settings(self):
        conn = self.conn()
        try:
            st = load_settings(conn)
            sec = load_secrets(conn)
        finally:
            conn.close()
        c = self.cfg
        st["general"] = {"host": c.host, "poll_s": c.poll, "usage_s": c.usage_s, "raw_days": c.raw_days,
                         "limit_gb": c.limit_gb, "billing_day": c.billing_day, "ui_refresh_s": c.ui_refresh}
        r = self.collector.router
        return {"settings": st,
                "router": {"password_set": bool(c.password), "password_source": "ui" if sec.get("router_password") else ("env" if c.password else None),
                           "login_state": r.login_state, "login_error": r.login_error},
                "security": {"enabled": bool(self.auth and self.auth.enabled), "session_days": self.auth.session_days if self.auth else 30},
                "defaults": {k: v for k, v in c.defaults.items() if k != "password"},
                "capabilities": {"icmp": ICMP_STATE["ok"], "reconnect": r.can_login, "platform": sys.platform}}

    def save_settings(self, body):
        if "sms" not in body:                        # ältere Oberfläche: SMS-Einstellungen unverändert lassen
            conn0 = self.conn()
            try:
                body = {**body, "sms": load_settings(conn0)["sms"]}
            finally:
                conn0.close()
        clean = sanitize_settings(body, strict=True)
        pw = body.get("router_password")
        conn = self.conn()
        try:
            kv_set(conn, "settings", clean)
            sec = load_secrets(conn)
            if body.get("clear_router_password"):
                sec.pop("router_password", None)
            elif isinstance(pw, str) and pw:
                if len(pw) > 200:
                    raise ValueError("Router-Passwort zu lang")
                sec["router_password"] = pw
            kv_set(conn, "secrets", sec)
            conn.commit()
        finally:
            conn.close()
        apply_runtime(self.cfg, clean, sec, self.collector, self.monitor)
        return self.get_settings()

    def security(self, body, client_ip="?"):
        """Dashboard-Passwort setzen/ändern/abschalten. Bei aktivem Schutz ist immer das aktuelle Passwort nötig."""
        a = self.auth
        action = body.get("action")
        if a.enabled:
            wait = a.wait_time(client_ip)
            if wait:
                raise ValueError(f"Zu viele Fehlversuche - bitte {wait} s warten")
            ok = a.verify(body.get("current") or "")
            a.record(client_ip, ok)
            if not ok:
                raise ValueError("Das aktuelle Passwort ist falsch")
        if action == "set":
            a.set_password(body.get("password") or "", body.get("session_days"))
        elif action == "disable":
            a.disable()
        elif action == "days":
            a.set_session_days(body.get("session_days"))
        else:
            raise ValueError("Unbekannte Aktion")
        return {"enabled": a.enabled, "session_days": a.session_days}

    def test_router(self, body):
        """Verbindungstest mit den eingegebenen (oder gespeicherten) Zugangsdaten - ohne sie zu speichern."""
        now = time.time()
        if now - self._last_test < 8:
            raise ValueError("Bitte kurz warten - der Test darf höchstens alle 8 Sekunden laufen")
        self._last_test = now
        host = clean_host(body.get("host")) or self.cfg.host
        pw = body.get("password") or self.cfg.password
        r = Router(SimpleNamespace(host=host, password=pw, session="", login_mode=self.cfg.login_mode))
        steps = []

        def step(name, fn):
            t0 = time.time()
            try:
                detail = fn()
                steps.append({"name": name, "ok": True, "detail": detail or "", "ms": int((time.time() - t0) * 1000)})
                return True
            except RouterError as exc:
                steps.append({"name": name, "ok": False, "detail": str(exc), "ms": int((time.time() - t0) * 1000)})
                return False
        if not step("Router erreichbar", lambda: (r.call("zwrt_web", "web_login_info") and "Login-Seite antwortet")):
            return {"ok": False, "steps": steps}
        step("Signalwerte (ohne Login)", lambda: (lambda d: f"{d.get('network_type') or '?'} · RSRP {d.get('nr5g_rsrp') or d.get('lte_rsrp') or '–'} dBm")(r.netinfo()))
        if not pw:
            steps.append({"name": "Anmeldung", "ok": None, "detail": "kein Passwort angegeben - Datenverbrauch und Neustart sind so nicht möglich", "ms": 0})
            return {"ok": all(x["ok"] for x in steps if x["ok"] is not None), "steps": steps}
        if step("Anmeldung", lambda: (r.login() or "Passwort akzeptiert")):
            step("Datenverbrauch", lambda: (lambda u: f"Monatszähler {fmt_bytes(parse_usage(u)['rx_month'])}")(r.usage()))
        return {"ok": all(x["ok"] for x in steps if x["ok"] is not None), "steps": steps}

    # -- Setup-Seite: Live-Feed und Standortmessungen -------------------------------------- #
    def live(self, since=0):
        return self.live_feed.poll(since)

    def spots(self):
        conn = self.conn()
        try:
            rows = conn.execute("SELECT * FROM spots ORDER BY rank_score DESC, ts DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["label"] = LEVEL_LABELS.get(d.get("level"), "")
                try:
                    d["series"] = json.loads(d["series"] or "[]")
                except ValueError:
                    d["series"] = []
                out.append(d)
            return {"spots": out}
        finally:
            conn.close()

    def add_spot(self, body):
        name = str(body.get("name") or "").strip()[:60]
        if not name:
            raise ValueError("Bitte einen Namen für den Standort angeben")
        note = str(body.get("note") or "").strip()[:200]
        smp = [x for x in (body.get("samples") or [])[:1500] if isinstance(x, dict) and num(x.get("rsrp")) is not None]
        if len(smp) < 5:
            raise ValueError("Zu wenige Messwerte (mindestens 5 nötig)")
        col = lambda k: [float(x[k]) for x in smp if num(x.get(k)) is not None]
        mean = lambda v: sum(v) / len(v) if v else None
        std = lambda v: math.sqrt(sum((a - sum(v) / len(v)) ** 2 for a in v) / len(v)) if len(v) > 1 else 0.0
        rsrp, snr, rsrq, rssi = col("rsrp"), col("snr"), col("rsrq"), col("rssi")
        scores = [r["score"] for r in (rate(num(x.get("rsrp")), num(x.get("snr")), num(x.get("rsrq"))) for x in smp) if r]
        m_score, sd_score = mean(scores), std(scores)
        rank = max(0.0, min(100.0, m_score - 0.5 * sd_score))      # Schwankung kostet Punkte: ein stabiler Ort schlägt einen wechselhaften
        lid, _ = level_for(rank)
        mr = rate(mean(rsrp), mean(snr), mean(rsrq))
        common = lambda k: Counter(x.get(k) for x in smp if x.get(k) not in (None, "")).most_common(1)
        net, band, pci = common("net"), common("band"), common("pci")
        step = max(1, len(smp) // 90)
        series = []
        for x in smp[::step]:
            rt = rate(num(x.get("rsrp")), num(x.get("snr")), num(x.get("rsrq")))
            series.append([round(float(x["rsrp"]), 1), None if num(x.get("snr")) is None else round(float(x["snr"]), 1),
                           rt["score"] if rt else None])
        conn = self.conn()
        try:
            cur = conn.execute(
                "INSERT INTO spots(ts,name,note,duration,n,net,band,pci,bw,rsrp,rsrq,snr,rssi,rsrp_std,snr_std,score,rank_score,level,limiting,stability,series) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (int(time.time()), name, note, _int(body.get("duration"), 5, 600, len(smp)), len(smp),
                 net[0][0] if net else "", band[0][0] if band else "", _int(pci[0][0], 0, 10 ** 9, None) if pci else None,
                 _int(common("bw")[0][0], 0, 1000, None) if common("bw") else None,
                 mean(rsrp), mean(rsrq), mean(snr), mean(rssi), std(rsrp), std(snr),
                 round(m_score, 1), round(rank, 1), lid, mr["limiting"] if mr else None,
                 stability_label(std(rsrp), std(snr)), json.dumps(series)))
            conn.commit()
            spot_id = cur.lastrowid
        finally:
            conn.close()
        return {"id": spot_id, **self.spots()}

    def delete_spot(self, body):
        conn = self.conn()
        try:
            if body.get("all"):
                conn.execute("DELETE FROM spots")
            else:
                conn.execute("DELETE FROM spots WHERE id=?", (_int(body.get("id"), 1, 2 ** 62, 0),))
            conn.commit()
        finally:
            conn.close()
        return self.spots()

    # -- Tageszeit-Auswertung -------------------------------------------------------------- #
    def hourofday(self, rng):
        """Werte nach Uhrzeit (0-23 Uhr, Ortszeit) und als Wochentag x Stunde. Grundlage sind die Stundenwerte,
        die dauerhaft gespeichert werden - der Zeitraum ist daher nicht auf die Rohdaten-Dauer begrenzt."""
        secs = RANGES.get(rng, RANGES["30d"])
        now = int(time.time())
        since = (now - secs) // HOUR * HOUR
        conn = self.conn()
        try:
            settings = load_settings(conn)
            names = [target_label(t) for t in settings["ping"]["targets"]]
            metrics = {}

            def metric(key, label, unit, decimals, better, kind="avg"):
                metrics[key] = {"id": key, "label": label, "unit": unit, "decimals": decimals, "better": better, "kind": kind,
                                "rows": [[] for _ in range(24)], "cell": {}}
                return metrics[key]

            def add(m, ts, value, weight=1.0):
                if value is None:
                    return
                dt = datetime.fromtimestamp(ts)
                m["rows"][dt.hour].append((value, weight))
                c = m["cell"].setdefault((dt.weekday(), dt.hour), [0.0, 0.0])
                c[0] += value * weight
                c[1] += weight
            mr = metric("rsrp", "Signalstärke (RSRP)", "dBm", 1, "high")
            ms = metric("snr", "Signalrauschabstand (SINR)", "dB", 1, "high")
            mq = metric("score", "Empfangsbewertung", "Punkte", 0, "high")
            ml = metric("latency", "Latenz", "ms", 1, "low")
            mp = metric("loss", "Paketverlust", "%", 2, "low")
            mv = metric("volume", "Datenverbrauch je Stunde", "MB", 0, None)
            mo = metric("outage", "Ausfallzeit (Summe)", "min", 1, "low", kind="sum")
            days = set()
            for r in conn.execute("SELECT ts, n, COALESCE(nr_rsrp, lte_rsrp), COALESCE(nr_snr, lte_snr), COALESCE(nr_rsrq, lte_rsrq) "
                                  "FROM samples_h WHERE ts>=? AND n>0", (since,)):
                ts, n, rsrp, snr, rsrq = r
                days.add(datetime.fromtimestamp(ts).date())
                add(mr, ts, rsrp, n)
                add(ms, ts, snr, n)
                sc = rate(rsrp, snr, rsrq)
                add(mq, ts, sc["score"] if sc else None, n)
            if names:
                ph = ",".join("?" * len(names))
                for ts, rn, rsum, tot, lost in conn.execute(
                        f"SELECT ts, SUM(rtt_n), SUM(rtt_sum), SUM(n), SUM(lost) FROM pings_h WHERE ts>=? AND target IN ({ph}) GROUP BY ts",
                        (since, *names)):
                    if rn:
                        add(ml, ts, rsum / rn, rn)
                    if tot:
                        add(mp, ts, 100.0 * (lost or 0) / tot, tot)
            for ts, rx, tx in conn.execute("SELECT ts, rx_delta, tx_delta FROM traffic_h WHERE ts>=?", (since,)):
                add(mv, ts, ((rx or 0) + (tx or 0)) / 1e6)
            # Ausfälle auf Ortszeit-Stunden verteilen
            tot_out = {}
            for o in conn.execute("SELECT start, end FROM outages WHERE COALESCE(end, ?)>=?", (now, since)).fetchall():
                a, b = max(o["start"], since), o["end"] or now
                while a < b:
                    dt = datetime.fromtimestamp(a)
                    nxt = int((dt.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)).timestamp())
                    seg = min(b, nxt) - a
                    key = (dt.weekday(), dt.hour)
                    tot_out[key] = tot_out.get(key, 0) + seg / 60.0
                    a += seg
            out = {}
            for key, m in metrics.items():
                if key == "outage":
                    by_hour = [{"h": h, "v": round(sum(v for (wd, hh), v in tot_out.items() if hh == h), 2), "n": len(days)} for h in range(24)]
                    grid = [[round(tot_out[(wd, h)], 2) if (wd, h) in tot_out else 0 for h in range(24)] for wd in range(7)]
                    out[key] = {k: m[k] for k in ("id", "label", "unit", "decimals", "better", "kind")}
                    out[key].update(by_hour=by_hour, grid=grid, best=None, worst=None)
                    continue
                by_hour, dec = [], 3
                for h in range(24):
                    rows = m["rows"][h]
                    if not rows:
                        by_hour.append({"h": h, "v": None, "n": 0})
                        continue
                    w = sum(x[1] for x in rows)
                    vals = sorted(x[0] for x in rows)
                    by_hour.append({"h": h, "v": round(sum(x[0] * x[1] for x in rows) / w, dec), "n": len(rows),
                                    "p25": round(quantile(vals, .25), dec), "p75": round(quantile(vals, .75), dec),
                                    "min": round(vals[0], dec), "max": round(vals[-1], dec)})
                grid = [[round(m["cell"][(wd, h)][0] / m["cell"][(wd, h)][1], dec) if (wd, h) in m["cell"] and m["cell"][(wd, h)][1] else None
                         for h in range(24)] for wd in range(7)]
                best = worst = None
                cand = [x for x in by_hour if x["v"] is not None and x["n"] >= (2 if len(days) >= 3 else 1)]
                if m["better"] and len(cand) >= 3:
                    pick_ = (max if m["better"] == "high" else min)
                    best = pick_(cand, key=lambda x: x["v"])["h"]
                    worst = (min if m["better"] == "high" else max)(cand, key=lambda x: x["v"])["h"]
                out[key] = {k: m[k] for k in ("id", "label", "unit", "decimals", "better", "kind")}
                out[key].update(by_hour=by_hour, grid=grid, best=best, worst=worst)
            return {"range": rng, "since": since, "now": now, "days": len(days), "metrics": out}
        finally:
            conn.close()

    def manual_reconnect(self):
        if not self.monitor:
            raise ValueError("Monitor nicht aktiv")
        if not self.collector.router.can_login:
            raise ValueError("Für den Neustart wird das Router-Passwort benötigt (ZTE_PASSWORD)")
        conn = self.conn()
        try:
            grace = load_settings(conn)["watchdog"]["grace_s"]
        finally:
            conn.close()
        if not self.monitor.start_reconnect("manuell ausgelöst", dry_run=False, grace_s=grace):
            raise ValueError("Es läuft bereits ein Neustart")
        return {"started": True}

    def export_csv(self, rng, kind="signal", t_from=None, t_to=None):
        since, until, _, _ = self.window(rng, t_from, t_to)
        conn = self.conn()
        try:
            if kind == "ping":
                names = [target_label(t) for t in load_settings(conn)["ping"]["targets"]]
                rows = conn.execute(f"SELECT * FROM pings WHERE ts>=? AND ts<=? AND target IN ({','.join('?' * len(names)) or chr(39) * 2}) ORDER BY ts",
                                    (since, until, *names)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM samples WHERE ts>=? AND ts<=? ORDER BY ts", (since, until)).fetchall()
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(rows[0].keys() if rows else ["ts"])
            for r in rows:
                w.writerow(list(r))
            return buf.getvalue()
        finally:
            conn.close()


class Handler(BaseHTTPRequestHandler):
    api = None
    cfg = None
    auth = None
    server_version = "zte-dash"
    PUBLIC = {"/login", "/api/login", "/api/auth", "/healthz"}

    def log_message(self, fmt, *args):  # ruhig
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _send(self, code, body, ctype="application/json; charset=utf-8", extra=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj, extra=None):
        return self._send(code, json.dumps(obj), extra=extra)

    # -- Anmeldung -------------------------------------------------------------- #
    def _ip(self):
        return self.client_address[0]

    def _authed(self):
        a = self.auth
        if not a.enabled:
            return True
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == a.COOKIE:
                return a.valid(v)
        return False

    def _cookie(self, on=True):
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        if not on:
            return {"Set-Cookie": f"{self.auth.COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"}
        return {"Set-Cookie": f"{self.auth.COOKIE}={self.auth.token()}; Path=/; HttpOnly; SameSite=Strict; "
                              f"Max-Age={self.auth.session_days * 86400}{secure}"}

    def _gate(self, path):
        """True = weiter, False = Antwort (Login-Seite bzw. 401) wurde schon gesendet."""
        if path in self.PUBLIC or self._authed():
            return True
        if path.startswith("/api/"):
            self._json(401, {"error": "Anmeldung erforderlich", "login": True})
        else:
            self._send(302, "", "text/plain", {"Location": "/login"})
        return False

    @staticmethod
    def _opt_int(q, key):
        try:
            return int(float(q[key][0]))
        except (KeyError, ValueError, IndexError):
            return None

    # -- SMS-API mit Token (/api/v1/...) -------------------------------------------------- #
    def _bearer(self):
        h = self.headers.get("Authorization") or ""
        return h[7:].strip() if h.lower().startswith("bearer ") else (self.headers.get("X-API-Key") or "").strip()

    @staticmethod
    def _truthy(v):
        return str(v).strip().lower() in ("1", "true", "yes", "on", "ja")

    def _sms_args(self, q):
        one = lambda k, d=None: (q.get(k) or [d])[0]
        order = one("order")
        return dict(box=one("box", "inbox"), unread=self._truthy(one("unread", "0")), number=one("number") or None,
                    since_id=self._opt_int(q, "since_id"), since_ts=self._opt_int(q, "since"), before_id=self._opt_int(q, "before_id"),
                    limit=self._opt_int(q, "limit") or 50, order=order if order in ("asc", "desc") else None, q=one("q") or None,
                    mark_read=self._truthy(one("mark_read", "0")), wait=self._opt_int(q, "wait") or 0)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            raise ValueError("zu groß")
        raw = self.rfile.read(length) if length else b""
        if "application/x-www-form-urlencoded" in (self.headers.get("Content-Type") or ""):
            return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
        body = json.loads(raw or b"{}")
        if not isinstance(body, dict):
            raise ValueError("Ungültige Anfrage: JSON-Objekt erwartet")
        return body

    def _v1(self, method, url, q):
        """Token-geschützte SMS-Schnittstelle für Skripte und andere Programme."""
        key = "api|" + self._ip()
        wait = self.auth.wait_time(key)
        if wait:
            return self._json(429, {"error": f"Zu viele ungültige Tokens - bitte {wait} s warten", "retry_after": wait})
        tok = self.api.token_verify(self._bearer())
        self.auth.record(key, tok is not None)
        if not tok:
            time.sleep(0.3)
            return self._json(401, {"error": "Ungültiger oder fehlender API-Token. Header: Authorization: Bearer <token>"})
        def need(perm):
            if not tok["can_" + perm]:
                raise SmsError(f"Dem Token fehlt das Recht '{perm}'", 403)
        parts = [x for x in url.path[len("/api/v1"):].split("/") if x]
        who = f"api:{tok['name']}"
        body = self._read_body() if method in ("POST", "PUT") else {}
        if parts == ["status"] and method == "GET":
            return self._json(200, self.api.sms_status())
        if parts[:1] == ["sms"]:
            if len(parts) == 1 and method == "GET":
                need("read")
                if self._truthy((q.get("refresh") or ["0"])[0]):
                    try:
                        self.api.sms_sync()
                    except SmsError:
                        pass                       # dann eben mit dem Stand vom letzten Abruf antworten
                return self._json(200, self.api.sms_list(**self._sms_args(q)))
            if (parts == ["sms"] or parts == ["sms", "send"]) and method == "POST":
                need("send")
                res = self.api.sms_send(body.get("to") or body.get("number"), body.get("text") or body.get("message"), who)
                return self._json(200, {"ok": True, "message": res})
            if parts == ["sms", "read"] and method == "POST":
                need("read")
                return self._json(200, self.api.sms_mark_read(body.get("ids"), self._truthy(body.get("all", False))))
            if parts == ["sms", "delete"] and method == "POST":
                need("delete")
                return self._json(200, self.api.sms_delete(body.get("ids") or []))
            if len(parts) >= 2 and parts[1].isdigit():
                sid = int(parts[1])
                if len(parts) == 2 and method == "GET":
                    need("read")
                    return self._json(200, self.api.sms_get(sid))
                if len(parts) == 2 and method == "DELETE" or (len(parts) == 3 and parts[2] == "delete" and method == "POST"):
                    need("delete")
                    self.api.sms_get(sid)
                    return self._json(200, self.api.sms_delete([sid]))
                if len(parts) == 3 and parts[2] == "read" and method == "POST":
                    need("read")
                    self.api.sms_get(sid)
                    return self._json(200, self.api.sms_mark_read([sid]))
        return self._json(404, {"error": "Unbekannter Endpunkt. Beschreibung: Dashboard → SMS → API"})

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        q = parse_qs(url.query)
        rng = q.get("range", ["24h"])[0]
        t_from, t_to = self._opt_int(q, "from"), self._opt_int(q, "to")
        try:
            if url.path == "/api/v1" or url.path.startswith("/api/v1/"):
                return self._v1("GET", url, q)
            if not self._gate(url.path):
                return
            if url.path == "/login":
                if self._authed():
                    return self._send(302, "", "text/plain", {"Location": "/"})
                return self._send(200, (self.cfg.static_dir / "login.html").read_bytes(), "text/html; charset=utf-8")
            if url.path in ("/", "/index.html"):
                return self._send(200, (self.cfg.static_dir / "index.html").read_bytes(), "text/html; charset=utf-8")
            if url.path == "/api/auth":
                return self._json(200, {"enabled": self.auth.enabled, "authenticated": self._authed()})
            if url.path == "/api/current":
                return self._json(200, self.api.current())
            if url.path == "/api/history":
                return self._json(200, self.api.history(rng, t_from, t_to))
            if url.path == "/api/ping":
                return self._json(200, self.api.ping(rng, t_from, t_to))
            if url.path == "/api/daily":
                return self._json(200, self.api.daily(int(q.get("days", ["30"])[0]), q.get("end", [None])[0]))
            if url.path == "/api/hourofday":
                return self._json(200, self.api.hourofday(rng if rng in RANGES else "30d"))
            if url.path == "/api/live":
                return self._json(200, self.api.live(self._opt_int(q, "since") or 0))
            if url.path == "/api/spots":
                return self._json(200, self.api.spots())
            if url.path == "/api/usage_series":
                bucket = q.get("bucket", ["1d"])[0]
                return self._json(200, self.api.usage_series(bucket, self._opt_int(q, "count"), t_from, t_to))
            if url.path == "/api/sms":
                return self._json(200, {**self.api.sms_list(**{**self._sms_args(q), "wait": 0}), "status": self.api.sms_status()})
            if url.path == "/api/sms/status":
                return self._json(200, self.api.sms_status())
            if url.path == "/api/sms/tokens":
                return self._json(200, self.api.tokens_list())
            if url.path == "/api/settings":
                return self._json(200, self.api.get_settings())
            if url.path == "/api/export.csv":
                kind = q.get("kind", ["signal"])[0]
                return self._send(200, self.api.export_csv(rng, kind, t_from, t_to), "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="zte-{kind}-{"zoom" if t_from else rng}.csv"'})
            if url.path == "/healthz":
                return self._send(200, "ok", "text/plain")
            return self._json(404, {"error": "not found"})
        except SmsError as exc:
            return self._json(exc.code, {"error": str(exc)})
        except (ValueError, FileNotFoundError) as exc:
            return self._json(400, {"error": str(exc)})
        except Exception:  # noqa: BLE001
            log.exception("API-Fehler bei %s", self.path)
            return self._json(500, {"error": "internal error"})

    def do_POST(self):  # noqa: N802
        url = urlparse(self.path)
        if url.path.startswith("/api/v1/"):           # Token-Schnittstelle: kein Cookie, daher kein CSRF-Header nötig
            try:
                return self._v1("POST", url, parse_qs(url.query))
            except SmsError as exc:
                return self._json(exc.code, {"error": str(exc)})
            except (ValueError, KeyError) as exc:
                return self._json(400, {"error": str(exc)})
            except Exception:  # noqa: BLE001
                log.exception("API-Fehler bei %s", self.path)
                return self._json(500, {"error": "internal error"})
        # Schutz vor Aufrufen aus fremden Webseiten (CSRF): der eigene Header löst bei fremden Origins einen Preflight aus
        if self.headers.get("X-Requested-With") != "zte-dash":
            return self._json(403, {"error": "forbidden"})
        try:
            if not self._gate(url.path):
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 1_000_000:
                return self._json(413, {"error": "zu groß"})
            body = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(body, dict):
                raise ValueError("Ungültige Anfrage")
            path = url.path
            if path == "/api/login":
                ip = self._ip()
                wait = self.auth.wait_time(ip)
                if wait:
                    return self._json(429, {"error": f"Zu viele Fehlversuche - bitte {wait} s warten", "retry_after": wait})
                ok = self.auth.enabled and self.auth.verify(str(body.get("password") or ""))
                self.auth.record(ip, ok)
                if not ok:
                    time.sleep(0.4)
                    return self._json(401, {"error": "Passwort falsch"})
                return self._json(200, {"ok": True}, self._cookie())
            if path == "/api/logout":
                return self._json(200, {"ok": True}, self._cookie(False))
            if path == "/api/security":
                res = self.api.security(body, self._ip())
                return self._json(200, res, self._cookie(res["enabled"]))
            if path == "/api/settings":
                return self._json(200, self.api.save_settings(body))
            if path == "/api/test-router":
                return self._json(200, self.api.test_router(body))
            if path == "/api/reconnect":
                return self._json(200, self.api.manual_reconnect())
            if path == "/api/spots":
                return self._json(200, self.api.add_spot(body))
            if path == "/api/spots/delete":
                return self._json(200, self.api.delete_spot(body))
            if path == "/api/sms/send":
                return self._json(200, {"ok": True, "message": self.api.sms_send(body.get("number"), body.get("text"), "dashboard")})
            if path == "/api/sms/read":
                return self._json(200, {**self.api.sms_mark_read(body.get("ids"), bool(body.get("all")), body.get("read", True) is not False),
                                        "status": self.api.sms_status()})
            if path == "/api/sms/delete":
                return self._json(200, {**self.api.sms_delete(body.get("ids") or []), "status": self.api.sms_status()})
            if path == "/api/sms/sync":
                return self._json(200, self.api.sms_sync())
            if path == "/api/sms/tokens":
                return self._json(200, self.api.token_create(body))
            if path == "/api/sms/tokens/delete":
                return self._json(200, self.api.token_delete(body))
            return self._json(404, {"error": "not found"})
        except SmsError as exc:
            return self._json(exc.code, {"error": str(exc)})
        except (ValueError, KeyError) as exc:
            return self._json(400, {"error": str(exc)})
        except Exception:  # noqa: BLE001
            log.exception("API-Fehler bei %s", self.path)
            return self._json(500, {"error": "internal error"})

    def do_DELETE(self):  # noqa: N802
        url = urlparse(self.path)
        try:
            if url.path.startswith("/api/v1/"):
                return self._v1("DELETE", url, parse_qs(url.query))
            return self._json(404, {"error": "not found"})
        except SmsError as exc:
            return self._json(exc.code, {"error": str(exc)})
        except (ValueError, KeyError) as exc:
            return self._json(400, {"error": str(exc)})
        except Exception:  # noqa: BLE001
            log.exception("API-Fehler bei %s", self.path)
            return self._json(500, {"error": "internal error"})


# --------------------------------------------------------------------------- #
# Diagnose
# --------------------------------------------------------------------------- #
def probe(cfg):
    """Loggt sich ein und zeigt, was der Router liefert (nur Schlüssel + Zähler, keine Passwörter)."""
    r = Router(cfg)
    print(f"Router: {cfg.host}")
    info = r.call("zwrt_web", "web_login_info")
    print("web_login_info:", {k: ("<%d Zeichen>" % len(str(v)) if k == "zte_web_sault" else v) for k, v in info.items()})
    net = r.netinfo()
    print("netinfo (ohne Login): Netz =", net.get("network_type"), "| Netzwerkmodus =", net.get("net_select"),
          "| NR-RSRP =", net.get("nr5g_rsrp"), "| LTE-RSRP =", net.get("lte_rsrp"))
    print(f"ping-Programm: {'gefunden' if ICMP_STATE['ok'] else 'NICHT gefunden (TCP-Ping wird verwendet)'}")
    if not r.can_login:
        print("Kein ZTE_PASSWORD gesetzt -> Datenverbrauch nicht abrufbar.")
        return
    r.login()
    print("Login OK")
    for args in Router.USAGE_ARGS[:2]:
        try:
            data = r.call("zwrt_data", "get_wwandst", args, sid=r.sid)
            print(f"get_wwandst{json.dumps(args)} -> {len(data)} Felder, month_rx_bytes={data.get('month_rx_bytes')}")
        except RouterError as exc:
            print(f"get_wwandst{json.dumps(args)} -> FEHLER: {exc}")
    for obj, meth, args in (("zwrt_data", "get_wwandst_clearday", {"source_module": "web", "cid": 1}),
                            ("zwrt_data", "get_wwaniface", {"source_module": "web", "cid": 1})):
        try:
            print(f"{meth} ->", json.dumps(r.call(obj, meth, args, sid=r.sid)))
        except RouterError as exc:
            print(f"{meth} -> FEHLER: {exc}")


def probe_sms(cfg):
    """Diagnose der SMS-Schnittstelle: zeigt Methoden und Aufbau der Antworten (ohne Nachrichtentexte)."""
    r = Router(cfg)
    if not r.can_login:
        print("Kein Router-Passwort gesetzt (ZTE_PASSWORD oder Dashboard-Einstellungen).")
        return 1
    r.login()
    print("Login OK")
    try:
        print("zwrt_wms Methoden:", json.dumps(r.list_methods("zwrt_wms")))
    except RouterError as exc:
        print("zwrt_wms list -> FEHLER:", exc)
    for meth, args in (("zwrt_wms_get_wms_capacity", {}), ("zwrt_get_wms_nvitems", {})):
        try:
            print(f"{meth} ->", json.dumps(r.call("zwrt_wms", meth, args, sid=r.sid))[:400])
        except RouterError as exc:
            print(f"{meth} -> FEHLER: {exc}")
    try:
        d = r.call("zwrt_wms", "zte_libwms_get_sms_data",
                   {"page": 0, "data_per_page": 500, "mem_store": 1, "tags": 10, "order_by": "order by id desc"}, sid=r.sid)
        print("zte_libwms_get_sms_data -> Schlüssel:", list(d.keys()))
        msgs = next((d[k] for k in ("messages", "messages_data", "sms_data") if isinstance(d.get(k), list)), [])
        print(f"{len(msgs)} Nachrichten; Tags:", dict(Counter(str(m.get('tag')) for m in msgs)))
        for m in msgs[:3]:
            print("  Felder:", {k: (f"<{len(str(v))} Zeichen>" if k in ("content", "number") else v) for k, v in m.items()})
            print("  Datum roh:", m.get("date"), "->", parse_sms_date(m.get("date"), None))
    except RouterError as exc:
        print("zte_libwms_get_sms_data -> FEHLER:", exc)
    return 0


def test_reconnect(cfg):
    r = Router(cfg)
    if not r.can_login:
        print("Für den Reconnect wird ZTE_PASSWORD benötigt.")
        return 1
    print("Achtung: Die Mobilfunkverbindung wird jetzt für ca. 10-60 Sekunden unterbrochen.")
    print("Dafür wird der Netzwerkmodus des Routers kurz auf 'Only_LTE' umgestellt und danach wieder zurückgesetzt.")
    if input("Fortfahren? [j/N] ").strip().lower() not in ("j", "ja", "y", "yes"):
        print("Abgebrochen.")
        return 0
    res = perform_reconnect(r, grace_s=90, progress=print)
    print("Ergebnis:", "OK" if res["ok"] else "FEHLER", "-", res["detail"])
    return 0 if res["ok"] else 2


def main():
    ap = argparse.ArgumentParser(description="ZTE G5TS Dashboard")
    ap.add_argument("--probe", action="store_true", help="Router-Antworten anzeigen (Diagnose)")
    ap.add_argument("--once", action="store_true", help="Einmal abfragen, speichern, ausgeben, beenden")
    ap.add_argument("--probe-sms", action="store_true", help="SMS-Schnittstelle des Routers prüfen (Diagnose)")
    ap.add_argument("--test-reconnect", action="store_true", help="Verbindung einmalig neu aufbauen (mit Rückfrage)")
    ap.add_argument("--reset-auth", action="store_true", help="Dashboard-Passwortschutz abschalten (falls das Passwort vergessen wurde)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg = Config()
    if args.reset_auth:
        init_db(cfg.db)
        Auth(cfg.db).disable()
        print("Der Passwortschutz des Dashboards ist abgeschaltet. Beim nächsten Start kann in den Einstellungen ein neues Passwort gesetzt werden.")
        return
    load_runtime(cfg)                # im Dashboard gespeicherte Einstellungen (Router-Passwort, Intervalle ...) haben Vorrang
    if args.probe:
        try:
            probe(cfg)
        except RouterError as exc:
            print("FEHLER:", exc)
            sys.exit(1)
        return
    if args.probe_sms:
        try:
            sys.exit(probe_sms(cfg))
        except RouterError as exc:
            print("FEHLER:", exc)
            sys.exit(1)
    if args.test_reconnect:
        sys.exit(test_reconnect(cfg))
    init_db(cfg.db)
    auth = Auth(cfg.db)
    if cfg.dash_password and not auth.enabled and not auth.a:
        try:
            auth.set_password(cfg.dash_password)
            log.info("Dashboard-Passwortschutz aus ZTE_DASH_PASSWORD eingerichtet")
        except ValueError as exc:
            log.error("ZTE_DASH_PASSWORD ungültig: %s", exc)
    collector = Collector(cfg)
    conn = connect(cfg.db)
    collector.maintenance(conn, startup=True)
    conn.close()
    if args.once:
        collector.poll_once()
        print(json.dumps(Api(cfg, collector).current(), indent=2))
        return
    monitor = Monitor(cfg, collector)
    sms = SmsService(cfg, collector)
    collector.sms = sms
    collector.start()
    monitor.start()
    sms.start()
    Handler.api, Handler.cfg, Handler.auth = Api(cfg, collector, monitor, auth, sms), cfg, auth
    httpd = ThreadingHTTPServer((cfg.bind, cfg.port), Handler)
    log.info("Dashboard auf http://%s:%d  (Router: %s, Intervall: %ds, Router-Login: %s, Dashboard-Passwort: %s)", cfg.bind, cfg.port,
             cfg.host, cfg.poll, "ja" if collector.router.can_login else "nein - nur Signalwerte", "ja" if auth.enabled else "nein")
    if not auth.enabled and cfg.bind not in ("127.0.0.1", "localhost", "::1"):
        log.info("Hinweis: Das Dashboard ist ohne Passwort für jedes Gerät im Netzwerk erreichbar. "
                 "Ein Passwort lässt sich unter Einstellungen → Sicherheit setzen.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for t in (collector, monitor, sms):
            t.stop_flag.set()
            t.wake.set()


if __name__ == "__main__":
    main()
