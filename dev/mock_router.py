#!/usr/bin/env python3
"""
Mock-Router zum Testen ohne echten ZTE (spricht dasselbe ubus-JSON-RPC wie der G5TS)
und Demo-Daten-Generator.

  python3 dev/mock_router.py --port 9999                 # Fake-Router (Passwort: demo)
  python3 dev/mock_router.py --seed data/demo.db --days 14   # Demo-Historie in eine DB schreiben

Dashboard gegen den Mock:
  ZTE_HOST=http://127.0.0.1:9999 ZTE_PASSWORD=demo ZTE_DB=data/demo.db python3 zte_dash.py
"""
import argparse
import hashlib
import json
import math
import os
import random
import secrets
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASSWORD = "demo"
SALT = secrets.token_hex(32).upper()[:64]
SESSIONS = {}          # sid -> expiry
SESSION_TTL = int(os.environ.get("MOCK_SESSION_TTL", "3600"))
COUNTERS = {"rx_m": 41_300_000_000, "tx_m": 3_900_000_000, "rx_t": 1_200_000_000, "tx_t": 120_000_000,
            "last": time.time()}


def init_counters():
    """Zähler passend zum Profil ab Monatsanfang, damit Live- und Demodaten zusammenpassen."""
    from datetime import datetime
    now = time.time()
    n = datetime.fromtimestamp(now)
    m0 = datetime(n.year, n.month, 1).timestamp()
    d0 = datetime(n.year, n.month, n.day).timestamp()
    rx = tx = drx = dtx = 0
    for t in range(int(m0), int(now), 60):
        p = profile(t)
        rx += int(p["dl"] * 60)
        tx += int(p["ul"] * 60)
        if t >= d0:
            drx += int(p["dl"] * 60)
            dtx += int(p["ul"] * 60)
    COUNTERS.update(rx_m=rx, tx_m=tx, day_rx=drx, day_tx=dtx, last=now)


SA_ALL = "1,3,8,28,41,77,78,7,20,38,40,75"
LTE_ALL = "0x7a0880800c5"
LOCK = {"sa": SA_ALL, "lte": LTE_ALL, "nr_cell": "0,0,0", "lte_cell": "0,0"}
# Wie beim echten Router: Eine neue Zellsperre wird sofort gemeldet, das Modem wechselt aber erst bei der nächsten
# Neuanmeldung im Netz (Netzwerkmodus umschalten) auf die Zelle. nr_cell_eff = die Sperre, nach der das Modem gerade arbeitet.
LOCK["nr_cell_eff"] = LOCK["nr_cell"]
# Zellen, die der Mock als aktive Zelle kennt: (pci, arfcn) -> (band, bandbreite, RSRP-Versatz)
MOCK_CELLS = {(768, 641760): ("n78", 90, 0), (115, 641760): ("n78", 90, -4), (970, 641760): ("n78", 90, -9),
              (870, 431070): ("n1", 20, -9)}
LOCK_SIG = {"nwinfo_set_sa_bandlock": {"nr5g_sa_band_lock": "String"},
            "nwinfo_lock_nr_cell": {"lock_nr_pci": "String", "lock_nr_earfcn": "String", "lock_nr_cell_band": "String"},
            "nwinfo_lock_lte_cell": {"lock_lte_pci": "String", "lock_lte_earfcn": "String"},
            "nwinfo_set_lte_ext_band": {"lte_band_lock": "String"}, "nwinfo_reset_band_cell_setting": {},
            "nwinfo_get_netinfo": {}, "nwinfo_set_netselect": {"net_select": "String"}}
STATE = {"fail": 0, "select": "4G_AND_5G", "reg_until": 0.0, "log": [], "sms_fail": False}
SMS = []               # Nachrichtenspeicher des Mock-Routers (wie zwrt_wms: tag 0 gelesen, 1 ungelesen, 2 gesendet, 3 fehlgeschlagen)
SMS_NEXT = [1]


# --- Feldverschlüsselung der SMS (wie die neuere ZTE-Firmware: RSA-Schlüsselaustausch + AES-256-GCM) ---------- #
def _is_prime(n):
    if n < 4:
        return n > 1
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % sp == 0:
            return n == sp
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(12):
        x = pow(random.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(c):
            return c


def _der(tag, body):
    ln = len(body)
    hdr = bytes([tag, ln]) if ln < 128 else bytes([tag, 0x80 | (ln.bit_length() + 7) // 8]) + ln.to_bytes((ln.bit_length() + 7) // 8, "big")
    return hdr + body


def _der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return _der(0x02, b)


RSA = {}


def rsa_init():
    import base64
    p, q = _prime(512), _prime(512)
    n, e = p * q, 65537
    RSA.update(n=n, e=e, d=pow(e, -1, (p - 1) * (q - 1)))
    spki = _der(0x30, _der(0x30, bytes.fromhex("06092A864886F70D0101010500")) + _der(0x03, b"\0" + _der(0x30, _der_int(n) + _der_int(e))))
    b64 = base64.b64encode(spki).decode()
    RSA["pem"] = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END PUBLIC KEY-----"


SESSION_KEYS = {}      # sid -> AES-Schlüssel (vom Client per web_http_enstr_set übergeben)


def _seal(sid, plain):
    import zte_dash as z
    key = SESSION_KEYS.get(sid)
    return z.wms_seal(key, plain) if key and STATE.get("enc", True) else plain


def _open(sid, value):
    import zte_dash as z
    key = SESSION_KEYS.get(sid)
    if not key or not STATE.get("enc", True):
        return value
    return z.wms_open(key, value)


def _hex(t):
    return t.encode("utf-16-be").hex().upper()


def sms_add(number, text, tag, when=None):
    from datetime import datetime
    lt = datetime.fromtimestamp(when or time.time()).astimezone()
    off = int(round(lt.utcoffset().total_seconds() / 900))      # Viertelstunden wie das echte Gerät (MESZ = +8)
    tz = "0" if off == 0 else (f"+{off}" if off > 0 else f"{off}")
    date = ",".join([lt.strftime("%y"), lt.strftime("%m"), lt.strftime("%d"), lt.strftime("%H"), lt.strftime("%M"), lt.strftime("%S"), tz])
    SMS.append({"id": str(SMS_NEXT[0]), "number": number, "content": _hex(text), "tag": str(tag), "date": date,
                "mem_store": "1", "draft_group_id": ""})
    SMS_NEXT[0] += 1


def sms_seed():
    now = time.time()
    sms_add("+491701234567", "Hallo! Dein Aldi-Talk-Guthaben wurde aufgeladen.", 0, now - 86400 * 3)
    sms_add("Aldi Talk", "Dein Datenvolumen ist zu 80 % verbraucht. Grüße dein ALDI TALK Team", 0, now - 86400)
    sms_add("+4915112345678", "Kommst du heute Abend? Bringe bitte Brot mit 🍞", 1, now - 3600 * 3)
    sms_add("+4915112345678", "Ja, bis später!", 2, now - 3600 * 2)


sms_seed()


def profile(t, live=False):
    """Gemeinsames Modell für Live- und Demo-Werte. t = Unix-Zeit."""
    h = (t % 86400) / 3600.0
    day = math.sin((h - 9) / 24 * 2 * math.pi)                # Tageszyklus (Netzlast/Wetter)
    slow = math.sin(t / 5400.0) + 0.5 * math.sin(t / 1900.0)   # langsame Schwankung
    r = random.Random(int(t // 20))                            # stabil je 20 s -> plausible Sprünge
    rsrp = -97 + 4 * slow + 2 * day + r.gauss(0, 1.6)
    band, pci, arfcn, bw, net = "n78", 768, 641760, 90, "SA"
    seg = int(t // 5400) % 11                                  # gelegentlich Zellwechsel
    if seg == 3:
        pci, rsrp = 115, rsrp - 4
    if seg == 7:
        band, pci, arfcn, bw, rsrp = "n1", 870, 431070, 20, rsrp - 9
    lte = None
    if seg == 9:
        net, band, rsrp = "LTE", "B3", None
        lte = -99 + 4 * slow + r.gauss(0, 1.8)
    if live and (LOCK["nr_cell_eff"] != "0,0,0" or LOCK["sa"] != SA_ALL):   # Sperre (nur im Live-Mock, nicht in den Demodaten)
        want = None
        if LOCK["nr_cell_eff"] != "0,0,0":
            f = LOCK["nr_cell_eff"].split(",")
            want = MOCK_CELLS.get((int(f[0]), int(f[1])))
            if not want:                                       # Zelle gibt es hier nicht -> kein Netz
                return {"net": "", "band": "", "pci": None, "arfcn": None, "bw": None, "rsrp": None, "lte": None,
                        "snr": 0, "rsrq": 0, "rssi": 0, "dl": 0, "ul": 0}
        else:
            allowed = {int(x) for x in LOCK["sa"].split(",") if x}
            cands = [(k, v) for k, v in MOCK_CELLS.items() if int(v[0][1:]) in allowed]
            want = cands[0][1] if cands else None
            if not want:
                net, band, rsrp, lte = "LTE", "B3", None, -99 + 4 * slow + r.gauss(0, 1.8)
        if want:
            net, lte = "SA", None
            band, bw, off = want
            pci, arfcn = [k for k, v in MOCK_CELLS.items() if v is want][0]
            rsrp = -97 + 4 * slow + 2 * day + r.gauss(0, 1.6) + off
    p = rsrp if rsrp is not None else lte
    snr = max(-4, min(28, 6.5 + (p + 102) * 0.9 + r.gauss(0, 1.2)))
    rsrq = max(-19, min(-6, -11 + (p + 100) * 0.12 + r.gauss(0, 0.7)))
    rssi = p + 5 + r.gauss(0, 0.8)
    load = 0.35 + 0.55 * max(0, math.sin((h - 6) / 24 * 2 * math.pi + 0.6)) ** 1.5
    if r.random() < 0.04 * (0.4 + load):          # gelegentlich Downloads/Streams
        dl = (snr + 6) * 0.45e6 * r.uniform(0.4, 1.2) * (1.0 if net == "SA" else 0.5)
    else:                                          # meist Grundrauschen
        dl = r.uniform(5e3, 8e4)
    ul = dl * r.uniform(0.04, 0.15)
    return {"net": net, "band": band, "pci": pci, "arfcn": arfcn, "bw": bw, "rsrp": rsrp, "lte": lte,
            "snr": snr, "rsrq": rsrq, "rssi": rssi, "dl": dl, "ul": ul}


def netinfo(t, live=False):
    p = profile(t, live)
    nr = p["rsrp"] is not None
    ca = "1, 870,2,1,431070,20,0,-104.0,-12.0,4.5,-95.0;" if p["net"] == "SA" and p["band"] == "n78" else ""
    return {"network_type": p["net"], "signalbar": "0" if (p["rsrp"] or p["lte"]) is None else "4" if (p["rsrp"] or p["lte"]) > -100 else "3",
            "network_provider_fullname": "Telekom.de", "wan_active_band": p["band"],
            "nr5g_cell_id": "21253422848", "nr5g_pci": str(p["pci"]) if nr else "0",
            "nr5g_action_channel": str(p["arfcn"]) if nr else "0", "nr5g_action_band": p["band"] if nr else "",
            "nr5g_bandwidth": str(p["bw"]) if nr else "0", "nrca": ca if nr else "",
            "nr5g_rsrp": f"{p['rsrp']:.0f}" if nr else "0", "nr5g_rsrq": f"{p['rsrq']:.0f}" if nr else "0",
            "nr5g_snr": f"{p['snr']:.1f}" if nr else "0", "nr5g_rssi": f"{p['rssi']:.0f}" if nr else "0",
            "lte_rsrp": f"{p['lte']:.0f}" if p["lte"] else "0", "lte_rsrq": f"{p['rsrq']:.0f}" if p["lte"] else "0",
            "lte_snr": f"{p['snr']:.1f}" if p["lte"] else "0", "lte_rssi": f"{p['rssi']:.0f}" if p["lte"] else "0",
            "nr_neighbor_cell": "768,641760;115,641760;970,641760;513,641760;381,641760;870,431070;153,641760;" if nr else "",
            "lte_neighbor_cell": "", "lte_band": "1,3,7,8,20,28,32,38,40,41,42,43",
            "nr5g_sa_band_lock": LOCK["sa"], "nr5g_nsa_band_lock": "", "nr5g_nrdc_band_lock": "",
            "lte_band_lock": LOCK["lte"], "gw_band_lock": "0x000000000", "lock_nr_cell": LOCK["nr_cell"], "lock_lte_cell": LOCK["lte_cell"]}


def wwandst(now):
    p = profile(now)
    dt = now - COUNTERS["last"]
    COUNTERS["last"] = now
    for k, v in (("rx", p["dl"]), ("tx", p["ul"])):
        COUNTERS[k + "_m"] += int(v * dt)
        COUNTERS[k + "_t"] += int(v * dt)
    return {"cid": 1, "real_rx_bytes": COUNTERS["rx_t"], "real_tx_bytes": COUNTERS["tx_t"],
            "real_rx_speed": int(p["dl"]), "real_tx_speed": int(p["ul"]),
            "month_rx_bytes": COUNTERS["rx_m"], "month_tx_bytes": COUNTERS["tx_m"],
            "day_rx_bytes": COUNTERS.get("day_rx", 0), "day_tx_bytes": COUNTERS.get("day_tx", 0)}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):  # noqa: N802
        """Steuerung für Tests: /mock/incoming?number=..&text=..  und  /mock/smsfail?on=1"""
        from urllib.parse import urlparse, parse_qs
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/mock/incoming":
            sms_add(q.get("number", ["+4917099999999"])[0], q.get("text", ["Test-SMS"])[0], 1)
            msg = "ok"
        elif u.path == "/mock/smsstrict":
            STATE["sms_strict"] = q.get("on", ["1"])[0] == "1"
            msg = "ok"
        elif u.path == "/mock/enc":          # Verschlüsselung der SMS-Felder an/aus (Firmware ohne Verschlüsselung)
            STATE["enc"] = q.get("on", ["1"])[0] == "1"
            msg = "ok"
        elif u.path == "/mock/locksig":       # Methodenliste (ubus list) für zte_nwinfo_api an/aus
            STATE["locksig"] = q.get("on", ["1"])[0] == "1"
            msg = "ok"
        elif u.path == "/mock/smsfail":
            STATE["sms_fail"] = q.get("on", ["1"])[0] == "1"
            msg = "ok"
        else:
            msg = "mock"
        data = msg.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"[]")
        out = []
        for req in body if isinstance(body, list) else [body]:
            if req.get("method") == "list":
                params = req.get("params") or []
                obj = next((x for x in params if x in ("zte_nwinfo_api", "zwrt_wms")), "zwrt_wms")
                sig = LOCK_SIG if obj == "zte_nwinfo_api" and STATE.get("locksig") else {}
                out.append({"jsonrpc": "2.0", "id": req.get("id"), "result": {obj: sig}})
                continue
            sid, obj, method, args = (req.get("params") + [{}])[:4]
            out.append({"jsonrpc": "2.0", "id": req.get("id"), **self.dispatch(sid, obj, method, args or {})})
        data = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def dispatch(self, sid, obj, method, args):
        authed = SESSIONS.get(sid, 0) > time.time()
        denied = {"error": {"code": -32002, "message": "Access denied"}}
        if (obj, method) == ("zwrt_web", "web_login_info"):
            return {"result": [0, {"login_fail_num": 5, "login_fail_lock_lefttime": 0, "zte_web_sault": SALT}]}
        if (obj, method) == ("zwrt_web", "web_login"):
            h1 = hashlib.sha256(PASSWORD.encode()).hexdigest().upper()
            good = hashlib.sha256((h1 + SALT).encode()).hexdigest().upper()
            if args.get("password") == good:
                new = secrets.token_hex(16)
                SESSIONS[new] = time.time() + SESSION_TTL
                return {"result": [0, {"ubus_rpc_session": new}]}
            STATE["fail"] += 1
            return {"result": [0, {"result": "1"}]}
        if (obj, method) == ("zwrt_web", "web_crt_get"):
            if not authed:
                return denied
            if not STATE.get("enc", True):
                return {"error": {"code": -32000, "message": "Object not found"}}
            return {"result": [0, {"result": RSA["pem"]}]}
        if (obj, method) == ("zwrt_web", "web_http_enstr_set"):
            if not authed:
                return denied
            import base64
            em = pow(int.from_bytes(base64.b64decode(args.get("web_enstr", "")), "big"), RSA["d"], RSA["n"]).to_bytes(
                (RSA["n"].bit_length() + 7) // 8, "big")
            key_hex = em[em.index(b"\0", 2) + 1:].decode()
            SESSION_KEYS[sid] = bytes.fromhex(key_hex)
            print("web_http_enstr_set -> Schlüssel gesetzt", flush=True)
            return {"result": [0, {"result": "0"}]}
        if (obj, method) == ("zte_nwinfo_api", "nwinfo_get_netinfo"):
            d = netinfo(time.time(), live=True)
            d["net_select"] = STATE["select"]
            if time.time() < STATE["reg_until"]:       # Modem meldet sich gerade neu an
                d.update(network_type="", nr5g_rsrp="0", lte_rsrp="0")
            elif STATE["select"] == "Only_LTE":
                d.update(network_type="LTE", nr5g_rsrp="0", nr5g_snr="0", lte_rsrp="-98", lte_snr="8.0")
            return {"result": [0, d]}
        if (obj, method) == ("zte_nwinfo_api", "nwinfo_set_netselect"):
            if not authed:
                return denied
            STATE["select"] = args.get("net_select", "4G_AND_5G")
            STATE["reg_until"] = time.time() + 5
            LOCK["nr_cell_eff"] = LOCK["nr_cell"]              # Neuanmeldung: jetzt gilt die gespeicherte Zellsperre
            STATE["log"].append(STATE["select"])
            print("set_netselect ->", STATE["select"], flush=True)
            return {"result": [0, {}]}
        if obj == "zte_nwinfo_api" and method in LOCK_SIG and method not in ("nwinfo_get_netinfo", "nwinfo_set_netselect"):
            if not authed:
                return denied
            want = set(LOCK_SIG[method])
            if set(args) != want and not (method == "nwinfo_reset_band_cell_setting" and not args):
                print(method, "-> INVALID ARGUMENT", args, flush=True)
                return {"result": [2]}
            if method == "nwinfo_reset_band_cell_setting":
                LOCK.update(sa=SA_ALL, lte=LTE_ALL, nr_cell="0,0,0", lte_cell="0,0", nr_cell_eff="0,0,0")
            elif method == "nwinfo_set_sa_bandlock":
                LOCK["sa"] = args["nr5g_sa_band_lock"]
            elif method == "nwinfo_set_lte_ext_band":
                LOCK["lte"] = args["lte_band_lock"]
            elif method == "nwinfo_lock_nr_cell":
                LOCK["nr_cell"] = f'{args["lock_nr_pci"]},{args["lock_nr_earfcn"]},{args["lock_nr_cell_band"]}'
            elif method == "nwinfo_lock_lte_cell":
                LOCK["lte_cell"] = f'{args["lock_lte_pci"]},{args["lock_lte_earfcn"]}'
            if method != "nwinfo_lock_nr_cell":
                STATE["reg_until"] = time.time() + 4
            print(method, "->", args, "| Sperre jetzt", LOCK, flush=True)
            return {"result": [0, {"result": "success"}]}
        if (obj, method) == ("zwrt_data", "get_wwandst"):
            if not authed:
                return denied
            if args.get("type") not in (2, 4):      # wie der echte Router: ohne type -> Invalid argument
                return {"result": [2]}
            return {"result": [0, wwandst(time.time())]}
        if obj == "zwrt_wms":
            if not authed:
                return denied
            if method == "zte_libwms_get_sms_data":
                out = []
                for m in reversed(SMS):
                    m = dict(m)
                    num = m["number"]
                    if m.get("tag") == "3":          # wie am echten Gerät: Nummer als UTF-16-Hex
                        num = _hex(num)
                    m["number"], m["content"] = _seal(sid, num), _seal(sid, m["content"])
                    out.append(m)
                return {"result": [0, {"messages": out}]}
            if method == "zte_libwms_send_sms":
                if STATE["sms_fail"]:
                    return {"result": [0, {"result": 2}]}
                if set(args) != {"id", "number", "sms_time", "message_body", "encode_type"} \
                        or args.get("encode_type") not in ("GSM7_default", "UNICODE") \
                        or (STATE.get("sms_strict") and (args.get("id") != "-1" or ";" not in str(args.get("sms_time")))):
                    print("send_sms -> INVALID ARGUMENT", sorted(args), flush=True)
                    return {"result": [2]}
                try:
                    args = dict(args, number=_open(sid, args["number"]), message_body=_open(sid, args["message_body"]))
                except ValueError:
                    print("send_sms -> INVALID ARGUMENT (nicht entschlüsselbar)", flush=True)
                    return {"result": [2]}
                text = bytes.fromhex(args.get("message_body", "")).decode("utf-16-be")
                num = args.get("number", "")
                parts = str(args.get("sms_time", "")).replace(";", ",").split(",")        # Router rechnet Stunden in Viertelstunden um
                try:
                    parts[6] = f"{float(parts[6]) * 4:+.0f}"
                except (IndexError, ValueError):
                    pass
                d = ",".join(parts)
                SMS.append({"id": str(SMS_NEXT[0]), "number": num, "content": args.get("message_body", ""), "tag": "2",
                            "date": d, "mem_store": "1", "draft_group_id": ""})
                SMS_NEXT[0] += 1
                print(f"send_sms -> {num}: {text!r} ({args.get('encode_type')}, id={args.get('id')!r})", flush=True)
                return {"result": [0, {"result": 3}]}
            if method == "zwrt_wms_get_cmd_status":
                return {"result": [0, {"sms_cmd_status_result": "3"}]}
            if method == "zwrt_wms_delete_sms":
                ids = {x for x in str(args.get("id", "")).split(";") if x}
                SMS[:] = [m for m in SMS if m["id"] not in ids]
                print("delete_sms ->", sorted(ids), flush=True)
                return {"result": [0, {"result": 3}]}
        return {"error": {"code": -32000, "message": "Object not found"}}


def seed(db_path, days, step=60):
    import zte_dash as z
    from datetime import datetime
    z.init_db(db_path)
    conn = z.connect(db_path)
    for t in ("samples", "traffic", "daily", "events", "pings", "outages", "samples_h", "traffic_h", "pings_h", "cells_h", "cells_seen"):
        conn.execute(f"DELETE FROM {t}")
    now = int(time.time())
    start = now - days * 86400
    rx_m, tx_m, cur_month = 0, 0, None
    last_cfg, daily = None, {}
    rows_s, rows_t = [], []
    for ts in range(start - start % step, now, step):
        if random.Random(ts).random() < 0.004:      # kleine Lücken (z. B. Neustart)
            continue
        d = netinfo(ts)
        s = z.parse_sample(ts, d)
        rows_s.append(tuple(s.values()))
        p = profile(ts)
        rx_d, tx_d = int(p["dl"] * step), int(p["ul"] * step)
        mk = datetime.fromtimestamp(ts).strftime("%Y-%m")
        if mk != cur_month:                          # Router-Zähler springt am Monatsersten auf 0
            cur_month, rx_m, tx_m = mk, 0, 0
        rx_m += rx_d
        tx_m += tx_d
        rows_t.append((ts, rx_m, tx_m, rx_m, tx_m, p["dl"], p["ul"], rx_d, tx_d, z.sample_key(s)))
        day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
        a = daily.setdefault(day, [0, 0])
        a[0] += rx_d
        a[1] += tx_d
        key = f"{s['net_type']}|{s['band']}|{s['pci']}"
        if last_cfg and key != last_cfg:
            def f(k):
                a = k.split("|")
                return f"{a[0]} {a[1]}" + (f" (PCI {a[2]})" if a[2] != "None" else "")
            z.add_event(conn, ts, "cell", f"{f(last_cfg)} → {f(key)}")
        last_cfg = key
    cols = list(z.parse_sample(now, netinfo(now)))
    conn.executemany(f"INSERT INTO samples({','.join(cols)}) VALUES({','.join('?' * len(cols))})", rows_s)
    conn.executemany("INSERT INTO traffic(ts,rx_total,tx_total,rx_month,tx_month,rx_speed,tx_speed,rx_delta,tx_delta,cell) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?)", rows_t)
    for (pci, arfcn), role in (((768, 641760), "serving"), ((115, 641760), "serving"), ((870, 431070), "serving"),
                               ((970, 641760), "neighbor"), ((513, 641760), "neighbor"), ((381, 641760), "neighbor"),
                               ((153, 641760), "neighbor")):
        conn.execute("INSERT OR REPLACE INTO cells_seen VALUES('NR',?,?,?,?,?,?)", (pci, arfcn, role, start, now - 60, 500))
    conn.executemany("INSERT INTO daily VALUES(?,?,?)", [(k, v[0], v[1]) for k, v in daily.items()])
    # Ping-Demo: 4 Ziele, Ausfälle mit Watchdog-Neustart
    targets = {"1.1.1.1": 27, "8.8.8.8": 31, "google.com": 34, "cloudflare.com": 29}
    outs = [(now - 2 * 86400 - 41000, 250), (now - 30 * 3600, 95), (now - 9 * 3600, 140)]
    rows_p = []
    for ts in range(start - start % 30, now, 30):
        down = any(a <= ts < a + d for a, d in outs)
        p = profile(ts)
        q = p["rsrp"] if p["rsrp"] is not None else p["lte"]
        for name, base in targets.items():
            rr = random.Random(hash((ts, name)) & 0xFFFFFFFF)
            if down or rr.random() < 0.003:
                rows_p.append((ts, name, None))
                continue
            rtt = base + max(0, -q - 92) * 0.9 + rr.gauss(0, 2.2) + (rr.random() < 0.02) * rr.uniform(20, 90)
            rows_p.append((ts, name, round(max(8.0, rtt), 2)))
    conn.executemany("INSERT OR REPLACE INTO pings VALUES(?,?,?)", rows_p)
    for a, d in outs:
        conn.execute("INSERT INTO outages(start,end,reconnects) VALUES(?,?,1)", (a, a + d))
        z.add_event(conn, a, "outage", "Ziele nicht erreichbar (4/4 Watchdog-Ziele ohne Antwort)")
        z.add_event(conn, a + 70, "reconnect", "Verbindung neu gestartet (6 Ping-Runden ohne Antwort): Modem wieder im Netz (SA), 24 s")
        z.add_event(conn, a + d, "outage_end", f"Verbindung wieder da nach {d} s (1 Neustart)")
    z.add_event(conn, now - 3 * 86400 - 4000, "offline", "Router nicht erreichbar")
    z.add_event(conn, now - 3 * 86400 - 3900, "online", "Router wieder erreichbar")
    st = z.load_settings(conn)                       # Demo: kein Live-Ping in die Demodaten mischen
    st["ping"]["enabled"] = False
    z.kv_set(conn, "settings", st)
    conn.commit()
    conn.close()
    print(f"{len(rows_s)} Messpunkte, {len(daily)} Tage in {db_path}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--seed", metavar="DB")
    ap.add_argument("--days", type=int, default=14)
    a = ap.parse_args()
    if a.seed:
        seed(a.seed, a.days)
    else:
        init_counters()
        rsa_init()
        print(f"Mock-Router auf http://127.0.0.1:{a.port}  (Passwort: {PASSWORD})")
        ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
