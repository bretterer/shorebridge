#!/usr/bin/env python3
"""
shorebridge - use ShoreTel/Mitel IP400-series phones (IP480/480g/485g) with any
standard SIP PBX (3CX, FreePBX/Asterisk, FreeSWITCH, ...).

These phones, on the Mitel/RingCentral "generic SIP" firmware, speak SIP only over
TLS and pin the server certificate to a CA they download from their config server.
shorebridge emulates just enough of the ShoreTel switch to make the phone register
(config server, downloadable trust CA, CAS, TLS, uaCSTA acks) and is a back-to-back
user agent (B2BUA) to your real PBX. The phone thinks we are its switch; the PBX
thinks we are normal SIP extensions.

Multi-phone: each physical phone (identified by the MAC it sends in its registration)
maps to its own PBX extension. Mappings live in phones.json and are managed from a
small web UI on :8910 - point a phone at the bridge, it appears there as "seen",
assign it an extension + auth, done. The installer only configures the PBX
connection; per-phone credentials are never in config.ini.

Single process, Python standard library only.
"""
import socket, ssl, threading, hashlib, random, time, re, os, sys, json, configparser, signal
import http.server, socketserver, functools, html
from urllib.parse import parse_qs, urlparse
import connectors

# ----------------------------- config -----------------------------
CFG_PATH = os.environ.get("SHOREBRIDGE_CONFIG", "/etc/shorebridge/config.ini")
CFG = configparser.ConfigParser()
if not CFG.read(CFG_PATH):
    sys.stderr.write(f"shorebridge: cannot read config {CFG_PATH}\n"); sys.exit(1)

def detect_ip(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect((target, 5060)); return s.getsockname()[0]
    except Exception: return "127.0.0.1"
    finally: s.close()

SBC_IP   = CFG.get("pbx", "sbc_ip")
SBC_PORT = CFG.getint("pbx", "sbc_port", fallback=5060)
SBC      = (SBC_IP, SBC_PORT)
DOMAIN   = CFG.get("pbx", "domain")

_bind    = CFG.get("bridge", "bind_ip", fallback="auto").strip()
MYIP     = detect_ip(SBC_IP) if _bind in ("", "auto") else _bind
DATA     = CFG.get("bridge", "data_dir", fallback="/opt/shorebridge")
TZ       = CFG.get("phone", "timezone", fallback="Eastern Standard Time")
# Number the phone's Voicemail key dials (voip.ms: *97 = own mailbox).
VM_NUMBER = CFG.get("phone", "voicemail_number", fallback="*97")
DEBUG    = CFG.getboolean("bridge", "debug", fallback=False)
UI_PORT  = CFG.getint("bridge", "ui_port", fallback=8910)
CSTA_AUTOANSWER = CFG.getboolean("bridge", "csta_test_autoanswer", fallback=False)  # test: auto-fire AnswerCall on inbound ring
# Reboot connected phones when the bridge is stopped/restarted (SIGTERM). Off by default
# so dev restarts don't bounce the phone. reboot_when: "on-idle" (wait for no active call)
# or "immediate". The phone honors Event: reboot;when=<v> over SIP-NOTIFY (firmware-verified).
REBOOT_ON_RESTART = CFG.getboolean("bridge", "reboot_phones_on_restart", fallback=False)
REBOOT_WHEN = CFG.get("bridge", "reboot_when", fallback="on-idle").strip() or "on-idle"

HTTP_ROOT = os.path.join(DATA, "www")
CERT = os.path.join(DATA, "tls", "switch_fullchain.crt")
KEY  = os.path.join(DATA, "tls", "switch.key")
LOGFILE = CFG.get("bridge", "log_file", fallback=os.path.join(DATA, "shorebridge.log"))
PHONES_JSON = CFG.get("bridge", "phones_file", fallback=os.path.join(os.path.dirname(CFG_PATH), "phones.json"))
P3CX = 5062  # our local SIP port toward the PBX

# optional connector: a source of extension data (number/name/auth) from the PBX
CONN_TYPE = CFG.get("connector", "type", fallback="manual")
CONN_CFG  = dict(CFG.items("connector")) if CFG.has_section("connector") else {}
connectors.load_dropins(os.path.join(DATA, "connectors.d"))
CONNECTOR = connectors.make(CONN_TYPE, CONN_CFG)
CATALOG = []                 # list[connectors.Extension], refreshed in the background
catalog_lock = threading.Lock()

lock = threading.Lock()
def log(m):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + m
    with lock:
        print(line, flush=True)
        try: open(LOGFILE, "a").write(line + "\n")
        except Exception: pass
def dbg(m):
    if DEBUG: log(m)
def rid(n=10): return "".join(random.choice("0123456789abcdef") for _ in range(n))
def md5(s): return hashlib.md5(s.encode()).hexdigest()

# ----------------------------- phone registry -----------------------------
# PHONES:  mac -> {"extension","auth_id","password","label"}
# CONNS:   mac -> live TLS connection (the phone's persistent signaling channel)
# SEEN:    mac -> {"ip","ts"}  phones that connected but have no mapping yet
# REGOK:   extension -> bool   last registration result toward the PBX
PHONES = {}; CONNS = {}; CONTACTS = {}; SEEN = {}; REGOK = {}
PHONE_IPS = {}                       # mac -> last source IP (to map CAS clients -> extension)
reg_threads = {}
pstate = threading.Lock()

def norm_mac(s):
    return re.sub(r"[^0-9a-fA-F]", "", s or "").lower()[:12]
def mac_from_contact(contact):
    # +sip.instance="<urn:uuid:00000000-0000-1000-8000-001049543b4c>" -> MAC is the last 12 hex
    m = re.search(r'urn:uuid:([0-9a-fA-F-]+)', contact or "")
    if not m: return None
    hexs = re.sub(r"[^0-9a-fA-F]", "", m.group(1))
    return hexs[-12:].lower() if len(hexs) >= 12 else None

def load_phones():
    global PHONES
    try:
        with open(PHONES_JSON) as f: data = json.load(f)
        PHONES = {norm_mac(k): v for k, v in data.items()}
    except Exception:
        PHONES = {}
def save_phones():
    tmp = PHONES_JSON + ".tmp"
    with open(tmp, "w") as f: json.dump(PHONES, f, indent=2)
    os.replace(tmp, PHONES_JSON)
    try: os.chmod(PHONES_JSON, 0o600)
    except Exception: pass

def creds_for_mac(mac):
    p = PHONES.get(mac)
    return (p["extension"], p["auth_id"], p["password"]) if p else None
def mac_for_ext(ext):
    for mac, p in PHONES.items():
        if p["extension"] == ext: return mac
    return None

def mac_for_ip(ip):
    """Reverse the MAC->IP map (populated at REGISTER). Lets an INVITE that arrives on a
    TLS connection before this phone has REGISTERed on it still be identified, e.g. a
    *97 dialed in the gap right after a bridge restart."""
    if not ip: return None
    for mac, pip in PHONE_IPS.items():
        if pip == ip and mac in PHONES: return mac
    return None

# ----------------------------- SIP helpers -----------------------------
def parse(msg):
    head, _, body = msg.partition("\r\n\r\n"); lines = head.split("\r\n"); start = lines[0]; hdrs = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1); hdrs.setdefault(k.strip().lower(), []).append(v.strip())
    return start, hdrs, body
def H(hdrs, k):
    v = hdrs.get(k.lower(), []); return v[0] if v else ""
def allvia(hdrs): return [f"Via: {v}" for v in hdrs.get("via", [])]
def allrr(hdrs):  return [f"Record-Route: {v}" for v in hdrs.get("record-route", [])]
def uri_of(val):
    m = re.search(r"<([^>]+)>", val or "")
    return m.group(1) if m else (val.split(";")[0].strip() if val else "")
def parse_auth(h):
    g = lambda p: (re.search(p, h).group(1) if re.search(p, h) else None)
    return g(r'realm="([^"]*)"'), g(r'nonce="([^"]*)"'), g(r'qop="?([a-z,]*)"?'), g(r'opaque="([^"]*)"')
def digest(method, uri, realm, nonce, qop, cnonce, nc, opaque, authid, password):
    ha1 = md5(f"{authid}:{realm}:{password}"); ha2 = md5(f"{method}:{uri}")
    resp = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}") if qop else md5(f"{ha1}:{nonce}:{ha2}")
    a = f'Digest username="{authid}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}", algorithm=MD5'
    if qop: a += f', qop={qop.split(",")[0]}, nc={nc}, cnonce="{cnonce}"'
    if opaque: a += f', opaque="{opaque}"'
    return a

# ----------------------------- PBX side (UDP) -----------------------------
u3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
u3.bind((MYIP, P3CX))
waiters = {}; wlock = threading.Lock()
def u3_send(msg): u3.sendto(msg.encode(), SBC)

def build_bye(leg):
    leg["cseq"] = leg.get("cseq", 1) + 1
    L = [f"BYE {leg['ruri']} SIP/2.0",
         f"Via: SIP/2.0/{leg['transport']} {MYIP}:{leg['lport']};branch=z9hG4bK{rid(16)};rport"]
    for rt in leg.get("route", []): L.append(f"Route: {rt}")
    L += ["Max-Forwards: 70", f"From: {leg['local']};tag={leg['ltag']}", f"To: {leg['remote']}",
          f"Call-ID: {leg['callid']}", f"CSeq: {leg['cseq']} BYE", "User-Agent: ShoreBridge/1.0", "Content-Length: 0"]
    data = ("\r\n".join(L) + "\r\n\r\n").encode()
    if leg["transport"] == "TLS":
        c = leg.get("conn")
        if c:
            try: c.sendall(data)
            except Exception: pass
    else:
        u3.sendto(data, SBC)
    log(f"sent BYE ({leg['transport']}) callid {leg['callid'][:8]}")

def wait(callid, timeout):
    end = time.time() + timeout
    while time.time() < end:
        with wlock:
            q = waiters.get(callid)
            if q:
                for r in q:
                    p = r.split("\r\n")[0].split()
                    if len(p) > 1 and p[1].isdigit() and int(p[1]) >= 200: return r
        time.sleep(0.05)
    with wlock:
        q = waiters.get(callid) or []; return q[-1] if q else None

def reg_loop(ext):
    while True:
        # resolve current creds for this extension; exit if the phone was removed
        creds = None
        with pstate:
            for mac, p in PHONES.items():
                if p["extension"] == ext: creds = (p["auth_id"], p["password"]); break
        if creds is None:
            with pstate: reg_threads.pop(ext, None); REGOK.pop(ext, None)
            log(f"registration for ext {ext} stopped (phone removed)"); return
        authid, password = creds
        callid = rid(16) + "@" + MYIP; ftag = rid(8)
        def mk(cseq, auth=None, hdr="Authorization"):
            L = [f"REGISTER sip:{DOMAIN} SIP/2.0",
                 f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch=z9hG4bK{rid(16)};rport", "Max-Forwards: 70",
                 f"From: <sip:{ext}@{DOMAIN}>;tag={ftag}", f"To: <sip:{ext}@{DOMAIN}>",
                 f"Call-ID: {callid}", f"CSeq: {cseq} REGISTER",
                 f"Contact: <sip:{ext}@{MYIP}:{P3CX}>", "Expires: 120", "User-Agent: ShoreBridge/1.0"]
            if auth: L.append(f"{hdr}: {auth}")
            L.append("Content-Length: 0"); return "\r\n".join(L) + "\r\n\r\n"
        with wlock: waiters[callid] = []
        u3_send(mk(1)); r = wait(callid, 4)
        if r and (" 401 " in r.split("\r\n")[0] or " 407 " in r.split("\r\n")[0]):
            st = r.split("\r\n")[0]
            hh = [l for l in r.split("\r\n") if l.lower().startswith(("www-authenticate", "proxy-authenticate"))]
            realm, nonce, qop, opaque = parse_auth(hh[0]) if hh else (None,) * 4
            hdr = "Proxy-Authorization" if " 407 " in st else "Authorization"
            auth = digest("REGISTER", f"sip:{DOMAIN}", realm, nonce, qop, rid(16), "00000001", opaque, authid, password)
            with wlock: waiters[callid] = []
            u3_send(mk(2, auth, hdr)); r = wait(callid, 4)
        with wlock: waiters.pop(callid, None)
        ok = bool(r and " 200 " in r.split("\r\n")[0])
        with pstate: REGOK[ext] = ok
        dbg(f"ext {ext} registration: " + ("OK" if ok else "FAILED"))
        time.sleep(90 if ok else 15)

def ensure_registrations():
    with pstate:
        exts = {p["extension"] for p in PHONES.values()}
        for ext in exts:
            if ext not in reg_threads:
                reg_threads[ext] = True
                threading.Thread(target=reg_loop, args=(ext,), daemon=True).start()
                log(f"starting registration for ext {ext}")
            if ext not in mwi_threads:
                mwi_threads[ext] = True
                threading.Thread(target=mwi_loop, args=(ext,), daemon=True).start()

# ----------------------------- voicemail light (MWI) -----------------------------
# PBX side: per extension, SUBSCRIBE to message-summary (digest auth, refreshed) and
# answer the PBX's NOTIFYs. Phone side: the phone never subscribes, so we push an
# unsolicited NOTIFY (simple-message-summary) over its TLS connection on every
# change and whenever it re-registers.
MWI = {}                 # ext -> {"waiting": bool, "new": int, "old": int}
mwi_threads = {}
MWI_SUBS = {}            # PBX subscription Call-ID -> ext
MWI_PHONE = {}           # mac -> {"callid","tag","cseq"} for our NOTIFY dialog to the phone

def parse_mwi(body):
    waiting, new, old = False, 0, 0
    for line in (body or "").splitlines():
        k, _, v = line.partition(":"); k = k.strip().lower(); v = v.strip()
        if k == "messages-waiting": waiting = v.lower().startswith("y")
        elif k == "voice-message":
            m = re.match(r"(\d+)\s*/\s*(\d+)", v)
            if m: new, old = int(m.group(1)), int(m.group(2))
    return {"waiting": waiting or new > 0, "new": new, "old": old}

def on_mwi(ext, st):
    prev = MWI.get(ext); MWI[ext] = st
    if prev != st:
        log(f"voicemail ext {ext}: {st['new']} new / {st['old']} old -> lamp {'ON' if st['waiting'] else 'off'}")
    mac = mac_for_ext(ext)
    if mac: push_mwi_to_phone(mac)

def push_mwi_to_phone(mac):
    with pstate:
        conn = CONNS.get(mac); contact = CONTACTS.get(mac); p = PHONES.get(mac)
    if not (conn and contact and p): return
    ext = str(p.get("extension", "")); st = MWI.get(ext)
    if st is None: return
    d = MWI_PHONE.setdefault(mac, {"callid": rid(16) + "@" + MYIP, "tag": rid(8), "cseq": 0})
    d["cseq"] += 1
    body = (f"Messages-Waiting: {'yes' if st['waiting'] else 'no'}\r\n"
            f"Message-Account: sips:{ext}@{MYIP}\r\n"
            f"Voice-Message: {st['new']}/{st['old']} (0/0)\r\n").encode()
    L = [f"NOTIFY {contact} SIP/2.0", f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)};rport",
         "Max-Forwards: 70", f"From: <sips:{ext}@{MYIP}>;tag={d['tag']}", f"To: <sips:{ext}@{MYIP}>",
         f"Call-ID: {d['callid']}", f"CSeq: {d['cseq']} NOTIFY", "Event: message-summary",
         "Subscription-State: active;expires=3600", f"Contact: <sips:switch@{MYIP}:5061;transport=tls>",
         "Content-Type: application/simple-message-summary", f"Content-Length: {len(body)}"]
    try:
        conn.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
        dbg(f"MWI -> phone {mac}: {'yes' if st['waiting'] else 'no'} {st['new']}/{st['old']}")
    except Exception as e:
        log(f"MWI push to {mac} failed: {e!r}")

def mwi_loop(ext):
    callid = rid(16) + "@" + MYIP; ftag = rid(8); cseq = 0; totag = ""; warned = False
    with pstate: MWI_SUBS[callid] = ext
    while True:
        creds = None
        with pstate:
            for mac, p in PHONES.items():
                if p["extension"] == ext: creds = (p["auth_id"], p["password"]); break
        if creds is None:
            with pstate: mwi_threads.pop(ext, None); MWI_SUBS.pop(callid, None)
            log(f"voicemail subscription for ext {ext} stopped (phone removed)"); return
        authid, password = creds
        def mk(n, auth=None, hdr="Authorization"):
            L = [f"SUBSCRIBE sip:{ext}@{DOMAIN} SIP/2.0",
                 f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch=z9hG4bK{rid(16)};rport", "Max-Forwards: 70",
                 f"From: <sip:{ext}@{DOMAIN}>;tag={ftag}", f"To: <sip:{ext}@{DOMAIN}>" + (f";tag={totag}" if totag else ""),
                 f"Call-ID: {callid}", f"CSeq: {n} SUBSCRIBE", f"Contact: <sip:{ext}@{MYIP}:{P3CX}>",
                 "Event: message-summary", "Accept: application/simple-message-summary",
                 "Expires: 3600", "User-Agent: ShoreBridge/1.0"]
            if auth: L.append(f"{hdr}: {auth}")
            L.append("Content-Length: 0"); return "\r\n".join(L) + "\r\n\r\n"
        cseq += 1
        with wlock: waiters[callid] = []
        u3_send(mk(cseq)); r = wait(callid, 4)
        if r and r.split("\r\n")[0].split()[1] in ("401", "407"):
            st = r.split("\r\n")[0]
            hh = [l for l in r.split("\r\n") if l.lower().startswith(("www-authenticate", "proxy-authenticate"))]
            realm, nonce, qop, opaque = parse_auth(hh[0]) if hh else (None,) * 4
            hdr = "Proxy-Authorization" if " 407 " in st else "Authorization"
            auth = digest("SUBSCRIBE", f"sip:{ext}@{DOMAIN}", realm, nonce, qop, rid(16), "00000001", opaque, authid, password)
            cseq += 1
            with wlock: waiters[callid] = []
            u3_send(mk(cseq, auth, hdr)); r = wait(callid, 4)
        with wlock: waiters.pop(callid, None)
        code = r.split("\r\n")[0].split()[1] if r else "timeout"
        if code.startswith("2"):
            _, h, _ = parse(r); m = re.search(r";tag=([^;>\s]+)", H(h, "to"))
            if m: totag = m.group(1)
            try: exp = int(re.sub(r"\D", "", H(h, "expires")) or 3600)
            except Exception: exp = 3600
            if warned or not MWI.get(ext): dbg(f"voicemail subscription ext {ext}: {code}, expires {exp}s")
            warned = False
            time.sleep(max(60, min(exp - 60, 1800)))
        else:
            if not warned: log(f"voicemail subscription ext {ext} failed: {code} (retrying every 10 min)")
            warned = True; totag = ""
            time.sleep(600)

CALLS = {}
PIN = {}; pinlock = threading.Lock()

def u3_recv():
    while True:
        try: data, addr = u3.recvfrom(65535)
        except Exception: continue
        try:
            msg = data.decode("utf-8", "replace"); start = msg.split("\r\n")[0]
            _, hdrs, _ = parse(msg); cid = H(hdrs, "call-id")
            _dispatch(start, hdrs, cid, msg, addr)
        except Exception as e:
            log("pbx recv err: " + repr(e))

def _dispatch(start, hdrs, cid, msg, addr):
    if start.startswith("SIP/2.0"):
        with wlock:
            if cid in waiters: waiters[cid].append(msg)
        for cs in list(CALLS.values()):
            if cs.x_callid == cid: cs.on_3cx_response(msg)
    else:
        method = start.split()[0]
        if method == "OPTIONS":
            u3_send(resp_line(200, "OK", hdrs))
        elif method == "INVITE":
            cs = CALLS.get(cid)
            if cs and cs.alive and ";tag=" in H(hdrs, "to"):      # in-dialog re-INVITE
                threading.Thread(target=pbx_reinvite, args=(cs, hdrs, msg, addr), daemon=True).start()
            else:
                threading.Thread(target=inbound_invite, args=(hdrs, msg, addr), daemon=True).start()
        elif method == "NOTIFY":
            u3.sendto(resp_line(200, "OK", hdrs).encode(), addr)
            if "message-summary" in H(hdrs, "event").lower():
                _, _, body = parse(msg)
                ext = MWI_SUBS.get(cid)
                if not ext:                          # unsolicited: take the user part of To
                    m = re.search(r"sips?:([^@>;]+)@", H(hdrs, "to")); ext = m.group(1) if m else ""
                if ext and mac_for_ext(ext): on_mwi(ext, parse_mwi(body))
                elif DEBUG: dbg(f"MWI NOTIFY for unknown ext {ext!r}")
        elif method in ("BYE", "CANCEL", "ACK"):
            for cs in list(CALLS.values()):
                if cs.x_callid == cid: cs.on_3cx_request(method, hdrs, msg)
            if method != "ACK": u3.sendto(resp_line(200, "OK", hdrs).encode(), addr)

def resp_line(code, reason, hdrs):
    L = [f"SIP/2.0 {code} {reason}"] + allvia(hdrs) + allrr(hdrs) + [
        f"From: {H(hdrs,'from')}", f"To: {H(hdrs,'to')}",
        f"Call-ID: {H(hdrs,'call-id')}", f"CSeq: {H(hdrs,'cseq')}", "Content-Length: 0"]
    return "\r\n".join(L) + "\r\n\r\n"

# ----------------------------- RTP relay -----------------------------
def alloc_rtp():
    # No SO_REUSEADDR here: on Linux it lets two UDP sockets bind the SAME port, so the
    # phone-side and PBX-side sockets of a call collided and the phone's audio was
    # looped back to the phone instead of reaching the PBX (one-way audio).
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for p in range(12000, 12800, 2):
        try: s.bind((MYIP, p)); return s, p
        except OSError: continue
    s.bind((MYIP, 0)); return s, s.getsockname()[1]

def sdp_media(sdp):
    ip = port = None
    for line in (sdp or "").split("\n"):
        line = line.strip()
        if line.startswith("c=IN IP4"): ip = line.split()[2]
        if line.startswith("m=audio") and port is None: port = int(line.split()[1])
    return (ip, port) if ip and port else None

# ----------------------------- call log (for the phone's History) -----------------------------
CALLS_JSON = os.path.join(DATA, "calls.json")
HISTORY_FMT_JSON = os.path.join(DATA, "history_format.json")
CALLLOG_LOCK = threading.Lock()
CALLLOG_MAX = 200

def load_calllog():
    try:
        with open(CALLS_JSON) as f: d = json.load(f); return d if isinstance(d, list) else []
    except Exception: return []

def _digits(n): return re.sub(r"\D", "", str(n or ""))[-10:]
def name_for_number(num):
    """Best-effort caller name from the directory / configured phones (last 10 digits)."""
    key = _digits(num)
    if not key: return ""
    for e in load_directory():
        if _digits(e.get("number")) == key: return e.get("name", "")
    for p in PHONES.values():
        if _digits(p.get("extension")) == key: return p.get("label", "")
    return ""

def delete_calllog(ext, ids=None):
    """Remove this extension's records: all of them (ids=None) or just those ids.
    Other phones' records are never touched. Returns the number removed."""
    if not ext: return 0                        # unidentified phone: never delete
    with CALLLOG_LOCK:
        log_ = load_calllog()
        keep = [r for r in log_ if (ext and r.get("ext") != ext)
                or (ids is not None and r.get("id") not in ids)]
        removed = len(log_) - len(keep)
        if removed:
            # remember the highest id ever issued before dropping records, so it is never reused
            seq_f = CALLS_JSON + ".seq"
            try: last = int(open(seq_f).read().strip() or 0)
            except Exception: last = 0
            hi = max([last] + [r.get("id", 0) for r in log_])
            with open(seq_f, "w") as f: f.write(str(hi))
            tmp = CALLS_JSON + ".tmp"
            with open(tmp, "w") as f: json.dump(keep, f, indent=1)
            os.replace(tmp, CALLS_JSON)
    return removed

def record_call(cs):
    try:
        peer = getattr(cs, "peer", "") or cs.dst
        start = getattr(cs, "t_start", None) or time.time(); up = getattr(cs, "t_up", None)
        direction = getattr(cs, "direction", "out")
        rec = {"ext": cs.ext, "mac": cs.mac, "direction": direction, "number": peer,
               "name": name_for_number(peer), "start": int(start),
               "duration": int(time.time() - up) if up else 0,
               "answered": bool(up), "missed": direction == "in" and not up}
        with CALLLOG_LOCK:
            log_ = load_calllog()
            # ids are never reused (the phone caches recids): keep a high-water mark
            seq_f = CALLS_JSON + ".seq"
            try: last = int(open(seq_f).read().strip() or 0)
            except Exception: last = 0
            rec["id"] = max(last, max((r.get("id", 0) for r in log_), default=0)) + 1
            with open(seq_f, "w") as f: f.write(str(rec["id"]))
            log_.append(rec); log_ = log_[-CALLLOG_MAX:]
            tmp = CALLS_JSON + ".tmp"
            with open(tmp, "w") as f: json.dump(log_, f, indent=1)
            os.replace(tmp, CALLS_JSON)
        log(f"call log: #{rec['id']} {direction} {peer} {'missed' if rec['missed'] else str(rec['duration'])+'s'}")
    except Exception as e:
        log("call log err " + repr(e))

# History reply format, from the IP485g firmware (bin/linemgrSip, CasCallLogsParser):
# reply keys request-id/response/details/message + "records"; records use the same
# COLUMNAR layout as the directory: element[0] = header (field names), then rows.
# Record fields: recid rec-type ts-start duration-secs time-label secure
# call-recording-flag parties; each party list is columnar too: name number
# number-canonical. The numeric rec-type codes are NOT in the binary as text, so
# they (and the ts-start unit) are read from history_format.json on every request.
HIST_HDR  = ["recid", "rec-type", "ts-start", "duration-secs", "time-label", "secure",
             "call-recording-flag", "parties"]
PARTY_HDR = ["name", "number", "number-canonical"]
HISTORY_FMT_DEFAULT = {"rec_type": {"in": 1, "out": 2, "missed": 3}, "ts_units": "s", "time_label": 0}

def _canon(num):
    d = re.sub(r"\D", "", str(num or ""))
    if len(d) == 10: return "+1" + d
    if len(d) == 11 and d.startswith("1"): return "+" + d
    return str(num or "")

def cas_history_response(req, ext, sid=""):
    try:
        with open(HISTORY_FMT_JSON) as f: fmt = {**HISTORY_FMT_DEFAULT, **json.load(f)}
    except Exception: fmt = HISTORY_FMT_DEFAULT
    msg = req.get("message"); rid_ = req.get("request-id", 0)
    base = {"request-id": rid_, "topic": "history", "message": msg, "response": 0}
    if msg in ("delete-recs", "delete-all"):
        log(f"CAS history {msg} request: {json.dumps(req)[:300]}")
        ids = req.get("recids", req.get("recid", []))
        if not isinstance(ids, list): ids = [ids]
        ids = {int(x) for x in ids if str(x).lstrip("-").isdigit()}
        n = delete_calllog(ext, None if msg == "delete-all" else ids)
        log(f"CAS history {msg} -> removed {n} rec(s) for ext {ext}")
        return base
    if msg not in ("get-recs", "get-page-view"):
        log(f"CAS history {msg} -> ok"); return base          # close-page-view etc.
    recs = [r for r in load_calllog() if not ext or r.get("ext") == ext]
    # newest first, except get-recs forward=true (asks for the oldest end)
    recs.sort(key=lambda r: r.get("start", 0), reverse=not (msg == "get-recs" and req.get("forward")))
    try: mx = int(req.get("max", req.get("count", 50)))   # get-page-view uses "count"
    except Exception: mx = 50
    rt = fmt.get("rec_type", HISTORY_FMT_DEFAULT["rec_type"])
    mult = 1000 if fmt.get("ts_units") == "ms" else 1
    rows = [HIST_HDR]
    for r in recs[:max(0, mx)]:
        kind = "missed" if r.get("missed") else ("in" if r.get("direction") == "in" else "out")
        name = r.get("name") or ""
        parties = [PARTY_HDR, [name, str(r.get("number", "")), _canon(r.get("number"))]]
        rows.append([r.get("id", 0), rt.get(kind, 0), int(r.get("start", 0)) * mult,
                     int(r.get("duration", 0)), fmt.get("time_label", 0), False, False, parties])
    resp = {**base, "records": rows}
    log(f"CAS history {msg} max={req.get('max')} count={req.get('count')} forward={req.get('forward')} -> {len(rows)-1} rec(s)")
    if DEBUG: dbg("CAS history reply: " + json.dumps(resp)[:800])
    return resp

# ---- in-dialog re-INVITE (hold / resume / session-timer refresh) ----
# Both legs are answered locally by the bridge: the RTP relay keeps running, we just
# mirror the offered direction so each side sees a valid answer. Without this a
# re-INVITE was treated as a brand-new call (Hold dropped the phone's call leg).
_MIRROR = {"sendonly": "recvonly", "recvonly": "sendonly", "inactive": "inactive", "sendrecv": "sendrecv"}
def sdp_dir(sdp):
    """Direction of the first audio m-section of an offer (c=0.0.0.0 = old-style hold)."""
    d = "sendrecv"; in_audio = False; seen = False
    for line in (sdp or "").split("\n"):
        line = line.strip()
        if line.startswith("m="):
            if seen: break
            in_audio = line.startswith("m=audio"); seen = seen or in_audio
        elif line.startswith("c=IN IP4 0.0.0.0"): d = "inactive"
        elif in_audio and line[2:] in _MIRROR and line.startswith("a="): d = line[2:]
    return d
def _next_ver(cs):
    cs.sdp_ver = getattr(cs, "sdp_ver", 1) + 1; return cs.sdp_ver
def reinvite_answer(cs, offer, leg):
    """Answer SDP for a re-INVITE on leg 'phone' or 'pbx', same m-line count as the offer."""
    d = _MIRROR.get(sdp_dir(offer), "sendrecv"); v = _next_ver(cs)
    nm = max(1, sum(1 for l in (offer or "").split("\n") if l.startswith("m=")))
    if leg == "phone":
        sdp = ("v=0\r\n" f"o=switch 1 {v} IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
               f"m=audio {cs.rpP} RTP/AVP 0 {cs.phone_te}\r\n" "a=rtpmap:0 PCMU/8000\r\n"
               f"a=rtpmap:{cs.phone_te} telephone-event/8000\r\n" "a=ptime:20\r\n" f"a={d}\r\n")
        sdp += "m=audio 0 RTP/SAVP 0\r\n" * (nm - 1)
    else:
        sdp = ("v=0\r\n" f"o=bridge 1 {v} IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
               f"m=audio {cs.rp3} RTP/AVP 0 {cs.pbx_te}\r\n" "a=rtpmap:0 PCMU/8000\r\n"
               f"a=rtpmap:{cs.pbx_te} telephone-event/8000\r\n" f"a={d}\r\n")
        sdp += "m=audio 0 RTP/AVP 0\r\n" * (nm - 1)
    return sdp, d

def phone_reinvite(conn, cs, hdrs, body, addr):
    m = sdp_media(body)
    if m and m[1] and m[0] != "0.0.0.0": cs.phone_rtp = m
    ans, d = reinvite_answer(cs, body, "phone")
    conn.sendall(p_resp(200, "OK", hdrs, addr, "INVITE", sdp=ans))
    pd = sdp_dir(body)
    log(f"phone re-INVITE on {cs.dst}: {pd} -> answered {d}"
        + (" (hold)" if d in ("recvonly", "inactive") else ""))
    # Pass hold/resume on to the PBX so it plays its music-on-hold to the far end.
    # Skip pure session-timer refreshes (direction unchanged).
    if pd != getattr(cs, "x_dir", "sendrecv"):
        threading.Thread(target=x_reinvite, args=(cs, pd), daemon=True).start()

def x_reinvite(cs, direction):
    """In-dialog re-INVITE to the PBX leg offering `direction` (sendonly = hold,
    sendrecv = resume). Handles one digest challenge, ACKs the 2xx."""
    leg = cs.x_dialog
    if not leg: return
    with pstate: creds = creds_for_mac(cs.mac)
    authid, password = (creds[1], creds[2]) if creds else (cs.authid, cs.password)
    v = _next_ver(cs)
    sdp = ("v=0\r\n" f"o=bridge 1 {v} IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rp3} RTP/AVP 0 {cs.pbx_te}\r\n" "a=rtpmap:0 PCMU/8000\r\n"
           f"a=rtpmap:{cs.pbx_te} telephone-event/8000\r\n" f"a={direction}\r\n").encode()
    def mk(cseq, branch, auth=None, hdr="Proxy-Authorization"):
        L = [f"INVITE {leg['ruri']} SIP/2.0",
             f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch={branch};rport"]
        L += [f"Route: {rt}" for rt in leg.get("route", [])]
        L += ["Max-Forwards: 70", f"From: {leg['local']};tag={leg['ltag']}", f"To: {leg['remote']}",
              f"Call-ID: {leg['callid']}", f"CSeq: {cseq} INVITE",
              f"Contact: <sip:{cs.ext}@{MYIP}:{P3CX}>", "User-Agent: ShoreBridge/1.0"]
        if auth: L.append(f"{hdr}: {auth}")
        L += ["Content-Type: application/sdp", f"Content-Length: {len(sdp)}"]
        return ("\r\n".join(L) + "\r\n\r\n").encode() + sdp
    def ack(cseq, resp, branch):
        # non-2xx ACK reuses the INVITE's branch (same transaction); 2xx ACK gets a new one
        _, h, _ = parse(resp)
        if resp.split("\r\n")[0].split()[1].startswith("2"): branch = "z9hG4bK" + rid(16)
        L = [f"ACK {leg['ruri']} SIP/2.0", f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch={branch};rport"]
        L += [f"Route: {rt}" for rt in leg.get("route", [])]
        L += ["Max-Forwards: 70", f"From: {leg['local']};tag={leg['ltag']}", f"To: {H(h,'to') or leg['remote']}",
              f"Call-ID: {leg['callid']}", f"CSeq: {cseq} ACK", "Content-Length: 0"]
        u3.sendto(("\r\n".join(L) + "\r\n\r\n").encode(), SBC)
    leg["cseq"] = leg.get("cseq", 1) + 1; cseq = leg["cseq"]
    br = "z9hG4bK" + rid(16)
    with wlock: waiters[leg["callid"]] = []
    u3.sendto(mk(cseq, br), SBC)
    r = wait_invite(leg["callid"], 6, cseq=cseq)
    if r and r.split("\r\n")[0].split()[1] in ("401", "407"):
        st = r.split("\r\n")[0]; ack(cseq, r, br)
        hh = [l for l in r.split("\r\n") if l.lower().startswith(("www-authenticate", "proxy-authenticate"))]
        realm, nonce, qop, opaque = parse_auth(hh[0])
        hdr = "Proxy-Authorization" if " 407 " in st else "Authorization"
        auth = digest("INVITE", leg["ruri"], realm, nonce, qop, rid(16), "00000001", opaque, authid, password)
        leg["cseq"] += 1; cseq = leg["cseq"]; br = "z9hG4bK" + rid(16)
        with wlock: waiters[leg["callid"]] = []
        u3.sendto(mk(cseq, br, auth, hdr), SBC)
        r = wait_invite(leg["callid"], 6, cseq=cseq)
    code = r.split("\r\n")[0].split()[1] if r else "timeout"
    if DEBUG:
        dbg("PBX re-INVITE SENT >>>>\n" + mk(cseq, br).decode("utf-8", "replace").strip() + "\n<<<< end")
        dbg("PBX re-INVITE REPLY >>>>\n" + (r or "(none)").strip() + "\n<<<< end")
    if r and code.isdigit() and int(code) >= 200: ack(cseq, r, br)
    if code == "200":
        _, _, rb = parse(r); m = sdp_media(rb)
        if m and m[1] and m[0] != "0.0.0.0": cs.x_rtp = m
        cs.x_dir = direction
    log(f"PBX re-INVITE {direction} on {cs.dst}: {code}" + (" (hold music from PBX)" if direction != "sendrecv" and code == "200" else ""))

def pbx_reinvite(cs, xh, xraw, xaddr):
    _, _, xbody = parse(xraw)
    m = sdp_media(xbody)
    if m and m[1] and m[0] != "0.0.0.0": cs.x_rtp = m
    to = H(xh, "to")
    # (an offer-less re-INVITE gets our sendrecv offer here; its answer comes in the ACK)
    ans, d = reinvite_answer(cs, xbody, "pbx"); ob = ans.encode()
    extra = ["Content-Type: application/sdp", f"Content-Length: {len(ob)}"]
    L = ["SIP/2.0 200 OK"] + allvia(xh) + allrr(xh) + [f"From: {H(xh,'from')}", f"To: {to}",
         f"Call-ID: {H(xh,'call-id')}", f"CSeq: {H(xh,'cseq')}",
         f"Contact: <sip:{cs.ext}@{MYIP}:{P3CX}>"] + extra
    u3.sendto(("\r\n".join(L) + "\r\n\r\n").encode() + ob, xaddr)
    log(f"PBX re-INVITE on {cs.dst}: {sdp_dir(xbody)} -> answered {d}")

def sdp_te_pt(sdp):
    """Payload type the SDP assigns to telephone-event (RFC 4733 DTMF), or None."""
    m = re.search(r"a=rtpmap:(\d+)\s+telephone-event/", sdp or "", re.I)
    return int(m.group(1)) if m else None

class CallSession:
    def __init__(s, dst, conn, mac, ext, authid, password):
        s.dst = dst; s.pc = conn; s.mac = mac
        s.ext = ext; s.authid = authid; s.password = password
        s.x_callid = rid(16) + "@" + MYIP; s.x_ftag = rid(8); s.x_totag = None
        s.p_callid = None; s.ph = None
        s.sockP, s.rpP = alloc_rtp(); s.sock3, s.rp3 = alloc_rtp()
        s.phone_rtp = None; s.x_rtp = None
        s.alive = True; s.p_ftag = None; s.p_totag = None; s.p_addr = None
        s.p_dialog = None; s.x_dialog = None; s.p_inv = None
        s.t_start = time.time(); s.t_up = None; s.direction = "out"; s.peer = dst
        s.phone_te = 102; s.pbx_te = 101      # DTMF payload types negotiated on each leg
    def on_3cx_response(s, msg): pass
    def on_3cx_request(s, method, hdrs, msg):
        if method in ("BYE", "CANCEL"): s.teardown(origin="3cx")
    def relay(s):
        import select as sel
        try: s.sockP.setblocking(False); s.sock3.setblocking(False)
        except Exception: return
        np_ = n3 = 0
        while s.alive:
            try: r, _, _ = sel.select([s.sockP, s.sock3], [], [], 0.5)
            except Exception: break
            for so in r:
                try: d, a = so.recvfrom(4096)
                except Exception: continue
                # DTMF (telephone-event) uses a different payload-type number on each
                # leg; relabel it or the far end drops the digits.
                if len(d) >= 12 and (d[0] >> 6) == 2:
                    pt = d[1] & 0x7F
                    if so is s.sockP and pt == s.phone_te and s.pbx_te != s.phone_te:
                        d = d[:1] + bytes([(d[1] & 0x80) | s.pbx_te]) + d[2:]
                    elif so is s.sock3 and pt == s.pbx_te and s.pbx_te != s.phone_te:
                        d = d[:1] + bytes([(d[1] & 0x80) | s.phone_te]) + d[2:]
                if so is s.sockP:
                    s.phone_rtp = a; np_ += 1
                    if s.x_rtp:
                        try: s.sock3.sendto(d, s.x_rtp)
                        except Exception: pass
                else:
                    s.x_rtp = a; n3 += 1
                    if s.phone_rtp:
                        try: s.sockP.sendto(d, s.phone_rtp)
                        except Exception: pass
                if np_ in (1, 250) or n3 in (1, 250): dbg(f"relay: phone->{np_} pbx->{n3}")
    def teardown(s, origin=None):
        if not s.alive: return
        s.alive = False
        if origin != "phone":
            if s.p_dialog:                      # call was answered -> BYE
                try: build_bye(s.p_dialog)
                except Exception as e: log("bye phone err " + repr(e))
            elif s.p_inv:                        # phone still ringing -> CANCEL its INVITE
                try:
                    iv = s.p_inv
                    L = [f"CANCEL {iv['contact']} SIP/2.0",
                         f"Via: SIP/2.0/TLS {MYIP}:5061;branch={iv['branch']};rport", "Max-Forwards: 70",
                         f"From: {iv['from']}", f"To: <{iv['contact']}>",
                         f"Call-ID: {iv['callid']}", "CSeq: 1 CANCEL", "Content-Length: 0"]
                    iv["conn"].sendall(("\r\n".join(L) + "\r\n\r\n").encode())
                    log("sent CANCEL to phone (caller hung up before answer)")
                except Exception as e: log("cancel phone err " + repr(e))
        if origin != "3cx" and s.x_dialog:
            try: build_bye(s.x_dialog)
            except Exception as e: log("bye pbx err " + repr(e))
        for so in (s.sockP, s.sock3):
            try: so.close()
            except Exception: pass
        CALLS.pop(s.p_callid, None); CALLS.pop(s.x_callid, None)
        log(f"call {s.dst} ended (origin={origin})")
        record_call(s)

# ----------------------------- outbound: phone -> PBX -----------------------------
def x_invite(cs):
    sdp = ("v=0\r\n" f"o=bridge 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rp3} RTP/AVP 0 101\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:101 telephone-event/8000\r\n" "a=sendrecv\r\n")
    def mk(cseq, branch, auth=None, hdr="Proxy-Authorization"):
        b = sdp.encode()
        L = [f"INVITE sip:{cs.dst}@{DOMAIN} SIP/2.0",
             f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch={branch};rport", "Max-Forwards: 70",
             f"From: <sip:{cs.ext}@{DOMAIN}>;tag={cs.x_ftag}", f"To: <sip:{cs.dst}@{DOMAIN}>",
             f"Call-ID: {cs.x_callid}", f"CSeq: {cseq} INVITE",
             f"Contact: <sip:{cs.ext}@{MYIP}:{P3CX}>", "User-Agent: ShoreBridge/1.0",
             "Content-Type: application/sdp", f"Content-Length: {len(b)}"]
        if auth: L.insert(8, f"{hdr}: {auth}")
        return ("\r\n".join(L) + "\r\n\r\n").encode() + b
    b1 = "z9hG4bK" + rid(16)
    with wlock: waiters[cs.x_callid] = []
    u3.sendto(mk(1, b1), SBC)
    r = wait_invite(cs.x_callid, 6, cseq=1)
    if r and (" 407 " in r.split("\r\n")[0] or " 401 " in r.split("\r\n")[0]):
        st = r.split("\r\n")[0]
        hh = [l for l in r.split("\r\n") if l.lower().startswith(("www-authenticate", "proxy-authenticate"))]
        realm, nonce, qop, opaque = parse_auth(hh[0]); _, h407, _ = parse(r)
        ack = [f"ACK sip:{cs.dst}@{DOMAIN} SIP/2.0", f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch={b1}",
               "Max-Forwards: 70", f"From: <sip:{cs.ext}@{DOMAIN}>;tag={cs.x_ftag}", f"To: {H(h407,'to')}",
               f"Call-ID: {cs.x_callid}", "CSeq: 1 ACK", "Content-Length: 0"]
        u3.sendto(("\r\n".join(ack) + "\r\n\r\n").encode(), SBC)
        hdr = "Proxy-Authorization" if " 407 " in st else "Authorization"
        auth = digest("INVITE", f"sip:{cs.dst}@{DOMAIN}", realm, nonce, qop, rid(16), "00000001", opaque, cs.authid, cs.password)
        b2 = "z9hG4bK" + rid(16)
        with wlock: waiters[cs.x_callid] = []
        u3.sendto(mk(2, b2, auth, hdr), SBC)
        r = wait_invite(cs.x_callid, 35, cseq=2, cs=cs)
    return r

def wait_invite(callid, timeout, cseq=None, cs=None):
    end = time.time() + timeout; last = None; rang = False
    while time.time() < end:
        with wlock: q = list(waiters.get(callid, []))
        for m in q:
            _, h, _ = parse(m)
            if cseq is not None and not H(h, "cseq").strip().startswith(f"{cseq} "): continue
            code = int(m.split("\r\n")[0].split()[1])
            if code >= 200: return m
            if code in (180, 183) and cs is not None and not rang:
                rang = True
                try: cs.pc.sendall(p_resp(180, "Ringing", cs.ph, cs.p_addr, "INVITE"))
                except Exception: pass
            last = m
        time.sleep(0.05)
    return last

def x_ack_ok(resp, cs):
    _, h, _ = parse(resp); to = H(h, "to")
    ruri = uri_of(H(h, "contact")) or f"sip:{cs.dst}@{DOMAIN}"
    L = [f"ACK {ruri} SIP/2.0", f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch=z9hG4bK{rid(16)};rport"]
    for rt in reversed(h.get("record-route", [])): L.append(f"Route: {rt}")
    L += ["Max-Forwards: 70", f"From: <sip:{cs.ext}@{DOMAIN}>;tag={cs.x_ftag}", f"To: {to}",
          f"Call-ID: {cs.x_callid}", "CSeq: 2 ACK", "Content-Length: 0"]
    u3.sendto(("\r\n".join(L) + "\r\n\r\n").encode(), SBC)

# ----------------------------- phone side: TLS 5061 + CAS 5448 -----------------------------
def tlsctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
    try: ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception: pass
    try: ctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception: pass
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE; return ctx
def mktag(s2): return md5(s2)[:10]

def p_resp(code, reason, hdrs, addr, method, sdp=None):
    vias = hdrs.get("via", []); vlines = []
    for i, v in enumerate(vias):
        if i == 0 and "received=" not in v: v = v + f";received={addr[0]};rport={addr[1]}"
        vlines.append(f"Via: {v}")
    frm = H(hdrs, "from"); to = H(hdrs, "to")
    if to and ";tag=" not in to: to = to + ";tag=" + mktag(H(hdrs, "call-id") + "srv")
    L = [f"SIP/2.0 {code} {reason}"] + vlines + [f"From: {frm}", f"To: {to}",
         f"Call-ID: {H(hdrs,'call-id')}", f"CSeq: {H(hdrs,'cseq')}"]
    if method in ("REGISTER", "SUBSCRIBE"):
        ct = H(hdrs, "contact")
        if ct: L.append(f"Contact: {ct};expires=3600")
        L.append("Expires: 3600")
    if method == "INVITE": L.append(f"Contact: <sips:switch@{MYIP}:5061;transport=tls>")
    L.append("Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, SUBSCRIBE, NOTIFY, REFER, UPDATE, PRACK, MESSAGE")
    if sdp:
        b = sdp.encode(); L.append("Content-Type: application/sdp"); L.append(f"Content-Length: {len(b)}")
        return ("\r\n".join(L) + "\r\n\r\n").encode() + b
    L.append("Content-Length: 0"); return ("\r\n".join(L) + "\r\n\r\n").encode()

def phone_invite(conn, mac, hdrs, body, addr):
    to = H(hdrs, "to"); m = re.search(r'sips?:([^@>]+)@', to); dst = m.group(1) if m else "0"
    creds = creds_for_mac(mac)
    if not creds:                                  # no MAC on this connection yet -> identify by source IP
        alt = mac_for_ip(addr[0])
        if alt:
            log(f"INVITE with no MAC on connection; identified {alt} by IP {addr[0]}")
            mac = alt; creds = creds_for_mac(mac)
    if not creds:
        log(f"unconfigured phone {mac} tried to dial {dst}")
        conn.sendall(p_resp(403, "Forbidden", hdrs, addr, "INVITE")); return
    ext, authid, password = creds
    log(f"phone {mac} (ext {ext}) dialed {dst}")
    cs = CallSession(dst, conn, mac, ext, authid, password)
    cs.p_callid = H(hdrs, "call-id"); cs.ph = hdrs; cs.p_addr = addr; cs.phone_rtp = sdp_media(body)
    CALLS[cs.p_callid] = cs; CALLS[cs.x_callid] = cs
    conn.sendall(p_resp(100, "Trying", hdrs, addr, "INVITE"))
    r = x_invite(cs)
    if not r:
        log("PBX no answer"); conn.sendall(p_resp(504, "Server Timeout", hdrs, addr, "INVITE")); cs.teardown(); return
    code = int(r.split("\r\n")[0].split()[1])
    if code >= 300:
        log(f"PBX rejected: {r.splitlines()[0]}")
        conn.sendall(p_resp(code if code < 700 else 486, "Declined", hdrs, addr, "INVITE")); cs.teardown(); return
    _, xh, xb = parse(r); cs.x_rtp = sdp_media(xb); cs.x_totag = H(xh, "to"); x_ack_ok(r, cs)
    cs.pbx_te = sdp_te_pt(xb) or 101; cs.phone_te = sdp_te_pt(body) or 102
    cs.x_dialog = {'ruri': uri_of(H(xh, "contact")) or f"sip:{dst}@{DOMAIN}", 'transport': 'UDP', 'lport': P3CX,
                   'local': f"<sip:{ext}@{DOMAIN}>", 'ltag': cs.x_ftag, 'remote': H(xh, "to"),
                   'callid': cs.x_callid, 'route': list(reversed(xh.get("record-route", []))), 'cseq': 2}
    cs.p_dialog = {'ruri': uri_of(H(hdrs, "contact")) or f"sips:anonymous@{addr[0]}:5061", 'transport': 'TLS', 'lport': 5061,
                   'local': H(hdrs, "to"), 'ltag': mktag(cs.p_callid + "srv"), 'remote': H(hdrs, "from"),
                   'callid': cs.p_callid, 'route': [], 'cseq': 1, 'conn': conn}
    threading.Thread(target=cs.relay, daemon=True).start()
    ans = ("v=0\r\n" f"o=switch 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rpP} RTP/AVP 0 {cs.phone_te}\r\n" "a=rtpmap:0 PCMU/8000\r\n" f"a=rtpmap:{cs.phone_te} telephone-event/8000\r\n" "a=ptime:20\r\n" "a=sendrecv\r\n"
           "m=audio 0 RTP/SAVP 0\r\n")
    conn.sendall(p_resp(200, "OK", hdrs, addr, "INVITE", sdp=ans))
    cs.t_up = time.time()
    log(f"call up: ext {ext} <-> {dst}")

PHONE_IPS_JSON = os.path.join(DATA, "phone_ips.json")
def save_phone_ips():
    """Persist MAC -> last IP so that right after a bridge restart CAS can still tell
    which phone is talking (the phone reconnects CAS ~2 min before it re-registers SIP)."""
    try:
        tmp = PHONE_IPS_JSON + ".tmp"
        with open(tmp, "w") as f: json.dump(PHONE_IPS, f, indent=1)
        os.replace(tmp, PHONE_IPS_JSON)
    except Exception as e: log("save phone ips err " + repr(e))
def load_phone_ips():
    try:
        with open(PHONE_IPS_JSON) as f: d = json.load(f)
        if isinstance(d, dict): PHONE_IPS.update({norm_mac(k) or k: v for k, v in d.items()})
    except Exception: pass

def register_phone(conn, hdrs, addr):
    """Handle a phone REGISTER: identify by MAC, attach its connection; unknown MACs go to SEEN for the UI."""
    mac = mac_from_contact(H(hdrs, "contact")) or ("ip-" + addr[0].replace(".", "-"))
    ct = uri_of(H(hdrs, "contact"))
    with pstate:
        CONNS[mac] = conn
        changed = PHONE_IPS.get(mac) != addr[0]
        PHONE_IPS[mac] = addr[0]            # so CAS (a separate connection) can map IP -> extension
        if changed: save_phone_ips()
        if ct: CONTACTS[mac] = ct
        if mac in PHONES:
            SEEN.pop(mac, None); known = True
        else:
            SEEN[mac] = {"ip": addr[0], "ts": int(time.time())}; known = False
    if not known:
        log(f"unconfigured phone seen: {mac} ({addr[0]}) - assign it at http://{MYIP}:{UI_PORT}")
    return mac

def phone_handle(conn, addr):
    mymac = None; buf = b""; conn.settimeout(300)
    try:
        while True:
            while buf[:2] == b"\r\n": buf = buf[2:]
            if b"\r\n\r\n" not in buf:
                try: d = conn.recv(4096)
                except socket.timeout: continue
                if not d: return
                if d.strip(b"\r\n") == b"" and buf == b"": conn.sendall(b"\r\n"); continue
                buf += d; continue
            head, _, rest = buf.partition(b"\r\n\r\n")
            if head.strip() == b"": conn.sendall(b"\r\n"); buf = rest; continue
            cl = 0
            for line in head.decode("utf-8", "replace").split("\r\n"):
                if line.lower().startswith("content-length:"):
                    try: cl = int(line.split(":", 1)[1].strip() or 0)
                    except Exception: cl = 0
            while len(rest) < cl:
                d = conn.recv(4096)
                if not d: break
                rest += d
            body = rest[:cl]; buf = rest[cl:]
            msg = (head + b"\r\n\r\n" + body).decode("utf-8", "replace")
            start, hdrs, b = parse(msg); parts = start.split()
            if not parts: continue
            if DEBUG:   # full capture of the phone->switch channel (uaCSTA dialog, bodies)
                dbg("PHONE >>>>\n" + msg.strip() + "\n<<<< end")
            if start.startswith("SIP/2.0"):
                cid = H(hdrs, "call-id")
                with pinlock:
                    if cid in PIN: PIN[cid].append(msg)
                # ACK a non-2xx final response to an INVITE we sent the phone (e.g. 487 after CANCEL),
                # else the phone's transaction hangs and it loses dial tone.
                try: code = int(parts[1])
                except Exception: code = 0
                if code >= 300 and "INVITE" in H(hdrs, "cseq"):
                    cs = CALLS.get(cid)
                    if cs and getattr(cs, "p_inv", None):
                        iv = cs.p_inv; cseqn = H(hdrs, "cseq").split()[0]
                        ack = [f"ACK {iv['contact']} SIP/2.0",
                               f"Via: SIP/2.0/TLS {MYIP}:5061;branch={iv['branch']}", "Max-Forwards: 70",
                               f"From: {iv['from']}", f"To: {H(hdrs,'to')}",
                               f"Call-ID: {cid}", f"CSeq: {cseqn} ACK", "Content-Length: 0"]
                        try: conn.sendall(("\r\n".join(ack) + "\r\n\r\n").encode())
                        except Exception: pass
                continue
            method = parts[0]
            if method == "ACK": continue
            if method == "REGISTER":
                mymac = register_phone(conn, hdrs, addr)
                conn.sendall(p_resp(200, "OK", hdrs, addr, method))
                if mymac: threading.Timer(2.0, push_mwi_to_phone, args=(mymac,)).start()
            elif method == "INVITE":
                cs = CALLS.get(H(hdrs, "call-id"))
                if cs and cs.alive and ";tag=" in H(hdrs, "to"):  # in-dialog re-INVITE (hold/resume/refresh)
                    try: phone_reinvite(conn, cs, hdrs, b, addr)
                    except Exception as e: log(f"phone re-INVITE err {e!r}")
                else:
                    threading.Thread(target=phone_invite, args=(conn, mymac, hdrs, b, addr), daemon=True).start()
            elif method == "SUBSCRIBE":
                ev = H(hdrs, "event")
                log(f"phone {mymac} SUBSCRIBE Event: {ev} Accept: {H(hdrs, 'accept')[:120]}")
                if ev.split(";")[0].strip().lower() == "ua-profile":
                    threading.Thread(target=ua_profile_subscribe, args=(conn, mymac, hdrs, addr), daemon=True).start()
                else:
                    conn.sendall(p_resp(200, "OK", hdrs, addr, method))
            elif method == "BYE":
                cs = CALLS.get(H(hdrs, "call-id"))
                conn.sendall(p_resp(200, "OK", hdrs, addr, method))
                if cs: cs.teardown(origin="phone")
            else:
                conn.sendall(p_resp(200, "OK", hdrs, addr, method))
    except Exception as e:
        log(f"phone conn err {repr(e)}")
    finally:
        if mymac:
            with pstate:
                if CONNS.get(mymac) is conn: CONNS.pop(mymac, None)
        try: conn.close()
        except Exception: pass

# ----------------------------- CAS: ShoreTel Client Application Server -----------------------------
# CAS is JSON over TLS on :5448. The phone uses it for its identity (the user name
# shown on the idle title bar after login / the "Assign" button) and the directory.
# The flow the firmware drives (reverse-engineered from the p8_phone binary):
#   POST /            body "expiry=N"          -> session manager: open a session
#   POST /Login?      body {ticket,app-id,..}  -> CAS login: returns the SessionId used below
#   POST /Execute?SessionId=..  {topic:..}     -> queries; topic "find" = directory lookup
#   GET  /GetEvents?SessionId=..&timeout=N     -> long-poll event channel (presence/config)
#   GET/POST /Logout?SessionId=..              -> teardown
# We ARE the CAS server, so we accept any login and synthesize the answers.
CAS_LOCK = threading.Lock()
CAS_SESSIONS = {}            # SessionId -> {"ext": str, "user": str}
CAS_EVENTS = {}              # SessionId -> [event dict] pending for the GetEvents long-poll
LIVE_SESSION = {}            # client-ip -> SessionId the phone is currently polling (debugger)
DIRECTORY_JSON = os.path.join(os.path.dirname(CFG_PATH), "directory.json")

def load_directory():
    """Directory-only entries the user adds in the UI: [{"name","number","type"}].
    These are contacts (e.g. a mobile reached by dialing 11) that are not phones."""
    try:
        with open(DIRECTORY_JSON) as f:
            d = json.load(f); return d if isinstance(d, list) else []
    except Exception:
        return []

def save_directory(entries):
    tmp = DIRECTORY_JSON + ".tmp"
    with open(tmp, "w") as f: json.dump(entries, f, indent=2)
    os.replace(tmp, DIRECTORY_JSON)
    try: os.chmod(DIRECTORY_JSON, 0o600)
    except Exception: pass

def _split_name(s):
    s = (s or "").strip()
    if "," in s:                                   # "Last, First"
        last, first = s.split(",", 1); return first.strip(), last.strip()
    parts = s.split()
    if len(parts) >= 2: return parts[0], " ".join(parts[1:])
    return s, ""

def cas_contacts():
    """Assemble the directory from registered phones + directory-only entries +
    any connector catalog. -> [{id, first, last, points:[{type,addr}]}]."""
    out, seen = [], set()
    for mac, p in sorted(PHONES.items()):
        ext = str(p.get("extension", "")).strip()
        if not ext or ext in seen: continue
        seen.add(ext); first, last = _split_name(p.get("label") or ext)
        out.append({"id": "ph-" + ext, "first": first, "last": last,
                    "points": [{"type": "extension", "addr": ext}]})
    for e in load_directory():
        num = str(e.get("number", "")).strip()
        if not num or num in seen: continue
        seen.add(num); first, last = _split_name(e.get("name") or num)
        out.append({"id": "dir-" + num, "first": first, "last": last,
                    "points": [{"type": e.get("type", "mobile"), "addr": num}]})
    for x in CATALOG:
        ext = str(getattr(x, "number", "")).strip()
        if not ext or ext in seen: continue
        seen.add(ext); first, last = _split_name(getattr(x, "display_name", "") or ext)
        out.append({"id": "cat-" + ext, "first": first, "last": last,
                    "points": [{"type": "extension", "addr": ext}]})
    return out

# contact-point type -> ShoreTel numeric kind (best-effort; iterated against the phone)
_CP_TYPE = {"extension": 1, "did": 2, "mobile": 3, "home": 4, "work": 5, "fax": 6, "external": 2}

def cas_find_response(req):
    """Build the directory result for a topic:find / lookup-chunked Execute.

    The phone's contact parser (contact::fromJsonHeader + contact::fromJson, both
    erroring "not an array") uses a COLUMNAR layout: each collection is an array
    whose element[0] is the header (the field names in order) and elements[1..] are
    positional rows. Contact-points nest the same way inside each contact row."""
    CHDR = ["id", "source-type", "source-name", "first", "last", "rec-type", "contact-points"]
    PHDR = ["id", "type", "addr", "addr-canonical", "field", "features"]
    contacts = [CHDR]
    for c in cas_contacts():
        points = [PHDR]
        for i, p in enumerate(c["points"]):
            t = _CP_TYPE.get(p.get("type"), 1)
            # "field" is the ShoreTel contact field-type code. getCallableContactPoints
            # only treats a point as dialable when its field is in
            # {10,75,100,200,511,521,531,541,551}; 100 = a callable phone field.
            # With field=0 the entry shows in the directory but won't dial.
            points.append([i, t, p["addr"], p["addr"], 100, 0])
        contacts.append([c["id"], 1, "shorebridge", c["first"], c["last"], 0, points])
    return {"request-id": req.get("request-id", 0), "topic": "find",
            "message": "lookup-chunked", "cursor": "", "total-count": len(contacts) - 1,
            "contacts": contacts}

def phone_for_ip(ip):
    """Map a CAS client IP back to its configured extension + label (name), via the
    MAC->IP recorded at SIP registration. Returns (extension, label) or (None, None)."""
    for mac, mip in list(PHONE_IPS.items()):
        if mip == ip and mac in PHONES:
            p = PHONES[mac]; return p.get("extension", ""), p.get("label", "")
    return None, None

def cas_user_name(ext, label):
    first, last = _split_name(label or ext)
    return {"firstName": first, "lastName": last, "first": first, "last": last,
            "did": ext, "extension": ext, "displayName": (label or ext),
            "name": (label or ext)}

UNAUTH = object()   # sentinel: make cas_handle answer HTTP 401 (forces the phone to re-login)

# ---- Options-menu PIN ("voicemail password" prompt) ----
# The phone sends md5(PIN digits) as lowercase hex in "pwd". Each phone's PIN is kept
# the same way in phones.json ("tui_pwd_md5"). No PIN set -> any PIN opens Options
# (never lock the user out). 5 wrong tries -> Options locked for 5 minutes.
PIN_FAILS = {}               # mac -> [fail_count, locked_until]
PIN_MAX_FAILS, PIN_LOCK_SECS = 5, 300
def _is_md5(v): return isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]{32}", v or "") is not None
def pin_md5(pin): return hashlib.md5(str(pin).encode()).hexdigest()

def cas_pin(msg, req, ext):
    rid_ = req.get("request-id", 0)
    ok = {"request-id": rid_, "topic": "config", "message": msg, "response": 0, "error": 0}
    bad = {"request-id": rid_, "topic": "config", "message": msg, "response": 1, "error": 1,
           "error-message": "Invalid password", "results": {}}
    mac = mac_for_ext(ext) if ext else None
    if not mac:
        log(f"CAS {msg}: unidentified phone -> refused")
        return bad
    with pstate: stored = PHONES.get(mac, {}).get("tui_pwd_md5", "")
    if msg == "authenticate-tui-pwd":
        fails, until = PIN_FAILS.get(mac, [0, 0])
        if until > time.time():
            log(f"CAS PIN check {mac}: locked out for {int(until - time.time())}s more"); return bad
        given = str(req.get("pwd", "")).lower()
        if not stored or given == stored.lower():
            PIN_FAILS.pop(mac, None)
            log(f"CAS PIN check {mac}: accepted" + ("" if stored else " (no PIN set)"))
            return {**ok, "results": {"must-change": False}, "must-change": False}
        fails += 1
        PIN_FAILS[mac] = [fails, time.time() + PIN_LOCK_SECS if fails >= PIN_MAX_FAILS else 0]
        log(f"CAS PIN check {mac}: WRONG PIN ({fails}/{PIN_MAX_FAILS})"
            + (" -> locked 5 min" if fails >= PIN_MAX_FAILS else ""))
        return bad
    # set-tui-pwd: field names not known yet -> log keys only (never values), take the
    # md5 that looks like the NEW pin, and require the old one when a PIN is set.
    log(f"CAS set-tui-pwd {mac}: fields {sorted(k for k in req if k not in ('request-id','topic','message'))}")
    hashes = {k: str(v).lower() for k, v in req.items() if _is_md5(v)}
    new = next((v for k, v in hashes.items() if "new" in k), None)
    old = next((v for k, v in hashes.items() if "old" in k or "cur" in k), None)
    if new is None and len(hashes) == 1: new = next(iter(hashes.values()))
    if not new:
        log(f"CAS set-tui-pwd {mac}: no new PIN found in request -> refused"); return bad
    if stored and old is not None and old != stored.lower():
        log(f"CAS set-tui-pwd {mac}: old PIN wrong -> refused"); return bad
    with pstate:
        if mac in PHONES: PHONES[mac]["tui_pwd_md5"] = new
    save_phones(); PIN_FAILS.pop(mac, None)
    log(f"CAS set-tui-pwd {mac}: PIN changed from the phone")
    return {**ok, "results": {}}

def cas_set_prog_buttons(req, ext):
    """Phone's Options > Programmable Keys: store the button(s) in the phone's layout
    (columnar CAS rows) and regenerate its config so it survives the next reload."""
    rid_ = req.get("request-id", 0)
    ok = {"request-id": rid_, "topic": "config", "message": "set-prog-buttons", "response": 0,
          "error": 0, "results": {}}
    mac = mac_for_ext(ext) if ext else None
    rows = req.get("buttons") or []
    if not mac or not rows or not isinstance(rows[0], list):
        log(f"CAS set-prog-buttons: {'unidentified phone' if not mac else 'no rows'}"); return ok
    hdr = rows[0]; saved = []
    for r in rows[1:]:
        f = dict(zip(hdr, r))
        try: num = int(f.get("button-num", 0))
        except Exception: continue
        if num < 1: continue
        if f.get("btn-box"):
            try: box = max(1, int(f.get("dev-order", 1)))
            except Exception: box = 1
            sk = bb_sk(box, num)
        else:
            sk = num
        try: func = int(f.get("func-id", 1))
        except Exception: func = 1
        with pstate:
            btns = PHONES.get(mac, {}).setdefault("buttons", {})
            if func in (0, 1): btns.pop(str(sk), None)
            else:
                btns[str(sk)] = {"func": func, "target": str(f.get("target", "")),
                                 "target2": str(f.get("target2", "")),
                                 "label": str(f.get("label") or f.get("long-label") or ""),
                                 "long": str(f.get("long-label") or f.get("label") or "")}
        saved.append(f"SK={sk} {PROG_FUNC_NAMES.get(func, func)} {f.get('target', '')}")
    save_phones()
    try: write_phoneconfig()
    except Exception as e: log(f"phoneconfig rewrite failed: {e!r}")
    log(f"CAS set-prog-buttons {mac}: stored {', '.join(saved) or 'nothing'} (the phone keeps it locally; bridge only records it)")
    return ok

CAS_OVERRIDES_JSON = os.path.join(DATA, "cas_overrides.json")
def cas_override(topic, msg, rid_):
    """Reply for "<topic>/<message>" from cas_overrides.json, re-read on every request
    so reply shapes can be tried without a restart. "$rid" is replaced by the
    request-id. No file / no entry -> None (normal handling)."""
    try:
        with open(CAS_OVERRIDES_JSON) as f: table = json.load(f)
    except Exception: return None
    tpl = table.get(f"{topic}/{msg}")
    if not isinstance(tpl, dict): return None
    def fill(v):
        if isinstance(v, dict): return {k: fill(x) for k, x in v.items()}
        if isinstance(v, list): return [fill(x) for x in v]
        return rid_ if v == "$rid" else v
    return fill(tpl)

def _session_ok(target):
    sid = parse_qs(urlparse(target).query).get("SessionId", [""])[0]
    with CAS_LOCK:
        return bool(sid) and sid in CAS_SESSIONS

def cas_dispatch(method, target, body, client_ip=""):
    """Return a JSON-serialisable dict for a CAS request, or None to long-poll.

    Login hands the phone a user identity (the extension mapped from its IP) so the
    phone treats a user as logged in and asks for that user's name via
    getExtensionProperties -- which we answer to populate the idle-screen title bar.
    The Assign (tn+pin) flow is still left alone (it drops the line to No Service)."""
    path = urlparse(target).path
    ext, label = phone_for_ip(client_ip)
    if path == "/" or path == "":                  # session manager: authenticate the user
        if not ext:
            return {"Status": "OK"}                 # unknown phone: anonymous (safe)
        sid = "S" + rid(16)
        with CAS_LOCK: CAS_SESSIONS[sid] = {"ext": ext, "label": label}
        # Establish the current user here (this is what the title bar's user config
        # reads). logon-server-ip is a BARE host. session-id + user-id set the user.
        return {"session-id": sid, "user-id": ext, "logon-server-ip": MYIP}
    if path.startswith("/Login"):                  # CAS login -> establish the user
        if not ext:
            return {"Status": "OK"}                 # unknown phone: stay anonymous (safe)
        sid = "S" + rid(16)
        with CAS_LOCK: CAS_SESSIONS[sid] = {"ext": ext, "label": label}
        # Do NOT return home-cas: the firmware treats it as "home CAS server changed"
        # and re-bootstraps -> POST / -> Login -> sees it again -> infinite login loop.
        # Omitting it keeps the phone on us. user-id is what makes it fetch its name.
        return {"SessionId": sid, "loggable-id": ext, "user-id": ext, "user-role": "user"}
    if path.startswith("/Logout"):
        return {"Status": "OK"}
    if path.startswith("/Execute"):
        # Force re-login if the session is stale/empty (e.g. after a bridge restart,
        # or the phone's cached anonymous session): 401 -> phone runs Login again and
        # picks up its identity. Only for phones we can identify (ext known).
        if ext and not _session_ok(target):
            return UNAUTH
        try: req = json.loads(body or "{}")
        except Exception: req = {}
        # The phone batches requests as a JSON array (e.g. two history get-recs after a
        # call). Answer each one and return an array. Previously this crashed the
        # handler, the phone got no reply and fell into a re-login loop.
        if isinstance(req, list):
            return [cas_dispatch(method, target, json.dumps(x), client_ip)
                    for x in req if isinstance(x, dict)]
        if not isinstance(req, dict): req = {}
        topic, msg = req.get("topic"), req.get("message")
        rid_ = req.get("request-id", 0)
        log(f"CAS Execute topic={topic} message={msg}")
        if topic == "config" and msg in ("authenticate-tui-pwd", "set-tui-pwd"):
            return cas_pin(msg, req, ext)
        if topic == "config" and msg == "set-prog-buttons":
            return cas_set_prog_buttons(req, ext)
        ov = cas_override(topic, msg, rid_)       # hot-editable reply (cas_overrides.json)
        if ov is not None:
            log(f"CAS {topic}/{msg} -> override reply: {json.dumps(ov)[:300]}")
            return ov
        if topic == "find":
            return cas_find_response(req)
        if topic == "tel" and msg == "reset-missed-call-count":
            log("CAS reset-missed-call-count -> ok")
            return {"request-id": rid_, "topic": topic, "message": msg, "response": 0}
        if topic == "history":                     # call log -> phone History screen
            return cas_history_response(req, ext,
                                        parse_qs(urlparse(target).query).get("SessionId", [""])[0])
        first, last = _split_name(label or ext or "")
        eprops = {"ext": ext, "did": ext, "firstname": first, "lastname": last,
                  "firstName": first, "lastName": last, "display-name": (label or ext),
                  "phone-assignment": "PRIMARY-PHONE", "phone-assignment-descr": "Primary phone"}
        # the "Assign user to phone" sequence (the path that sets the title-bar name)
        if msg == "authenticate-tui-pwd":          # verify the PIN -> accept any
            # The phone reads "response" (int, AsInt; 0 = ok) and "must-change" (bool),
            # NOT "result". Wrong key = it never sees the auth succeed and stalls.
            log("CAS authenticate-tui-pwd -> accepted (response=0)")
            return {"request-id": rid_, "response": 0, "must-change": False}
        if msg == "assign-to-phone":               # assign this user to the phone
            # Queue the completion event HERE (delivery on assign-to-phone provably reaches
            # telephonyFinalResponse; after auth the pending request is cleared). response
            # MUST be negative -> assignUserStatus(<0) success path -> sets the user/name.
            sid = parse_qs(urlparse(target).query).get("SessionId", [""])[0]
            evt = {"topic": "tel", "message": "tel-completion-evt",
                   "name": "assign-to-phone", "response": -1, "error": 0}
            with CAS_LOCK: CAS_EVENTS.setdefault(sid, []).append(evt)
            log(f"CAS assign-to-phone -> {ext} ({label}); queued completion (response=-1)")
            return {"request-id": rid_, "topic": topic, "message": msg, "Status": "OK"}
        if msg in ("get-ext-props", "getExtensionProperties", "get-extension-properties") \
           or "extensionproperties" in (body or "").lower():
            log(f"CAS get-ext-props -> {label or ext}")
            return {"request-id": rid_, "topic": topic, "message": msg,
                    "result": True, "ext-props": eprops, **eprops}
        # subscribe / unsubscribe / everything else: acknowledge
        return {"request-id": rid_, "topic": topic, "message": msg, "Status": "OK"}
    if path.startswith("/GetEvents"):
        sid = parse_qs(urlparse(target).query).get("SessionId", [""])[0]
        if sid and client_ip: LIVE_SESSION[client_ip] = sid   # for the debugger push
        if ext and not _session_ok(target):
            return UNAUTH                          # stale session -> re-login
        return None                                # signal: long-poll
    return {"Status": "OK"}

def _read_http(conn, buf):
    """Read one HTTP request off a (keep-alive) connection. Returns
    (method, target, headers, body, leftover_buf) or None at EOF."""
    while b"\r\n\r\n" not in buf:
        d = conn.recv(4096)
        if not d: return None
        buf += d
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("utf-8", "replace").split("\r\n")
    try: method, target, _ = lines[0].split(" ", 2)
    except ValueError: return None
    headers = {}
    for ln in lines[1:]:
        if ":" in ln: k, v = ln.split(":", 1); headers[k.strip().lower()] = v.strip()
    cl = int(headers.get("content-length", "0") or 0)
    while len(rest) < cl:
        d = conn.recv(4096)
        if not d: break
        rest += d
    body = rest[:cl].decode("utf-8", "replace"); leftover = rest[cl:]
    return method, target, headers, body, leftover

def cas_handle(conn, addr):
    try:
        conn.settimeout(310); buf = b""
        while True:
            got = _read_http(conn, buf)
            if not got: break
            method, target, headers, body, buf = got
            log(f"CAS req: {method} {target}")
            if DEBUG:
                raw = "\n".join(f"{k}: {v}" for k, v in headers.items())
                log("CAS REQUEST >>>>\n" + f"{method} {target}\n" + raw +
                    (("\n\n" + body) if body else "") + "\n<<<< end")
            result = cas_dispatch(method, target, body, client_ip=addr[0])
            if result is UNAUTH:                    # stale session -> 401 forces a re-login
                b401 = b'{"error":401,"message":"session invalid"}'
                conn.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n"
                             b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(b401), b401))
                break
            if result is None:                     # GetEvents long-poll
                q = parse_qs(urlparse(target).query)
                sid = q.get("SessionId", [""])[0]
                try: wait = min(int(q.get("timeout", ["30"])[0]), 50)
                except Exception: wait = 30
                ev = []
                for _ in range(max(1, int(wait / 0.25))):   # wake early when an event is queued
                    with CAS_LOCK: ev = CAS_EVENTS.pop(sid, [])
                    if ev: break
                    time.sleep(0.25)
                # The phone's event parser expects a bare event object with "topic" at
                # top level (it discards a wrapper like {"events":[...]}). Deliver the
                # event object directly; an empty poll keeps the known-safe shape.
                if ev:
                    log(f"CAS GetEvents -> delivering {len(ev)} event(s)")
                    result = ev                    # bare array of event objects
                else:
                    result = {"events": []}
            payload = json.dumps(result).encode()
            keep = "keep-alive" in headers.get("connection", "").lower()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: %d\r\nConnection: %s\r\n\r\n%s"
                % (len(payload), b"keep-alive" if keep else b"close", payload))
            if not keep: break
    except (ConnectionResetError, BrokenPipeError, socket.timeout, ssl.SSLError) as e:
        if DEBUG: log("CAS err " + repr(e))         # phone hung up / long-poll ended: normal
    except Exception as e:
        log("CAS err " + repr(e))                   # real handler bug: always log
    finally:
        try: conn.close()
        except Exception: pass

def tls_server(port, handler):
    ctx = tlsctx(); s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Retry the bind: on a quick service restart the previous process may not have
    # released the port yet. Without this, a transient bind error would kill the
    # thread and the port (notably CAS :5448) would silently never come up.
    for attempt in range(10):
        try:
            s.bind(("0.0.0.0", port)); break
        except OSError as e:
            log(f"TLS :{port} bind failed ({e}); retrying"); time.sleep(1)
    else:
        log(f"TLS :{port} could not bind after retries"); return
    s.listen(16); log(f"TLS server on :{port}")
    while True:
        # Never let one bad accept/handshake kill the accept loop (and with it the
        # listening socket) -- catch everything and keep serving.
        try:
            c, a = s.accept()
            if DEBUG: dbg(f"TCP connect :{port} from {a[0]}")
            try:
                tc = ctx.wrap_socket(c, server_side=True)
                threading.Thread(target=handler, args=(tc, a), daemon=True).start()
            except ssl.SSLError as e:
                if DEBUG: dbg(f"TLS handshake FAILED :{port} from {a[0]}: {e}")
                try: c.close()
                except Exception: pass
        except Exception as e:
            log(f"TLS :{port} accept error: {e!r}"); time.sleep(0.2)

# ----------------------------- inbound: PBX -> phone -----------------------------
def inbound_invite(xh, xraw, xaddr):
    _, _, xbody = parse(xraw)
    to = H(xh, "to"); m = re.search(r'sips?:([^@>;]+)@', uri_of(to) or to)
    ext = m.group(1) if m else ""
    mac = mac_for_ext(ext)
    conn = CONNS.get(mac) if mac else None
    if not conn:
        log(f"inbound for ext {ext}: no phone online"); u3.sendto(resp_line(480, "Unavailable", xh).encode(), xaddr); return
    fm = re.search(r'sips?:([^@>;]+)', H(xh, "from")); caller = fm.group(1) if fm else "unknown"
    cs = CallSession("inbound", conn, mac, ext, "", "")
    cs.direction = "in"; cs.peer = caller
    cs.x_callid = H(xh, "call-id"); cs.x_rtp = sdp_media(xbody); cs.pbx_te = sdp_te_pt(xbody) or 101
    cs.p_callid = rid(16) + "@" + MYIP; cs.p_ftag = rid(8)
    CALLS[cs.x_callid] = cs; CALLS[cs.p_callid] = cs
    with pstate:
        contact = CONTACTS.get(mac)
    phone_uri = contact or f"sips:anonymous@{xaddr_ip(conn)}:5061"
    u3.sendto(resp_line(100, "Trying", xh).encode(), xaddr)
    sdp = ("v=0\r\n" f"o=switch 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rpP} RTP/AVP 0 102\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:102 telephone-event/8000\r\n" "a=ptime:20\r\n" "a=sendrecv\r\n")
    b = sdp.encode(); pbranch = "z9hG4bK" + rid(16)
    cs.p_inv = {"branch": pbranch, "contact": phone_uri,
                "from": f"<sips:{caller}@{MYIP}>;tag={cs.p_ftag}", "callid": cs.p_callid, "conn": conn}
    inv = ("\r\n".join([
        f"INVITE {phone_uri} SIP/2.0",
        f"Via: SIP/2.0/TLS {MYIP}:5061;branch={pbranch};rport", "Max-Forwards: 70",
        f"From: <sips:{caller}@{MYIP}>;tag={cs.p_ftag}", f"To: <{phone_uri}>",
        f"Call-ID: {cs.p_callid}", "CSeq: 1 INVITE",
        f"Contact: <sips:switch@{MYIP}:5061;transport=tls>", "User-Agent: ShoreBridge/1.0",
        "Content-Type: application/sdp", f"Content-Length: {len(b)}"]) + "\r\n\r\n").encode() + b
    with pinlock: PIN[cs.p_callid] = []
    log(f"inbound from {caller} -> ext {ext} (ringing phone {mac})")
    try: conn.sendall(inv)
    except Exception:
        u3.sendto(resp_line(480, "Unavailable", xh).encode(), xaddr); cs.teardown(); return
    if CSTA_AUTOANSWER:   # test mode: fire AnswerCall ~3s into the ring to prove it answers
        def _autoanswer():
            time.sleep(3)
            if cs.alive and not cs.p_totag:
                log("CSTA test: auto-firing AnswerCall")
                send_to_phone_csta(mac, csta_preset("answercall", "", dev=mac_colon(mac)))
        threading.Thread(target=_autoanswer, daemon=True).start()
    got_ring = False; end = time.time() + 45; final = None
    while time.time() < end and cs.alive:
        with pinlock: q = list(PIN.get(cs.p_callid, []))
        for r in q:
            code = int(r.split("\r\n")[0].split()[1])
            if code in (180, 183) and not got_ring:
                got_ring = True; u3.sendto(resp_line(180, "Ringing", xh).encode(), xaddr)
            if code >= 200: final = r
        if final: break
        time.sleep(0.1)
    if not cs.alive: return
    if not final:
        u3.sendto(resp_line(487, "Request Terminated", xh).encode(), xaddr); cs.teardown(); return
    code = int(final.split("\r\n")[0].split()[1])
    if code >= 300:
        u3.sendto(resp_line(486, "Busy Here", xh).encode(), xaddr); cs.teardown(); return
    _, ph, pb = parse(final); cs.phone_rtp = sdp_media(pb); cs.p_totag = H(ph, "to")
    cs.phone_te = sdp_te_pt(pb) or 102
    ack = ("\r\n".join([
        f"ACK {phone_uri} SIP/2.0", f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)}",
        "Max-Forwards: 70", f"From: <sips:{caller}@{MYIP}>;tag={cs.p_ftag}", f"To: {cs.p_totag}",
        f"Call-ID: {cs.p_callid}", "CSeq: 1 ACK", "Content-Length: 0"]) + "\r\n\r\n").encode()
    try: conn.sendall(ack)
    except Exception: pass
    threading.Thread(target=cs.relay, daemon=True).start()
    osdp = ("v=0\r\n" f"o=bridge 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
            f"m=audio {cs.rp3} RTP/AVP 0 {cs.pbx_te}\r\n" "a=rtpmap:0 PCMU/8000\r\n" f"a=rtpmap:{cs.pbx_te} telephone-event/8000\r\n" "a=sendrecv\r\n")
    ob = osdp.encode(); to2 = H(xh, "to")
    if ";tag=" not in to2: to2 = to2 + ";tag=" + mktag(cs.x_callid + "in")
    L = [f"SIP/2.0 200 OK"] + allvia(xh) + allrr(xh) + [f"From: {H(xh,'from')}", f"To: {to2}",
         f"Call-ID: {cs.x_callid}", f"CSeq: {H(xh,'cseq')}",
         f"Contact: <sip:{ext}@{MYIP}:{P3CX}>", "Content-Type: application/sdp", f"Content-Length: {len(ob)}"]
    u3.sendto(("\r\n".join(L) + "\r\n\r\n").encode() + ob, xaddr)
    cs.x_dialog = {'ruri': uri_of(H(xh, "contact")) or uri_of(H(xh, "from")), 'transport': 'UDP', 'lport': P3CX,
                   'local': H(xh, "to"), 'ltag': mktag(cs.x_callid + "in"), 'remote': H(xh, "from"),
                   'callid': cs.x_callid, 'route': list(reversed(xh.get("record-route", []))), 'cseq': 1}
    cs.p_dialog = {'ruri': phone_uri, 'transport': 'TLS', 'lport': 5061,
                   'local': f"<sips:{caller}@{MYIP}>", 'ltag': cs.p_ftag, 'remote': cs.p_totag,
                   'callid': cs.p_callid, 'route': [], 'cseq': 1, 'conn': conn}
    cs.t_up = time.time()
    log(f"inbound call up: {caller} <-> ext {ext}")

def xaddr_ip(conn):
    try: return conn.getpeername()[0]
    except Exception: return MYIP

# ----------------------------- uaCSTA experiment harness -----------------------------
# Send a CSTA service request DOWN to a phone over its existing TLS connection
# (NOTIFY Event: uaCSTA + application/csta+xml). Returns the phone's reply so we can
# see whether it accepts the service (200 OK + CSTA response) or rejects it.
ED = "http://www.ecma-international.org/standards/ecma-323/csta/ed3"  # match the phone (it uses ed3)
def mac_colon(mac):
    return ":".join(mac[i:i+2] for i in range(0, 12, 2)).upper()
def csta_preset(kind, ext, text="", dev=""):
    d = dev or ext
    if kind == "answercall":
        return f'<AnswerCall xmlns="{ED}"><callToBeAnswered><deviceID>{d}</deviceID></callToBeAnswered></AnswerCall>'
    if kind == "offhook":
        return f'<SetHookswitchStatus xmlns="{ED}"><device>{d}</device><hookswitch>1</hookswitch><hookswitchOnHook>false</hookswitchOnHook></SetHookswitchStatus>'
    if kind == "setdisplay":
        return f'<SetDisplay xmlns="{ED}"><device>{d}</device><contentsOfDisplay>{text}</contentsOfDisplay></SetDisplay>'
    return text  # raw

def csta_probe(mac):
    """Fire a batch of CSTA services and report which the phone implements."""
    dev = mac_colon(mac)
    cands = {
        "GetPhysicalDeviceInformation": f'<GetPhysicalDeviceInformation xmlns="{ED}"><device>{dev}</device></GetPhysicalDeviceInformation>',
        "GetDisplay":                   f'<GetDisplay xmlns="{ED}"><device>{dev}</device></GetDisplay>',
        "GetButtonInformation":         f'<GetButtonInformation xmlns="{ED}"><device>{dev}</device></GetButtonInformation>',
        "GetHookswitchStatus":          f'<GetHookswitchStatus xmlns="{ED}"><device>{dev}</device></GetHookswitchStatus>',
        "GetLampInformation":           f'<GetLampInformation xmlns="{ED}"><device>{dev}</device></GetLampInformation>',
        "GetMessageWaitingIndicator":   f'<GetMessageWaitingIndicator xmlns="{ED}"><device>{dev}</device></GetMessageWaitingIndicator>',
        "GetDeviceId":                  f'<GetDeviceId xmlns="{ED}"><device>{dev}</device></GetDeviceId>',
        "GetSwitchingFunctionCapabilities": f'<GetSwitchingFunctionCapabilities xmlns="{ED}"></GetSwitchingFunctionCapabilities>',
        "SnapshotDevice":               f'<SnapshotDevice xmlns="{ED}"><snapshotObject>{dev}</snapshotObject></SnapshotDevice>',
        "MonitorStart":                 f'<MonitorStart xmlns="{ED}"><monitorObject><deviceObject>{dev}</deviceObject></monitorObject></MonitorStart>',
        "SetLampMode":                  f'<SetLampMode xmlns="{ED}"><device>{dev}</device><lamp>1</lamp><lampMode>3</lampMode></SetLampMode>',
        "SetButtonInformation":         f'<SetButtonInformation xmlns="{ED}"><device>{dev}</device><buttonID>1</buttonID><buttonLabel>TEST</buttonLabel></SetButtonInformation>',
        "SetMessageWaitingIndicator":   f'<SetMessageWaitingIndicator xmlns="{ED}"><device>{dev}</device><messageWaitingOn>true</messageWaitingOn></SetMessageWaitingIndicator>',
        "AnswerCall":                   f'<AnswerCall xmlns="{ED}"><callToBeAnswered><deviceID>{dev}</deviceID></callToBeAnswered></AnswerCall>',
        "MakeCall":                     f'<MakeCall xmlns="{ED}"><callingDevice>{dev}</callingDevice><calledDirectoryNumber>1</calledDirectoryNumber></MakeCall>',
        "GetForwarding":                f'<GetForwarding xmlns="{ED}"><device>{dev}</device></GetForwarding>',
        "GetDoNotDisturb":              f'<GetDoNotDisturb xmlns="{ED}"><device>{dev}</device></GetDoNotDisturb>',
        "GenerateDigits":               f'<GenerateDigits xmlns="{ED}"><connectionToSendDigits><deviceID>{dev}</deviceID></connectionToSendDigits><charactersToSend>1</charactersToSend></GenerateDigits>',
    }
    lines = [f"probing device {dev}:"]
    for name, xml in cands.items():
        r = send_to_phone_csta(mac, xml) or ""
        m = re.search(r"<operation>([^<]+)</operation>", r)
        body = r.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in r else r
        if "serviceNotSupported" in r:
            verdict = "not supported"
        elif m:
            verdict = f"IMPLEMENTED (rejected our args: {m.group(1)})"
        elif "no reply" in r:
            verdict = "(no reply)"
        elif "Response" in body or "<" in body:
            verdict = "SUPPORTED -> " + " ".join(body.split())[:160]
        else:
            verdict = "?"
        lines.append(f"  {name}: {verdict}")
    return "\n".join(lines)

def send_to_phone_csta(mac, body):
    conn = CONNS.get(mac); contact = CONTACTS.get(mac)
    if not conn or not contact:
        return "(phone not connected)"
    callid = rid(16) + "@" + MYIP; b = body.encode()
    msg = ("\r\n".join([
        f"NOTIFY {contact} SIP/2.0",
        f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)};rport", "Max-Forwards: 70",
        f"From: <sips:switch@{MYIP}>;tag={rid(8)}", f"To: <{contact}>",
        f"Call-ID: {callid}", "CSeq: 1 NOTIFY",
        "Event: uaCSTA", "Subscription-State: active",
        "Content-Type: application/csta+xml", f"Content-Length: {len(b)}"]) + "\r\n\r\n").encode() + b
    with pinlock: PIN[callid] = []
    log(f"CSTA >> phone {mac}:\n{body}")
    try: conn.sendall(msg)
    except Exception as e:
        with pinlock: PIN.pop(callid, None)
        return f"(send error: {e})"
    end = time.time() + 5; out = None
    while time.time() < end:
        with pinlock: q = list(PIN.get(callid, []))
        if q: out = q[-1]; break
        time.sleep(0.05)
    with pinlock: PIN.pop(callid, None)
    if out: log(f"CSTA << phone {mac}:\n{out.strip()}")
    return out or "(no reply from phone in 5s)"

def send_to_phone_notify(mac, event, ctype, body, from_user="switch"):
    """DEBUG: send an arbitrary out-of-dialog NOTIFY to a phone and return its reply."""
    conn = CONNS.get(mac); contact = CONTACTS.get(mac)
    if not conn or not contact:
        return "(phone not connected)"
    callid = rid(16) + "@" + MYIP; b = body.encode()
    msg = ("\r\n".join([
        f"NOTIFY {contact} SIP/2.0",
        f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)};rport", "Max-Forwards: 70",
        f"From: <sips:{from_user}@{MYIP}>;tag={rid(8)}", f"To: <{contact}>",
        f"Call-ID: {callid}", "CSeq: 1 NOTIFY", f"Event: {event}", "Subscription-State: active;expires=3600",
        f"Contact: <sips:switch@{MYIP}:5061;transport=tls>",
        f"Content-Type: {ctype}", f"Content-Length: {len(b)}"]) + "\r\n\r\n").encode() + b
    with pinlock: PIN[callid] = []
    log(f"DEBUG NOTIFY >> phone {mac}: Event {event}, {ctype}, {len(b)} bytes")
    try: conn.sendall(msg)
    except Exception as e:
        with pinlock: PIN.pop(callid, None)
        return f"(send error: {e})"
    end = time.time() + 5; out = None
    while time.time() < end:
        with pinlock: q = list(PIN.get(callid, []))
        if q: out = q[-1]; break
        time.sleep(0.05)
    with pinlock: PIN.pop(callid, None)
    first = (out or "").split("\r\n")[0]
    log(f"DEBUG NOTIFY << phone {mac}: {first or '(no reply in 5s)'}")
    return out or "(no reply from phone in 5s)"

def reboot_phone(mac, when=None):
    """Tell a connected phone to reboot via an unsolicited SIP-NOTIFY
    'Event: reboot;when=<immediate|on-idle>'. Firmware-verified: NotifyClr::
    EvUnhandledRequest matches event 'reboot' and reads the 'when' Event-header param
    (handlePphoneRebootEvent). 'on-idle' defers until the phone has no active call."""
    when = (when or REBOOT_WHEN).strip().lower()
    if when not in ("immediate", "on-idle"): when = "on-idle"
    if mac not in CONNS or mac not in CONTACTS:
        log(f"reboot {mac}: phone not connected"); return "(phone not connected)"
    log(f"reboot -> phone {mac}: when={when}")
    return send_to_phone_notify(mac, f"reboot;when={when}", "text/plain", "", "switch")

def reboot_all_phones(when=None):
    macs = [m for m in list(CONNS.keys()) if m in CONTACTS]
    if not macs: log("reboot-all: no connected phones"); return
    log(f"reboot-all: notifying {len(macs)} phone(s) (when={(when or REBOOT_WHEN)})")
    for m in macs:
        try: reboot_phone(m, when)
        except Exception as e: log(f"reboot {m} err: {e!r}")

def _on_shutdown(signum, frame):
    """SIGTERM/SIGINT: optionally reboot connected phones before the bridge exits."""
    log(f"shutdown signal {signum}" + (f"; rebooting phones (when={REBOOT_WHEN})" if REBOOT_ON_RESTART else ""))
    if REBOOT_ON_RESTART:
        try: reboot_all_phones()
        except Exception as e: log(f"shutdown reboot err: {e!r}")
        time.sleep(1.5)   # give the NOTIFYs time to go out and be ACKed before we exit
    sys.exit(0)

# ----------------------------- HTTP config/cert server (port 80) -----------------------------
class QuietHTTP(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        if DEBUG: super().log_message(*a)

def write_phoneconfig():
    d = os.path.join(HTTP_ROOT, "fileserver", "phoneconfig"); os.makedirs(d, exist_ok=True)
    # CAS (Client Application Server) provisioning. The phone needs BOTH casUrl
    # and authenticatorUrl set or it logs "CAS and/or Authenticator URLs are not
    # provisioned" and the Directory key fails. All three are CasConfigDM keys; we
    # point them at our own :5448 and answer the authenticator + CAS flow there.
    # sipExtension is the SipConfigDM key (confirmed at offset 0x150 in the firmware
    # constructor) that the phone reads to know "who am I". When it is non-empty,
    # casLoginStatus -> getExtensionProperties fetches the user's name (the title bar).
    # Empty (anonymous) = no name. This is the real unlock for the idle-screen name.
    def sip_block(ext=""):
        b = f'[sip]\nsipSwitchIpList="{MYIP}"\n'
        if ext: b += f'sipExtension={ext}\n'
        return b
    cas_block = (f'[cas]\n'
                 f'casUrl=https://{MYIP}:5448\n'
                 f'authenticatorUrl=https://{MYIP}:5448\n'
                 f'sessionManagerUrl=https://{MYIP}:5448\n')
    open(os.path.join(d, "generated.txt"), "w").write(sip_block() + cas_block)
    # Embed the (single) phone's sipExtension in custom.txt (always fetched; changing
    # its content forces the phone to re-read). Multi-phone uses per-MAC files below.
    # The idle-screen name is two plain pphone.conf [user] keys, userFirstName and
    # userLastName (confirmed on-device with a root shell). Serve them per phone,
    # split from the label, so every phone shows its name with no CAS user-assignment.
    def user_block(label, ext, with_tz=False):
        first, last = _split_name(label or ext or "")
        b = "[user]\n"
        if with_tz: b += f"timezone={TZ}\n"
        return b + f"userFirstName={first}\nuserLastName={last}\nallowPhoneButtonCustomization=true\n"
    one_ext = one_label = ""
    if len(PHONES) == 1:
        _one = next(iter(PHONES.values()))
        one_ext = str(_one.get("extension", "")).strip()
        one_label = _one.get("label", "")
    open(os.path.join(d, "custom.txt"), "w").write(
        sip_block(one_ext) + cas_block + user_block(one_label, one_ext, with_tz=True))
    # Per-MODEL config layer. The phone fetches custom_<MODEL>.txt (e.g. custom_IP485g.txt)
    # between custom.txt and custom_<MAC>.txt (seen in a 2026-11-10 capture -- we were
    # 404ing it). Serve the common sip/cas base + button customization so the layer exists.
    open(os.path.join(d, "custom_IP485g.txt"), "w").write(
        sip_block() + cas_block + "[user]\nallowPhoneButtonCustomization=true\n")
    # Per-MAC config (fetched as custom_<MAC>.txt after custom.txt) sets each phone's
    # own sipExtension and display name.
    for mac, p in list(PHONES.items()):
        ext = str(p.get("extension", "")).strip()
        if not ext: continue
        open(os.path.join(d, f"custom_{mac.upper()}.txt"), "w").write(
            sip_block(ext) + user_block(p.get("label", ""), ext) + p8_extra_blocks(p))
    cu = os.path.join(d, "country_US.txt")
    if not os.path.exists(cu):
        open(cu, "w").write('[site]\ndateFormatLong="\\\\a, \\\\b \\\\d \\\\Y"\n'
                            'timeFormatLong="\\\\h:\\\\m\\\\p"\ndateFormatShort="\\\\n/\\\\d/\\\\Y"\n'
                            'timeFormatShort="\\\\h:\\\\m\\\\p"\n')

# The Voicemail key dials "micloud voicemailloginextension", which the firmware only
# writes from ua-profile subscription data (UaProfSvc::EvUpdated -> PhUaProfMgr::
# UpdateSvcData). .txt keys, Aastra-style lines and unsolicited ua-profile NOTIFYs all
# had no effect (tested 2026-11-09). Kept so that if the phone ever SUBSCRIBEs to
# ua-profile, it gets the voicemail number.
def ua_profile_body(mac):
    """[user] block delivered through a ua-profile subscription -> PhUaProfMgr::
    UpdateSvcData; unknown keys become "micloud <key>" (lowercase is significant)."""
    lines = ["[user]"]
    if VM_NUMBER:
        lines += [f"voicemailloginextension={VM_NUMBER}", f"voicemailextension={VM_NUMBER}"]
    return "\n".join(lines) + "\n"

def ua_profile_subscribe(conn, mac, hdrs, addr):
    """Accept the phone's ua-profile SUBSCRIBE, then NOTIFY inside that dialog."""
    totag = mktag(H(hdrs, "call-id") + "srv")       # same tag p_resp puts on the 200 OK
    r = p_resp(200, "OK", hdrs, addr, "SUBSCRIBE")
    conn.sendall(r)
    time.sleep(0.3)
    body = ua_profile_body(mac).encode()
    acc = H(hdrs, "accept").split(",")[0].strip() or "text/plain"
    ct = uri_of(H(hdrs, "contact")) or CONTACTS.get(mac, "")
    to_hdr = H(hdrs, "from")                       # their From becomes our To
    frm = H(hdrs, "to")
    if ";tag=" not in frm: frm += ";tag=" + totag
    L = [f"NOTIFY {ct} SIP/2.0", f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)};rport",
         "Max-Forwards: 70", f"From: {frm}", f"To: {to_hdr}", f"Call-ID: {H(hdrs, 'call-id')}",
         "CSeq: 1 NOTIFY", f"Event: {H(hdrs, 'event')}", "Subscription-State: active;expires=3600",
         f"Contact: <sips:switch@{MYIP}:5061;transport=tls>",
         f"Content-Type: {acc}", f"Content-Length: {len(body)}"]
    with pinlock: PIN[H(hdrs, "call-id")] = []
    conn.sendall(("\r\n".join(L) + "\r\n\r\n").encode() + body)
    end = time.time() + 5; reply = None
    while time.time() < end and not reply:
        with pinlock: q = [m for m in PIN.get(H(hdrs, "call-id"), []) if "NOTIFY" in H(parse(m)[1], "cseq")]
        if q: reply = q[-1]
        time.sleep(0.05)
    with pinlock: PIN.pop(H(hdrs, "call-id"), None)
    log(f"ua-profile NOTIFY to {mac} ({acc}, {len(body)} bytes): "
        + ((reply or "").split("\r\n")[0] or "no reply"))

# ---- programmable buttons / BB424 (804 firmware p8_phone ProgrammableButtonsDM) ----
# [progbuttons] holds one value: ';'-separated records, each starting "SK=<n>".
# n = line+1; line 0-15 = the phone's own keys, 16+24*(box-1)+btn = button box
# keys, so BB424 #1 buttons 1-24 are SK=17..40 (translateLineToPair). Record:
# SK=n;label;funcId;target;flag;ringDelay;noConnAction;connAction;stackPos;
#      target2;papi;longLabel;   (field positions from ProgrammableButtonDM getters;
# label/longLabel positions inferred). funcId = firmware EnumProgButton codes.
PROG_FUNCS = [(1, "Unused"), (4, "Dial Number"), (5, "Dial Mailbox"), (2, "Call Appearance"),
              (3, "Monitor Extension"), (6, "Intercom"), (10, "Pickup"), (11, "Unpark"),
              (14, "Page"), (15, "Transfer Blind"), (16, "Transfer Consultative"),
              (17, "Transfer To Mailbox"), (19, "Conference Blind"), (20, "Conference Consultative"),
              (22, "Park"), (27, "Send Digits Over Call"), (60, "Toggle Handsfree"),
              (87, "Lock/Unlock")]
PROG_FUNC_NAMES = dict(PROG_FUNCS)
BB_BUTTONS = 24
PHONE_KEYS = 8                  # P8CGPhoneClr::populateProgrammableButtons builds 8 phone keys
def bb_sk(box, btn):            # box 1-based, btn 1-based  -> SK index (after the phone's keys)
    return PHONE_KEYS + BB_BUTTONS * (box - 1) + btn
def _clean(v, n=32):             # no record/field separators inside values
    return re.sub(r"[;\r\n]|SK=", "", str(v or ""))[:n]

def progbuttons_block(p):
    # NOT emitted. DISPROVEN 2026-11-09 by the speed-dial experiment + disassembly:
    #  - The config loader path is ProgrammableButtonsDM::set(QSettings*) -> the single
    #    call to configureDeviceButtons. It configures exactly ONE device.
    #  - populateProgrammableButtons is the ONLY site that constructs a
    #    ProgrammableButtonDeviceDM, and it builds ONE device of 8 buttons from locally
    #    persisted state -- so even device 0 ignores the served [progbuttons] on reboot
    #    (a phone-key speed dial written to custom_<MAC>.txt did NOT appear).
    # The phone owns its button state locally and reports changes up via config::
    # set-prog-buttons; the BB424 is never built as a button device from any served config.
    # Kept only to render the stored layout if a live push path is ever found.
    btns = dict(p.get("buttons") or {})
    recs = []
    for sk in sorted(btns, key=lambda k: int(k)):
        b = btns[sk]
        try: func = int(b.get("func", 1))
        except Exception: func = 1
        lab = _clean(b.get("label"), 16); lng = _clean(b.get("long") or b.get("label"), 32)
        recs.append(";".join([f"SK={int(sk)}", lab, str(func), _clean(b.get("target"), 40), "0", "-1",
                              "0", "0", "0", _clean(b.get("target2"), 40), "", lng, ""]))
    return (f"[progbuttons]\nbboxCount=1\nbuttons=" + ";".join(recs) + "\n") if recs else ""

def p8_extra_blocks(p=None):
    """Extra pphone.conf keys served per phone. SysConfigDM.voiceMailLoginExtension
    (exact case) is what the Voicemail key dials -- works. [progbuttons] is intentionally
    NOT emitted: disassembly + the 2026-11-09 speed-dial test proved the phone builds its
    8 keys from locally persisted state (not the served file) and never builds a button
    device for the BB424, so emitting it only risks disturbing the phone's own keys."""
    return f"[system]\nvoiceMailLoginExtension={VM_NUMBER}\n" if VM_NUMBER else ""

def http_server():
    write_phoneconfig()
    h = functools.partial(QuietHTTP, directory=HTTP_ROOT)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", 80), h)
    log(f"HTTP config server on :80 (root {HTTP_ROOT})")
    httpd.serve_forever()

# ----------------------------- admin web UI (port UI_PORT) -----------------------------
CSS = """
:root{{--bg:#f1f5f9;--card:#fff;--ink:#1e293b;--muted:#64748b;--line:#e2e8f0;--blue:#2563eb}}
*{{box-sizing:border-box}}
body{{font:15px system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}}
.wrap{{max-width:900px;margin:0 auto;padding:1.5rem}}
h1{{font-size:1.3rem;margin:0}} h2{{font-size:1.02rem;margin:1.4rem 0 .5rem;color:var(--ink)}}
a{{color:var(--blue)}} small{{color:var(--muted)}}
table{{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}}
td,th{{padding:.5rem .7rem;border-bottom:1px solid var(--line);text-align:left}}
tr:last-child td{{border-bottom:0}}
th{{background:#f8fafc;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:var(--muted)}}
.on{{color:#16a34a;font-weight:600}} .off{{color:#94a3b8}}
input,select{{padding:.4rem;border:1px solid #cbd5e1;border-radius:6px;font:inherit}}
button{{padding:.4rem .85rem;border:0;border-radius:6px;background:var(--blue);color:#fff;cursor:pointer;font:inherit}}
button.d{{background:#e2e8f0;color:#334155}} button.ghost{{background:#eef2ff;color:var(--blue)}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem;margin:.7rem 0}}
.card table,.card tr:last-child td{{border:0}} .card td{{border-bottom:0;padding:.3rem .4rem}}
.bar{{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:.3rem}}
.status{{color:var(--muted);font-size:.9rem;margin:.2rem 0 1rem}}
.tabbar{{display:flex;gap:.3rem;border-bottom:2px solid var(--line);margin-bottom:1rem;flex-wrap:wrap}}
.tabbar button{{background:none;color:var(--muted);border-radius:8px 8px 0 0;padding:.5rem 1rem;font-weight:600;border-bottom:2px solid transparent;margin-bottom:-2px}}
.tabbar button.active{{color:var(--blue);border-bottom-color:var(--blue)}}
"""
PAGE = ("""<!doctype html><html><head><meta charset=utf-8><title>shorebridge</title>
<style>""" + CSS + """</style></head><body><div class=wrap>
<div class=bar><h1>shorebridge <small>{ip}</small></h1><a href=/>&#8635; refresh</a></div>
<p class=status>{connstatus}</p>
<div class=tabbar>
<button data-t=phones>Phones</button>
<button data-t=calls>Recent calls</button>
<button data-t=dir>Directory</button>
</div>

<section class=tab id=tab-phones>
<h2>Configured phones</h2>
<table><tr><th>MAC</th><th>Extension</th><th>Label</th><th>Online</th><th>Registered</th><th></th></tr>
{rows}
</table>
{discovered}
<h2 id=phoneform>{formtitle}</h2>
<form method=post action=/add class=card>
<input type=hidden name=orig_mac value="{orig_mac}">
<table>
<tr><td>MAC</td><td><input name=mac value="{addmac}" placeholder="00:10:49:54:3b:4c" required></td></tr>
{catalog}
<tr><td>Extension</td><td><input name=extension value="{ext_val}" placeholder="number"></td></tr>
<tr><td>Auth ID</td><td><input name=auth_id value="{auth_val}" placeholder="(blank = same as extension)"></td></tr>
<tr><td>Password</td><td><input name=password type=password placeholder="{pw_hint}"></td></tr>
<tr><td>Label / name</td><td><input name=label value="{label_val}" placeholder="Front desk"></td></tr>
<tr><td>Options PIN</td><td><input name=tui_pin type=password inputmode=numeric pattern="[0-9]*" placeholder="{pin_hint}">
<label style="margin-left:.6rem"><input type=checkbox name=tui_pin_clear value=1> clear PIN</label></td></tr>
</table>
<p><button type=submit>Save phone</button> {cancel}</p>
</form>
</section>

<section class=tab id=tab-calls hidden>
<h2>Recent calls <small>(served to the phones' History)</small></h2>
<table><tr><th>When</th><th></th><th>Number</th><th>Name</th><th>Ext</th><th>Duration</th></tr>
{calls}
</table>
</section>

<section class=tab id=tab-dir hidden>
<h2>Directory contacts <small>(name + number only, no phone)</small></h2>
<table><tr><th>Name</th><th>Number</th><th>Type</th><th></th></tr>
{directory}
</table>
<form method=post action=/dir-add class=card>
<table>
<tr><td>Name</td><td><input name=name placeholder="Cell - Brian" required></td></tr>
<tr><td>Number</td><td><input name=number placeholder="11" required></td></tr>
<tr><td>Type</td><td><select name=type>
<option value=mobile>mobile</option><option value=extension>extension</option>
<option value=home>home</option><option value=work>work</option><option value=external>external</option>
</select></td></tr>
</table>
<p><button type=submit>Add contact</button></p>
</form>
<p><small>Shown in every phone's Directory alongside registered phones. Edits apply immediately.</small></p>
</section>

<p class=status>Config: {cfg}</p>
</div>
<script>
function showTab(id){{
  document.querySelectorAll('.tab').forEach(function(s){{s.hidden=(s.id!='tab-'+id);}});
  document.querySelectorAll('.tabbar button').forEach(function(b){{b.classList.toggle('active',b.dataset.t==id);}});
  try{{localStorage.setItem('sb_tab',id);}}catch(e){{}}
}}
(function(){{
  var t='phones';
  if(!/[?&](edit|add)=/.test(location.search)){{try{{t=localStorage.getItem('sb_tab')||'phones';}}catch(e){{}}}}
  showTab(t);
}})();
document.querySelectorAll('.tabbar button').forEach(function(b){{b.addEventListener('click',function(){{showTab(b.dataset.t);}});}});
// auto-refresh to surface newly-seen phones, but never while you're typing in a field
setInterval(function(){{
  var a=document.activeElement;
  if(a && (a.tagName=='INPUT'||a.tagName=='SELECT'||a.tagName=='TEXTAREA')) return;
  location.reload();
}}, 8000);
</script>
</body></html>""")

def render():
    with pstate:
        rows = []
        for mac, p in sorted(PHONES.items()):
            online = mac in CONNS
            reg = REGOK.get(p["extension"], False)
            rows.append(
                f"<tr><td><code>{mac}</code></td><td>{html.escape(str(p['extension']))}</td>"
                f"<td>{html.escape(p.get('label',''))}</td>"
                f"<td class={'on' if online else 'off'}>{'online' if online else 'offline'}</td>"
                f"<td class={'on' if reg else 'off'}>{'yes' if reg else 'no'}</td>"
                f"<td style=white-space:nowrap><form method=get style='display:inline;margin:0'>"
                f"<input type=hidden name=edit value='{mac}'><button>edit</button></form> "
                f"<form method=get action=/buttons style='display:inline;margin:0'>"
                f"<input type=hidden name=mac value='{mac}'><button>BB424</button></form> "
                + (f"<form method=post action=/reboot style='display:inline;margin:0' "
                   f"onsubmit=\"return confirm('Reboot this phone? It will drop any active call and take ~1-2 min.')\">"
                   f"<input type=hidden name=mac value='{mac}'><button class=ghost>reboot</button></form> " if online else "")
                + f"<form method=post action=/delete style='display:inline;margin:0'>"
                f"<input type=hidden name=mac value='{mac}'><button class=d>remove</button></form></td></tr>")
        seen = {m: v for m, v in SEEN.items() if m not in PHONES}
    rowhtml = "".join(rows) or "<tr><td colspan=6><small>none yet</small></td></tr>"
    disc = ""
    if seen:
        items = "".join(f"<li><code>{m}</code> ({v['ip']}) "
                        f"<form method=get style='display:inline'><input type=hidden name=add value='{m}'>"
                        f"<button>assign &raquo;</button></form></li>" for m, v in sorted(seen.items()))
        disc = f"<h2>New phones seen (unconfigured)</h2><div class=card><ul>{items}</ul></div>"
    dirrows = []
    for i, e in enumerate(load_directory()):
        dirrows.append(
            f"<tr><td>{e.get('name','')}</td><td>{e.get('number','')}</td><td>{e.get('type','')}</td>"
            f"<td><form method=post action=/dir-delete style=margin:0>"
            f"<input type=hidden name=number value='{e.get('number','')}'>"
            f"<button class=d>remove</button></form></td></tr>")
    dirhtml = "".join(dirrows) or "<tr><td colspan=4><small>none yet</small></td></tr>"
    with catalog_lock: cat = list(CATALOG)
    if cat:
        opts = "".join(f"<option value='{e.number}'>{e.number} &mdash; {e.display_name}</option>" for e in cat)
        catalog = ("<tr><td>PBX extension</td><td><select name=catalog_ext>"
                   "<option value=''>&mdash; pick from PBX &mdash;</option>" + opts +
                   "</select> <small>or fill in manually below</small></td></tr>")
        connstatus = f"Connector: {CONN_TYPE} &mdash; {len(cat)} extensions from {CONNECTOR.status()}"
    else:
        catalog = ""
        connstatus = (f"Connector: {CONN_TYPE} (no catalog &mdash; enter credentials manually)"
                      if CONN_TYPE == "manual" else
                      f"Connector: {CONN_TYPE} &mdash; no extensions returned (check [connector] config)")
    return rowhtml, disc, catalog, connstatus, dirhtml

class AdminHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        if DEBUG: super().log_message(*a)
    def _page(self, addmac="", edit=""):
        rowhtml, disc, catalog, connstatus, dirhtml = render()
        e = html.escape
        with pstate: cur = dict(PHONES.get(edit, {})) if edit else {}
        if cur:                                    # edit mode: pre-fill from the saved phone
            form = dict(formtitle=f"Edit phone <code>{e(edit)}</code>", orig_mac=e(edit), addmac=e(edit),
                        ext_val=e(str(cur.get("extension", ""))), auth_val=e(str(cur.get("auth_id", ""))),
                        label_val=e(cur.get("label", "")), pw_hint="(blank = keep current password)",
                        pin_hint=("set - blank keeps it" if cur.get("tui_pwd_md5") else "none - any PIN opens Options"),
                        cancel="<a href=/>cancel</a>")
        else:
            form = dict(formtitle="Add a phone", orig_mac="", addmac=e(addmac), ext_val="",
                        auth_val="", label_val="", pw_hint="", cancel="",
                        pin_hint="digits; blank = no PIN (any PIN opens Options)")
        crow = []
        for r in sorted(load_calllog(), key=lambda r: r.get("start", 0), reverse=True)[:15]:
            kind = "missed" if r.get("missed") else ("&#8601; in" if r.get("direction") == "in" else "&#8599; out")
            crow.append(f"<tr><td>{time.strftime('%b %d %H:%M', time.localtime(r.get('start', 0)))}</td>"
                        f"<td>{kind}</td><td>{e(str(r.get('number','')))}</td><td>{e(r.get('name',''))}</td>"
                        f"<td>{e(str(r.get('ext','')))}</td><td>{'' if r.get('missed') else str(r.get('duration',0))+'s'}</td></tr>")
        callhtml = "".join(crow) or "<tr><td colspan=6><small>none yet</small></td></tr>"
        page = PAGE.format(ip=MYIP, rows=rowhtml, discovered=disc, cfg=PHONES_JSON, catalog=catalog,
                           connstatus=connstatus, directory=dirhtml, calls=callhtml, **form)
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(page.encode())
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        if urlparse(self.path).path == "/buttons":
            return self._buttons_page(norm_mac(q.get("mac", [""])[0]) or "", q.get("saved", [""])[0])
        self._page(addmac=q.get("add", [""])[0], edit=norm_mac(q.get("edit", [""])[0]) or "")
    def _buttons_page(self, mac, saved=""):
        e = html.escape
        with pstate: p = dict(PHONES.get(mac, {}))
        if not p:
            self.send_response(302); self.send_header("Location", "/"); self.end_headers(); return
        btns = p.get("buttons") or {}
        def row(n):
            b = btns.get(str(bb_sk(1, n)), {})
            cur = int(b.get("func", 1) or 1)
            opts = "".join(f"<option value={fid}{' selected' if fid == cur else ''}>{e(nm)}</option>"
                           for fid, nm in PROG_FUNCS)
            if cur not in PROG_FUNC_NAMES:
                opts += f"<option value={cur} selected>code {cur}</option>"
            return (f"<tr><td><b>{n}</b></td><td><select name=f{n}>{opts}</select></td>"
                    f"<td><input name=t{n} value='{e(str(b.get('target','')))}' size=14 placeholder='number / ext'></td>"
                    f"<td><input name=l{n} value='{e(str(b.get('label','')))}' size=12 maxlength=16 placeholder='label'></td></tr>")
        left = "".join(row(n) for n in range(1, 13)); right = "".join(row(n) for n in range(13, 25))
        hdr = "<tr><th>#</th><th>Function</th><th>Number</th><th>Label</th></tr>"
        # Phone's own 8 keys (device 0, SK 1..8). Configuring any of these makes the
        # bridge actually emit [progbuttons] -- the live experiment.
        def prow(n):
            b = btns.get(str(n), {})
            cur = int(b.get("func", 1) or 1)
            opts = "".join(f"<option value={fid}{' selected' if fid == cur else ''}>{e(nm)}</option>"
                           for fid, nm in PROG_FUNCS)
            if cur not in PROG_FUNC_NAMES:
                opts += f"<option value={cur} selected>code {cur}</option>"
            return (f"<tr><td><b>{n}</b></td><td><select name=pf{n}>{opts}</select></td>"
                    f"<td><input name=pt{n} value='{e(str(b.get('target','')))}' size=14 placeholder='number / ext'></td>"
                    f"<td><input name=pl{n} value='{e(str(b.get('label','')))}' size=12 maxlength=16 placeholder='label'></td></tr>")
        phone_tbl = "".join(prow(n) for n in range(1, PHONE_KEYS + 1))
        exp = ("<p class=card style='background:#fee2e2'><b>Config channel: disproven (2026-11-09).</b> "
               "A speed dial written here to the phone's own key did <b>not</b> appear after a "
               "reboot. Disassembly confirms why: the phone builds its 8 keys from "
               "<b>locally persisted state</b>, not the served config, and the firmware never "
               "builds a button device for the BB424. The bridge therefore <b>no longer emits</b> "
               "<code>[progbuttons]</code> (it is ignored and only risks the phone's own keys). "
               "Programming a key <b>on the phone itself</b> is the only path that sticks. These "
               "tables remain a stored record / scratchpad in case a live CAS push path is found.</p>")
        warn = ("<p class=card style='background:#fef3c7'><b>BB424 not working.</b> Only one "
                "programmable-button device (the phone's 8 keys) is ever created by this "
                "firmware; the box is never built from any served config. Populating it appears "
                "to require a real ShoreTel/MiVoice switch, or a live CAS push we have not found.</p>")
        note = ("<p class=card style='background:#ecfdf5'>Saved to the stored layout (not pushed to the phone).</p>"
                if saved else "")
        css = CSS.replace("{{", "{").replace("}}", "}") + ".cols{display:flex;gap:1.5rem;flex-wrap:wrap}.cols table{width:auto}"
        page = f"""<!doctype html><html><head><meta charset=utf-8><title>Buttons - {e(p.get('label') or mac)}</title>
<style>{css}</style></head><body><div class=wrap>
<div class=bar><h1>Phone &amp; BB424 buttons <small>{e(p.get('label') or '')} &middot; ext {e(str(p.get('extension','')))} &middot; <code>{e(mac)}</code></small></h1><a href=/>&larr; back</a></div>
{note}
<form method=post action=/buttons-save>
<input type=hidden name=mac value='{e(mac)}'>
<h2>Phone keys (1&ndash;8) &mdash; speed-dial experiment</h2>
{exp}
<div class=cols><table>{hdr}{phone_tbl}</table></div>
<h2>BB424 button box</h2>
{warn}
<div class=cols><table>{hdr}{left}</table><table>{hdr}{right}</table></div>
<p><button type=submit>Save layout</button>
<small>Phone keys 1&ndash;8 are the phone's own keys. BB424 buttons 1&ndash;12 are its left column, 13&ndash;24 the right.</small></p>
</form></div></body></html>"""
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(page.encode())
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
        f = {k: v[0] for k, v in parse_qs(body).items()}
        path = urlparse(self.path).path
        if path == "/debug/csta" and DEBUG:
            mac = norm_mac(f.get("mac", ""))
            kind = f.get("kind", "raw")
            xml = csta_preset(kind, f.get("ext", ""), f.get("text", "")) if kind != "raw" else f.get("body", "")
            reply = send_to_phone_csta(mac, xml)
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write(("SENT:\n" + xml + "\n\nREPLY:\n" + (reply or "") + "\n").encode()); return
        if path == "/debug/notify" and DEBUG:
            # body = raw payload; ?mac=&event=&ctype=&from=  (debug only)
            q = parse_qs(urlparse(self.path).query)
            mac = norm_mac(q.get("mac", [""])[0]) or next(iter(CONNS), "")
            reply = send_to_phone_notify(mac, q.get("event", ["ua-profile"])[0],
                                         q.get("ctype", ["text/plain"])[0], body,
                                         q.get("from", ["switch"])[0])
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write((reply + "\n").encode()); return
        if path == "/debug/probe" and DEBUG:
            mac = norm_mac(f.get("mac", ""))
            out = csta_probe(mac)
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write((out + "\n").encode()); return
        if path == "/debug/push":
            # Push an arbitrary CAS event to a phone's live GetEvents long-poll, then
            # the bridge log shows how the phone reacts. Body is raw JSON: either one
            # event object {"topic":..} or a list. Optional ?ip= to target a phone.
            raw = body
            ip = (parse_qs(urlparse(self.path).query).get("ip", [""])[0]
                  or (next(iter(LIVE_SESSION), "")))
            sid = LIVE_SESSION.get(ip, "")
            try: evt = json.loads(raw)
            except Exception as e:
                self.send_response(400); self.end_headers()
                self.wfile.write(("bad json: %r\n" % e).encode()); return
            events = evt if isinstance(evt, list) else [evt]
            with CAS_LOCK:
                if sid: CAS_EVENTS.setdefault(sid, []).extend(events)
            log(f"DEBUG push -> ip={ip} sid={sid[:10]} {len(events)} event(s): {raw[:200]}")
            self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
            self.wfile.write((f"pushed {len(events)} event(s) to ip={ip} sid={sid}\n"
                              f"(watch: shorebridge logs)\n").encode()); return
        if path == "/buttons-save":
            mac = norm_mac(f.get("mac", ""))
            with pstate:
                if mac in PHONES:
                    btns = PHONES[mac].setdefault("buttons", {})
                    for n in range(1, BB_BUTTONS + 1):
                        sk = str(bb_sk(1, n))
                        try: func = int(f.get(f"f{n}", "1"))
                        except Exception: func = 1
                        tgt = f.get(f"t{n}", "").strip(); lab = f.get(f"l{n}", "").strip()
                        if func in (0, 1) and not tgt: btns.pop(sk, None)
                        else: btns[sk] = {"func": func, "target": tgt, "label": lab, "long": lab}
                    # phone's own keys (device 0, SK 1..8) -- the speed-dial experiment
                    for n in range(1, PHONE_KEYS + 1):
                        sk = str(n)
                        try: func = int(f.get(f"pf{n}", "1"))
                        except Exception: func = 1
                        tgt = f.get(f"pt{n}", "").strip(); lab = f.get(f"pl{n}", "").strip()
                        if func in (0, 1) and not tgt: btns.pop(sk, None)
                        else: btns[sk] = {"func": func, "target": tgt, "label": lab, "long": lab}
            save_phones()
            try: write_phoneconfig()
            except Exception as e: log(f"phoneconfig rewrite failed: {e!r}")
            log(f"UI: saved button layout for {mac} (stored only; [progbuttons] not emitted)")
            self.send_response(303); self.send_header("Location", f"/buttons?mac={mac}&saved=1"); self.end_headers()
            return
        if path == "/add":
            mac = norm_mac(f.get("mac", ""))
            orig = norm_mac(f.get("orig_mac", "")) or mac
            with pstate: prev = dict(PHONES.get(orig) or PHONES.get(mac) or {})
            pick = f.get("catalog_ext", "").strip()
            rec = None
            if pick:
                with catalog_lock:
                    rec = next((e for e in CATALOG if e.number == pick), None)
            ext = f.get("extension", "").strip() or (rec.number if rec else "")
            authid = f.get("auth_id", "").strip() or (rec.auth_id if rec else ext)
            password = f.get("password", "") or (rec.password if rec else "") or prev.get("password", "")
            label = f.get("label", "").strip() or (rec.display_name if rec else "")
            if mac and ext and password:
                with pstate:
                    if orig != mac: PHONES.pop(orig, None)      # MAC changed while editing
                    PHONES[mac] = {**prev, "extension": ext, "auth_id": authid,
                                   "password": password, "label": label}
                    pin = re.sub(r"\D", "", f.get("tui_pin", ""))
                    if f.get("tui_pin_clear"): PHONES[mac].pop("tui_pwd_md5", None)
                    elif pin: PHONES[mac]["tui_pwd_md5"] = pin_md5(pin)
                    SEEN.pop(mac, None)
                save_phones(); ensure_registrations()
                try: write_phoneconfig()                       # push new ext/name to the phone's config files
                except Exception as ex: log(f"UI: phoneconfig rewrite failed: {ex!r}")
                log(f"UI: {'updated' if prev else 'saved'} phone {mac} -> ext {ext}")
            else:
                log(f"UI: incomplete add for {mac} (need extension + password)")
        elif path == "/reboot":
            mac = norm_mac(f.get("mac", ""))
            when = f.get("when", "").strip() or REBOOT_WHEN
            log(f"UI: reboot phone {mac} (when={when})")
            threading.Thread(target=reboot_phone, args=(mac, when), daemon=True).start()
        elif path == "/delete":
            mac = norm_mac(f.get("mac", ""))
            with pstate: PHONES.pop(mac, None)
            save_phones(); log(f"UI: removed phone {mac}")
        elif path == "/dir-add":
            name = f.get("name", "").strip(); number = f.get("number", "").strip()
            typ = f.get("type", "mobile").strip() or "mobile"
            if name and number:
                entries = [e for e in load_directory() if str(e.get("number")) != number]
                entries.append({"name": name, "number": number, "type": typ})
                save_directory(entries); log(f"UI: added directory contact {name} ({number})")
        elif path == "/dir-delete":
            number = f.get("number", "").strip()
            save_directory([e for e in load_directory() if str(e.get("number")) != number])
            log(f"UI: removed directory contact {number}")
        self.send_response(303); self.send_header("Location", "/"); self.end_headers()

def admin_server():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", UI_PORT), AdminHandler)
    log(f"admin UI on http://{MYIP}:{UI_PORT}")
    httpd.serve_forever()

def refresh_catalog():
    global CATALOG
    while True:
        try:
            exts = CONNECTOR.list_extensions()
            with catalog_lock: CATALOG = exts
            if exts: dbg(f"connector {CONN_TYPE}: {len(exts)} extensions ({CONNECTOR.status()})")
        except Exception as e:
            log("connector refresh err: " + repr(e))
        time.sleep(300)

# ----------------------------- main -----------------------------
def main():
    for p in (CERT, KEY, os.path.join(HTTP_ROOT, "keystore", "certs", "hq_ca.crt")):
        if not os.path.exists(p):
            sys.stderr.write(f"shorebridge: missing {p} (run the installer first)\n"); sys.exit(1)
    load_phones(); load_phone_ips()
    signal.signal(signal.SIGTERM, _on_shutdown)
    signal.signal(signal.SIGINT, _on_shutdown)
    log(f"shorebridge starting: bind={MYIP} pbx={SBC_IP}:{SBC_PORT} domain={DOMAIN} phones={len(PHONES)}"
        + (f" (reboot phones on restart: when={REBOOT_WHEN})" if REBOOT_ON_RESTART else ""))
    ensure_registrations()
    threading.Thread(target=refresh_catalog, daemon=True).start()
    threading.Thread(target=http_server, daemon=True).start()
    threading.Thread(target=admin_server, daemon=True).start()
    threading.Thread(target=u3_recv, daemon=True).start()
    threading.Thread(target=tls_server, args=(5061, phone_handle), daemon=True).start()
    threading.Thread(target=tls_server, args=(5448, cas_handle), daemon=True).start()
    log(f"shorebridge ready - admin UI: http://{MYIP}:{UI_PORT}")
    threading.Event().wait()

if __name__ == "__main__":
    main()
