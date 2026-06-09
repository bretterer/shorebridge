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
import socket, ssl, threading, hashlib, random, time, re, os, sys, json, configparser
import http.server, socketserver, functools
from urllib.parse import parse_qs, urlparse

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
DEBUG    = CFG.getboolean("bridge", "debug", fallback=False)
UI_PORT  = CFG.getint("bridge", "ui_port", fallback=8910)

HTTP_ROOT = os.path.join(DATA, "www")
CERT = os.path.join(DATA, "tls", "switch_fullchain.crt")
KEY  = os.path.join(DATA, "tls", "switch.key")
LOGFILE = CFG.get("bridge", "log_file", fallback=os.path.join(DATA, "shorebridge.log"))
PHONES_JSON = CFG.get("bridge", "phones_file", fallback=os.path.join(os.path.dirname(CFG_PATH), "phones.json"))
P3CX = 5062  # our local SIP port toward the PBX

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
            threading.Thread(target=inbound_invite, args=(hdrs, msg, addr), daemon=True).start()
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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

class CallSession:
    def __init__(s, dst, conn, mac, ext, authid, password):
        s.dst = dst; s.pc = conn; s.mac = mac
        s.ext = ext; s.authid = authid; s.password = password
        s.x_callid = rid(16) + "@" + MYIP; s.x_ftag = rid(8); s.x_totag = None
        s.p_callid = None; s.ph = None
        s.sockP, s.rpP = alloc_rtp(); s.sock3, s.rp3 = alloc_rtp()
        s.phone_rtp = None; s.x_rtp = None
        s.alive = True; s.p_ftag = None; s.p_totag = None; s.p_addr = None
        s.p_dialog = None; s.x_dialog = None
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
        if origin != "phone" and s.p_dialog:
            try: build_bye(s.p_dialog)
            except Exception as e: log("bye phone err " + repr(e))
        if origin != "3cx" and s.x_dialog:
            try: build_bye(s.x_dialog)
            except Exception as e: log("bye pbx err " + repr(e))
        for so in (s.sockP, s.sock3):
            try: so.close()
            except Exception: pass
        CALLS.pop(s.p_callid, None); CALLS.pop(s.x_callid, None)
        log(f"call {s.dst} ended (origin={origin})")

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
    cs.x_dialog = {'ruri': uri_of(H(xh, "contact")) or f"sip:{dst}@{DOMAIN}", 'transport': 'UDP', 'lport': P3CX,
                   'local': f"<sip:{ext}@{DOMAIN}>", 'ltag': cs.x_ftag, 'remote': H(xh, "to"),
                   'callid': cs.x_callid, 'route': list(reversed(xh.get("record-route", []))), 'cseq': 2}
    cs.p_dialog = {'ruri': uri_of(H(hdrs, "contact")) or f"sips:anonymous@{addr[0]}:5061", 'transport': 'TLS', 'lport': 5061,
                   'local': H(hdrs, "to"), 'ltag': mktag(cs.p_callid + "srv"), 'remote': H(hdrs, "from"),
                   'callid': cs.p_callid, 'route': [], 'cseq': 1, 'conn': conn}
    threading.Thread(target=cs.relay, daemon=True).start()
    ans = ("v=0\r\n" f"o=switch 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rpP} RTP/AVP 0 102\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:102 telephone-event/8000\r\n" "a=ptime:20\r\n" "a=sendrecv\r\n"
           "m=audio 0 RTP/SAVP 0\r\n")
    conn.sendall(p_resp(200, "OK", hdrs, addr, "INVITE", sdp=ans))
    log(f"call up: ext {ext} <-> {dst}")

def register_phone(conn, hdrs, addr):
    """Handle a phone REGISTER: identify by MAC, attach its connection; unknown MACs go to SEEN for the UI."""
    mac = mac_from_contact(H(hdrs, "contact")) or ("ip-" + addr[0].replace(".", "-"))
    ct = uri_of(H(hdrs, "contact"))
    with pstate:
        CONNS[mac] = conn
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
            if start.startswith("SIP/2.0"):
                with pinlock:
                    cid = H(hdrs, "call-id")
                    if cid in PIN: PIN[cid].append(msg)
                continue
            method = parts[0]
            if method == "ACK": continue
            if method == "REGISTER":
                mymac = register_phone(conn, hdrs, addr)
                conn.sendall(p_resp(200, "OK", hdrs, addr, method))
            elif method == "INVITE":
                threading.Thread(target=phone_invite, args=(conn, mymac, hdrs, b, addr), daemon=True).start()
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

def cas_handle(conn, addr):
    try:
        conn.settimeout(20); buf = b""
        while b"\r\n\r\n" not in buf:
            d = conn.recv(4096)
            if not d: break
            buf += d
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
    except Exception: pass
    finally:
        try: conn.close()
        except Exception: pass

def tls_server(port, handler):
    ctx = tlsctx(); s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(16); log(f"TLS server on :{port}")
    while True:
        c, a = s.accept()
        try:
            tc = ctx.wrap_socket(c, server_side=True)
            threading.Thread(target=handler, args=(tc, a), daemon=True).start()
        except ssl.SSLError:
            try: c.close()
            except Exception: pass

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
    cs.x_callid = H(xh, "call-id"); cs.x_rtp = sdp_media(xbody)
    cs.p_callid = rid(16) + "@" + MYIP; cs.p_ftag = rid(8)
    CALLS[cs.x_callid] = cs; CALLS[cs.p_callid] = cs
    with pstate:
        contact = CONTACTS.get(mac)
    phone_uri = contact or f"sips:anonymous@{xaddr_ip(conn)}:5061"
    u3.sendto(resp_line(100, "Trying", xh).encode(), xaddr)
    sdp = ("v=0\r\n" f"o=switch 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rpP} RTP/AVP 0 102\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:102 telephone-event/8000\r\n" "a=ptime:20\r\n" "a=sendrecv\r\n")
    b = sdp.encode()
    inv = ("\r\n".join([
        f"INVITE {phone_uri} SIP/2.0",
        f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)};rport", "Max-Forwards: 70",
        f"From: <sips:{caller}@{MYIP}>;tag={cs.p_ftag}", f"To: <{phone_uri}>",
        f"Call-ID: {cs.p_callid}", "CSeq: 1 INVITE",
        f"Contact: <sips:switch@{MYIP}:5061;transport=tls>", "User-Agent: ShoreBridge/1.0",
        "Content-Type: application/sdp", f"Content-Length: {len(b)}"]) + "\r\n\r\n").encode() + b
    with pinlock: PIN[cs.p_callid] = []
    log(f"inbound from {caller} -> ext {ext} (ringing phone {mac})")
    try: conn.sendall(inv)
    except Exception:
        u3.sendto(resp_line(480, "Unavailable", xh).encode(), xaddr); cs.teardown(); return
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
    ack = ("\r\n".join([
        f"ACK {phone_uri} SIP/2.0", f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)}",
        "Max-Forwards: 70", f"From: <sips:{caller}@{MYIP}>;tag={cs.p_ftag}", f"To: {cs.p_totag}",
        f"Call-ID: {cs.p_callid}", "CSeq: 1 ACK", "Content-Length: 0"]) + "\r\n\r\n").encode()
    try: conn.sendall(ack)
    except Exception: pass
    threading.Thread(target=cs.relay, daemon=True).start()
    osdp = ("v=0\r\n" f"o=bridge 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
            f"m=audio {cs.rp3} RTP/AVP 0 101\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:101 telephone-event/8000\r\n" "a=sendrecv\r\n")
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
    log(f"inbound call up: {caller} <-> ext {ext}")

def xaddr_ip(conn):
    try: return conn.getpeername()[0]
    except Exception: return MYIP

# ----------------------------- HTTP config/cert server (port 80) -----------------------------
class QuietHTTP(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        if DEBUG: super().log_message(*a)

def write_phoneconfig():
    d = os.path.join(HTTP_ROOT, "fileserver", "phoneconfig"); os.makedirs(d, exist_ok=True)
    common = f'[sip]\nsipSwitchIpList="{MYIP}"\n[cas]\ncasUrl=https://{MYIP}:5448\n'
    open(os.path.join(d, "generated.txt"), "w").write(common)
    open(os.path.join(d, "custom.txt"), "w").write(common + f"[user]\ntimezone={TZ}\n")
    cu = os.path.join(d, "country_US.txt")
    if not os.path.exists(cu):
        open(cu, "w").write('[site]\ndateFormatLong="\\\\a, \\\\b \\\\d \\\\Y"\n'
                            'timeFormatLong="\\\\h:\\\\m\\\\p"\ndateFormatShort="\\\\n/\\\\d/\\\\Y"\n'
                            'timeFormatShort="\\\\h:\\\\m\\\\p"\n')

def http_server():
    write_phoneconfig()
    h = functools.partial(QuietHTTP, directory=HTTP_ROOT)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", 80), h)
    log(f"HTTP config server on :80 (root {HTTP_ROOT})")
    httpd.serve_forever()

# ----------------------------- admin web UI (port UI_PORT) -----------------------------
PAGE = """<!doctype html><html><head><meta charset=utf-8>
<meta http-equiv=refresh content=8><title>shorebridge</title>
<style>
body{{font:15px system-ui,sans-serif;margin:2rem;max-width:820px;color:#222}}
h1{{font-size:1.4rem}} h2{{font-size:1.05rem;margin-top:1.8rem;color:#444}}
table{{border-collapse:collapse;width:100%}} td,th{{padding:.45rem .6rem;border-bottom:1px solid #eee;text-align:left}}
.on{{color:#0a0;font-weight:600}} .off{{color:#999}}
input{{padding:.35rem;border:1px solid #ccc;border-radius:4px}}
button{{padding:.35rem .8rem;border:0;border-radius:4px;background:#2563eb;color:#fff;cursor:pointer}}
button.d{{background:#ddd;color:#333}}
.card{{background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:1rem;margin:.6rem 0}}
small{{color:#888}}
</style></head><body>
<h1>shorebridge <small>{ip}</small></h1>
<h2>Configured phones</h2>
<table><tr><th>MAC</th><th>Extension</th><th>Label</th><th>Online</th><th>Registered</th><th></th></tr>
{rows}
</table>
{discovered}
<h2>Add / update a phone</h2>
<form method=post action=/add class=card>
<table>
<tr><td>MAC</td><td><input name=mac value="{addmac}" placeholder="00:10:49:54:3b:4c" required></td></tr>
<tr><td>Extension</td><td><input name=extension required></td></tr>
<tr><td>Auth ID</td><td><input name=auth_id required></td></tr>
<tr><td>Password</td><td><input name=password type=password required></td></tr>
<tr><td>Label</td><td><input name=label placeholder="Front desk"></td></tr>
</table>
<p><button type=submit>Save phone</button></p>
</form>
<p><small>Edits apply immediately. Config: {cfg}</small></p>
</body></html>"""

def render():
    with pstate:
        rows = []
        for mac, p in sorted(PHONES.items()):
            online = mac in CONNS
            reg = REGOK.get(p["extension"], False)
            rows.append(
                f"<tr><td><code>{mac}</code></td><td>{p['extension']}</td><td>{p.get('label','')}</td>"
                f"<td class={'on' if online else 'off'}>{'online' if online else 'offline'}</td>"
                f"<td class={'on' if reg else 'off'}>{'yes' if reg else 'no'}</td>"
                f"<td><form method=post action=/delete style=margin:0>"
                f"<input type=hidden name=mac value='{mac}'><button class=d>remove</button></form></td></tr>")
        seen = {m: v for m, v in SEEN.items() if m not in PHONES}
    rowhtml = "".join(rows) or "<tr><td colspan=6><small>none yet</small></td></tr>"
    disc = ""; addmac = ""
    if seen:
        items = "".join(f"<li><code>{m}</code> ({v['ip']}) "
                        f"<form method=get style='display:inline'><input type=hidden name=add value='{m}'>"
                        f"<button>assign &raquo;</button></form></li>" for m, v in sorted(seen.items()))
        disc = f"<h2>New phones seen (unconfigured)</h2><div class=card><ul>{items}</ul></div>"
    return rowhtml, disc

class AdminHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        if DEBUG: super().log_message(*a)
    def _page(self, addmac=""):
        rowhtml, disc = render()
        html = PAGE.format(ip=MYIP, rows=rowhtml, discovered=disc, addmac=addmac, cfg=PHONES_JSON)
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(html.encode())
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        self._page(addmac=q.get("add", [""])[0])
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
        f = {k: v[0] for k, v in parse_qs(body).items()}
        path = urlparse(self.path).path
        if path == "/add":
            mac = norm_mac(f.get("mac", ""))
            if mac and f.get("extension"):
                with pstate:
                    PHONES[mac] = {"extension": f["extension"].strip(), "auth_id": f.get("auth_id", "").strip(),
                                   "password": f.get("password", ""), "label": f.get("label", "").strip()}
                    SEEN.pop(mac, None)
                save_phones(); ensure_registrations(); log(f"UI: saved phone {mac} -> ext {f['extension']}")
        elif path == "/delete":
            mac = norm_mac(f.get("mac", ""))
            with pstate: PHONES.pop(mac, None)
            save_phones(); log(f"UI: removed phone {mac}")
        self.send_response(303); self.send_header("Location", "/"); self.end_headers()

def admin_server():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", UI_PORT), AdminHandler)
    log(f"admin UI on http://{MYIP}:{UI_PORT}")
    httpd.serve_forever()

# ----------------------------- main -----------------------------
def main():
    for p in (CERT, KEY, os.path.join(HTTP_ROOT, "keystore", "certs", "hq_ca.crt")):
        if not os.path.exists(p):
            sys.stderr.write(f"shorebridge: missing {p} (run the installer first)\n"); sys.exit(1)
    load_phones()
    log(f"shorebridge starting: bind={MYIP} pbx={SBC_IP}:{SBC_PORT} domain={DOMAIN} phones={len(PHONES)}")
    ensure_registrations()
    threading.Thread(target=http_server, daemon=True).start()
    threading.Thread(target=admin_server, daemon=True).start()
    threading.Thread(target=u3_recv, daemon=True).start()
    threading.Thread(target=tls_server, args=(5061, phone_handle), daemon=True).start()
    threading.Thread(target=tls_server, args=(5448, cas_handle), daemon=True).start()
    log(f"shorebridge ready - admin UI: http://{MYIP}:{UI_PORT}")
    threading.Event().wait()

if __name__ == "__main__":
    main()
