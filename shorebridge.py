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
DEBUG    = CFG.getboolean("bridge", "debug", fallback=False)
UI_PORT  = CFG.getint("bridge", "ui_port", fallback=8910)
CSTA_AUTOANSWER = CFG.getboolean("bridge", "csta_test_autoanswer", fallback=False)  # test: auto-fire AnswerCall on inbound ring

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
        s.p_dialog = None; s.x_dialog = None; s.p_inv = None
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
        PHONE_IPS[mac] = addr[0]            # so CAS (a separate connection) can map IP -> extension
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
        topic, msg = req.get("topic"), req.get("message")
        rid_ = req.get("request-id", 0)
        log(f"CAS Execute topic={topic} message={msg}")
        if topic == "find":
            return cas_find_response(req)
        first, last = _split_name(label or ext or "")
        eprops = {"ext": ext, "did": ext, "firstname": first, "lastname": last,
                  "firstName": first, "lastName": last, "display-name": (label or ext),
                  "phone-assignment": "PRIMARY-PHONE", "phone-assignment-descr": "Primary phone"}
        # the "Assign user to phone" sequence (the path that sets the title-bar name)
        if msg == "authenticate-tui-pwd":          # verify the PIN -> accept any
            log("CAS authenticate-tui-pwd -> accepted")
            return {"request-id": rid_, "result": True, "must-change": False}
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
    except Exception as e:
        if DEBUG: log("CAS err " + repr(e))
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
    cs.x_callid = H(xh, "call-id"); cs.x_rtp = sdp_media(xbody)
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
    one_ext = ""
    if len(PHONES) == 1:
        one_ext = str(next(iter(PHONES.values())).get("extension", "")).strip()
    open(os.path.join(d, "custom.txt"), "w").write(
        sip_block(one_ext) + cas_block + f"[user]\ntimezone={TZ}\n")
    # Per-MAC config (fetched as custom_<MAC>.txt after custom.txt) sets each phone's
    # own sipExtension.
    for mac, p in list(PHONES.items()):
        ext = str(p.get("extension", "")).strip()
        if not ext: continue
        open(os.path.join(d, f"custom_{mac.upper()}.txt"), "w").write(sip_block(ext))
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
PAGE = """<!doctype html><html><head><meta charset=utf-8><title>shorebridge</title>
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
<h1>shorebridge <small>{ip}</small> <a href=/ style="font-size:.8rem;font-weight:400">&#8635; refresh</a></h1>
<p><small>{connstatus}</small></p>
<h2>Configured phones</h2>
<table><tr><th>MAC</th><th>Extension</th><th>Label</th><th>Online</th><th>Registered</th><th></th></tr>
{rows}
</table>
{discovered}
<h2>Add / update a phone</h2>
<form method=post action=/add class=card>
<table>
<tr><td>MAC</td><td><input name=mac value="{addmac}" placeholder="00:10:49:54:3b:4c" required></td></tr>
{catalog}
<tr><td>Extension</td><td><input name=extension placeholder="number"></td></tr>
<tr><td>Auth ID</td><td><input name=auth_id placeholder="(blank = same as extension)"></td></tr>
<tr><td>Password</td><td><input name=password type=password></td></tr>
<tr><td>Label / name</td><td><input name=label placeholder="Front desk"></td></tr>
</table>
<p><button type=submit>Save phone</button></p>
</form>

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
<p><small>Shown in every phone's Directory alongside registered phones. Edits apply immediately. Config: {cfg}</small></p>
<script>
// auto-refresh to surface newly-seen phones, but never while you're typing in a field
setInterval(function(){{
  var a=document.activeElement;
  if(a && (a.tagName=='INPUT'||a.tagName=='SELECT'||a.tagName=='TEXTAREA')) return;
  location.reload();
}}, 8000);
</script>
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
    def _page(self, addmac=""):
        rowhtml, disc, catalog, connstatus, dirhtml = render()
        html = PAGE.format(ip=MYIP, rows=rowhtml, discovered=disc, addmac=addmac,
                           cfg=PHONES_JSON, catalog=catalog, connstatus=connstatus, directory=dirhtml)
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(html.encode())
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        self._page(addmac=q.get("add", [""])[0])
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
        if path == "/add":
            mac = norm_mac(f.get("mac", ""))
            pick = f.get("catalog_ext", "").strip()
            rec = None
            if pick:
                with catalog_lock:
                    rec = next((e for e in CATALOG if e.number == pick), None)
            ext = f.get("extension", "").strip() or (rec.number if rec else "")
            authid = f.get("auth_id", "").strip() or (rec.auth_id if rec else ext)
            password = f.get("password", "") or (rec.password if rec else "")
            label = f.get("label", "").strip() or (rec.display_name if rec else "")
            if mac and ext and password:
                with pstate:
                    PHONES[mac] = {"extension": ext, "auth_id": authid, "password": password, "label": label}
                    SEEN.pop(mac, None)
                save_phones(); ensure_registrations(); log(f"UI: saved phone {mac} -> ext {ext}")
            else:
                log(f"UI: incomplete add for {mac} (need extension + password)")
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
    load_phones()
    log(f"shorebridge starting: bind={MYIP} pbx={SBC_IP}:{SBC_PORT} domain={DOMAIN} phones={len(PHONES)}")
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
