#!/usr/bin/env python3
"""
shorebridge - use ShoreTel/Mitel IP400-series phones (IP480/480g/485g) with any
standard SIP PBX (3CX, FreePBX/Asterisk, FreeSWITCH, ...).

These phones, once on the Mitel/RingCentral "generic SIP" firmware, speak SIP only
over TLS and pin the server certificate to a CA they download from the config server.
shorebridge emulates just enough of the ShoreTel switch to make the phone happy
(config server, CAS, TLS registration, uaCSTA acks) and is a back-to-back user agent
(B2BUA) to your real PBX. The phone thinks we are its switch; the PBX thinks we are a
normal SIP extension.

Single process, stdlib only. Configure via /etc/shorebridge/config.ini (see config.example.ini).
"""
import socket, ssl, threading, hashlib, random, time, re, os, sys, configparser
import http.server, socketserver, functools

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
EXT      = CFG.get("pbx", "extension")
AUTHID   = CFG.get("pbx", "auth_id")
PASSWORD = CFG.get("pbx", "password")

_bind    = CFG.get("bridge", "bind_ip", fallback="auto").strip()
MYIP     = detect_ip(SBC_IP) if _bind in ("", "auto") else _bind
DATA     = CFG.get("bridge", "data_dir", fallback="/opt/shorebridge")
TZ       = CFG.get("phone", "timezone", fallback="Eastern Standard Time")
DEBUG    = CFG.getboolean("bridge", "debug", fallback=False)

HTTP_ROOT = os.path.join(DATA, "www")
CERT = os.path.join(DATA, "tls", "switch_fullchain.crt")
KEY  = os.path.join(DATA, "tls", "switch.key")
LOGFILE = CFG.get("bridge", "log_file", fallback=os.path.join(DATA, "shorebridge.log"))
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

# ----------------------------- SIP parse helpers -----------------------------
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
def digest(method, uri, realm, nonce, qop, cnonce, nc, opaque):
    ha1 = md5(f"{AUTHID}:{realm}:{PASSWORD}"); ha2 = md5(f"{method}:{uri}")
    resp = md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}") if qop else md5(f"{ha1}:{nonce}:{ha2}")
    a = f'Digest username="{AUTHID}", realm="{realm}", nonce="{nonce}", uri="{uri}", response="{resp}", algorithm=MD5'
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
    if leg["transport"] == "TLS": phone_send(data)
    else: u3.sendto(data, SBC)
    log(f"sent BYE ({leg['transport']}) callid {leg['callid'][:8]}")

def reg_loop():
    while True:
        callid = rid(16) + "@" + MYIP; ftag = rid(8)
        def mk(cseq, auth=None, hdr="Authorization"):
            L = [f"REGISTER sip:{DOMAIN} SIP/2.0",
                 f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch=z9hG4bK{rid(16)};rport", "Max-Forwards: 70",
                 f"From: <sip:{EXT}@{DOMAIN}>;tag={ftag}", f"To: <sip:{EXT}@{DOMAIN}>",
                 f"Call-ID: {callid}", f"CSeq: {cseq} REGISTER",
                 f"Contact: <sip:{EXT}@{MYIP}:{P3CX}>", "Expires: 120", "User-Agent: ShoreBridge/1.0"]
            if auth: L.append(f"{hdr}: {auth}")
            L.append("Content-Length: 0"); return "\r\n".join(L) + "\r\n\r\n"
        with wlock: waiters[callid] = []
        u3_send(mk(1)); r = wait(callid, 4)
        if r and (" 401 " in r.split("\r\n")[0] or " 407 " in r.split("\r\n")[0]):
            st = r.split("\r\n")[0]
            hh = [l for l in r.split("\r\n") if l.lower().startswith(("www-authenticate", "proxy-authenticate"))]
            realm, nonce, qop, opaque = parse_auth(hh[0]) if hh else (None,) * 4
            hdr = "Proxy-Authorization" if " 407 " in st else "Authorization"
            auth = digest("REGISTER", f"sip:{DOMAIN}", realm, nonce, qop, rid(16), "00000001", opaque)
            with wlock: waiters[callid] = []
            u3_send(mk(2, auth, hdr)); r = wait(callid, 4)
        with wlock: waiters.pop(callid, None)
        ok = bool(r and " 200 " in r.split("\r\n")[0])
        log("registration: " + ("OK" if ok else "FAILED"))
        time.sleep(90 if ok else 15)

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

CALLS = {}
PHONE_CONN = None; PHONE_LOCK = threading.Lock()
PHONE_CONTACT = None; PHONE_IP = None     # learned from the phone's REGISTER
PIN = {}; pinlock = threading.Lock()
def phone_send(data):
    with PHONE_LOCK:
        if PHONE_CONN:
            try: PHONE_CONN.sendall(data); return True
            except Exception: return False
    return False

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
    for p in range(12000, 12400, 2):
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
    def __init__(s, dst, phone_conn, phone_hdrs, phone_sdp):
        s.dst = dst; s.pc = phone_conn; s.ph = phone_hdrs; s.psdp = phone_sdp
        s.p_callid = H(phone_hdrs, "call-id")
        s.x_callid = rid(16) + "@" + MYIP; s.x_ftag = rid(8); s.x_totag = None
        s.sockP, s.rpP = alloc_rtp(); s.sock3, s.rp3 = alloc_rtp()
        s.phone_rtp = sdp_media(phone_sdp); s.x_rtp = None
        s.alive = True
        s.p_ftag = None; s.p_totag = None; s.p_addr = None
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
    ftag = cs.x_ftag
    def mk(cseq, branch, auth=None, hdr="Proxy-Authorization"):
        b = sdp.encode()
        L = [f"INVITE sip:{cs.dst}@{DOMAIN} SIP/2.0",
             f"Via: SIP/2.0/UDP {MYIP}:{P3CX};branch={branch};rport", "Max-Forwards: 70",
             f"From: <sip:{EXT}@{DOMAIN}>;tag={ftag}", f"To: <sip:{cs.dst}@{DOMAIN}>",
             f"Call-ID: {cs.x_callid}", f"CSeq: {cseq} INVITE",
             f"Contact: <sip:{EXT}@{MYIP}:{P3CX}>", "User-Agent: ShoreBridge/1.0",
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
               "Max-Forwards: 70", f"From: <sip:{EXT}@{DOMAIN}>;tag={ftag}", f"To: {H(h407,'to')}",
               f"Call-ID: {cs.x_callid}", "CSeq: 1 ACK", "Content-Length: 0"]
        u3.sendto(("\r\n".join(ack) + "\r\n\r\n").encode(), SBC)
        hdr = "Proxy-Authorization" if " 407 " in st else "Authorization"
        auth = digest("INVITE", f"sip:{cs.dst}@{DOMAIN}", realm, nonce, qop, rid(16), "00000001", opaque)
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
    L += ["Max-Forwards: 70", f"From: <sip:{EXT}@{DOMAIN}>;tag={cs.x_ftag}", f"To: {to}",
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

def phone_invite(conn, hdrs, body, addr):
    to = H(hdrs, "to"); m = re.search(r'sips?:([^@>]+)@', to); dst = m.group(1) if m else "0"
    log(f"phone dialed {dst}")
    cs = CallSession(dst, conn, hdrs, body); cs.p_addr = addr; CALLS[cs.p_callid] = cs
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
                   'local': f"<sip:{EXT}@{DOMAIN}>", 'ltag': cs.x_ftag, 'remote': H(xh, "to"),
                   'callid': cs.x_callid, 'route': list(reversed(xh.get("record-route", []))), 'cseq': 2}
    cs.p_dialog = {'ruri': uri_of(H(hdrs, "contact")) or f"sips:anonymous@{addr[0]}:5061", 'transport': 'TLS', 'lport': 5061,
                   'local': H(hdrs, "to"), 'ltag': mktag(cs.p_callid + "srv"), 'remote': H(hdrs, "from"),
                   'callid': cs.p_callid, 'route': [], 'cseq': 1}
    threading.Thread(target=cs.relay, daemon=True).start()
    ans = ("v=0\r\n" f"o=switch 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rpP} RTP/AVP 0 102\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:102 telephone-event/8000\r\n" "a=ptime:20\r\n" "a=sendrecv\r\n"
           "m=audio 0 RTP/SAVP 0\r\n")
    conn.sendall(p_resp(200, "OK", hdrs, addr, "INVITE", sdp=ans))
    log(f"call up: phone <-> {dst}")

def phone_handle(conn, addr):
    global PHONE_CONN, PHONE_CONTACT, PHONE_IP
    PHONE_CONN = conn; buf = b""; conn.settimeout(300)
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
                ct = uri_of(H(hdrs, "contact"))
                if ct: PHONE_CONTACT = ct
                PHONE_IP = addr[0]
                conn.sendall(p_resp(200, "OK", hdrs, addr, method))
            elif method == "INVITE":
                threading.Thread(target=phone_invite, args=(conn, hdrs, b, addr), daemon=True).start()
            elif method == "BYE":
                cs = CALLS.get(H(hdrs, "call-id"))
                conn.sendall(p_resp(200, "OK", hdrs, addr, method))
                if cs: cs.teardown(origin="phone")
            else:
                conn.sendall(p_resp(200, "OK", hdrs, addr, method))
    except Exception as e:
        log(f"phone conn err {repr(e)}")
    finally:
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
    s.bind(("0.0.0.0", port)); s.listen(8); log(f"TLS server on :{port}")
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
    if not PHONE_CONN or not PHONE_CONTACT:
        u3.sendto(resp_line(480, "Unavailable", xh).encode(), xaddr); return
    m = re.search(r'sips?:([^@>;]+)', H(xh, "from")); caller = m.group(1) if m else "unknown"
    cs = CallSession("inbound", None, xh, xbody)
    cs.x_hdrs = xh; cs.x_callid = H(xh, "call-id"); cs.x_rtp = sdp_media(xbody)
    cs.p_callid = rid(16) + "@" + MYIP; cs.p_ftag = rid(8)
    CALLS[cs.x_callid] = cs; CALLS[cs.p_callid] = cs
    u3.sendto(resp_line(100, "Trying", xh).encode(), xaddr)
    sdp = ("v=0\r\n" f"o=switch 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
           f"m=audio {cs.rpP} RTP/AVP 0 102\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:102 telephone-event/8000\r\n" "a=ptime:20\r\n" "a=sendrecv\r\n")
    b = sdp.encode()
    inv = ("\r\n".join([
        f"INVITE {PHONE_CONTACT} SIP/2.0",
        f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)};rport", "Max-Forwards: 70",
        f"From: <sips:{caller}@{MYIP}>;tag={cs.p_ftag}", f"To: <{PHONE_CONTACT}>",
        f"Call-ID: {cs.p_callid}", "CSeq: 1 INVITE",
        f"Contact: <sips:switch@{MYIP}:5061;transport=tls>", "User-Agent: ShoreBridge/1.0",
        "Content-Type: application/sdp", f"Content-Length: {len(b)}"]) + "\r\n\r\n").encode() + b
    with pinlock: PIN[cs.p_callid] = []
    log(f"inbound from {caller} -> ringing phone")
    if not phone_send(inv):
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
        f"ACK {PHONE_CONTACT} SIP/2.0", f"Via: SIP/2.0/TLS {MYIP}:5061;branch=z9hG4bK{rid(16)}",
        "Max-Forwards: 70", f"From: <sips:{caller}@{MYIP}>;tag={cs.p_ftag}", f"To: {cs.p_totag}",
        f"Call-ID: {cs.p_callid}", "CSeq: 1 ACK", "Content-Length: 0"]) + "\r\n\r\n").encode()
    phone_send(ack); threading.Thread(target=cs.relay, daemon=True).start()
    osdp = ("v=0\r\n" f"o=bridge 1 1 IN IP4 {MYIP}\r\n" "s=call\r\n" f"c=IN IP4 {MYIP}\r\n" "t=0 0\r\n"
            f"m=audio {cs.rp3} RTP/AVP 0 101\r\n" "a=rtpmap:0 PCMU/8000\r\n" "a=rtpmap:101 telephone-event/8000\r\n" "a=sendrecv\r\n")
    ob = osdp.encode(); to = H(xh, "to")
    if ";tag=" not in to: to = to + ";tag=" + mktag(cs.x_callid + "in")
    L = [f"SIP/2.0 200 OK"] + allvia(xh) + allrr(xh) + [f"From: {H(xh,'from')}", f"To: {to}",
         f"Call-ID: {cs.x_callid}", f"CSeq: {H(xh,'cseq')}",
         f"Contact: <sip:{EXT}@{MYIP}:{P3CX}>", "Content-Type: application/sdp", f"Content-Length: {len(ob)}"]
    u3.sendto(("\r\n".join(L) + "\r\n\r\n").encode() + ob, xaddr)
    cs.x_dialog = {'ruri': uri_of(H(xh, "contact")) or uri_of(H(xh, "from")), 'transport': 'UDP', 'lport': P3CX,
                   'local': H(xh, "to"), 'ltag': mktag(cs.x_callid + "in"), 'remote': H(xh, "from"),
                   'callid': cs.x_callid, 'route': list(reversed(xh.get("record-route", []))), 'cseq': 1}
    cs.p_dialog = {'ruri': PHONE_CONTACT, 'transport': 'TLS', 'lport': 5061,
                   'local': f"<sips:{caller}@{MYIP}>", 'ltag': cs.p_ftag, 'remote': cs.p_totag,
                   'callid': cs.p_callid, 'route': [], 'cseq': 1}
    log(f"inbound call up: {caller} <-> phone")

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

# ----------------------------- main -----------------------------
def main():
    for p in (CERT, KEY, os.path.join(HTTP_ROOT, "keystore", "certs", "hq_ca.crt")):
        if not os.path.exists(p):
            sys.stderr.write(f"shorebridge: missing {p} (run the installer / generate certs first)\n"); sys.exit(1)
    log(f"shorebridge starting: bind={MYIP} ext={EXT} pbx={SBC_IP}:{SBC_PORT} domain={DOMAIN}")
    threading.Thread(target=http_server, daemon=True).start()
    threading.Thread(target=u3_recv, daemon=True).start()
    threading.Thread(target=reg_loop, daemon=True).start()
    threading.Thread(target=tls_server, args=(5061, phone_handle), daemon=True).start()
    threading.Thread(target=tls_server, args=(5448, cas_handle), daemon=True).start()
    log("shorebridge ready")
    threading.Event().wait()

if __name__ == "__main__":
    main()
