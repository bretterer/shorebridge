"""
PBX side of shorebridge, built on the pjsua2 Python library.

pjsua2 owns everything toward the PBX: registration and digest auth, the INVITE
dialogs, SDP, RTP and DTMF. The phone side stays handcrafted SIP in
shorebridge.py. The two sides meet at an audio port. pjsua2 delivers decoded
PCM from the PBX to a media.PhoneRtpLeg, which encodes it for the phone, and
takes the PCM that the leg decoded from the phone.

Threading: every pjsua2 object lives on one engine thread. That thread polls
the library, runs submitted tasks, and is where all pjsua2 callbacks run.
Other threads never touch pjsua2 objects. They hold a CallHandle, which turns
method calls into tasks and hands events back through a queue. The only code
that runs elsewhere is the audio port callbacks, which come from the pjmedia
clock thread and only touch the PhoneRtpLeg.

Events on CallHandle.events are tuples:
  ("early", status_code)       the PBX is ringing (outbound calls)
  ("answered",)                the call is confirmed
  ("ended", status_code, why)  the call is over
  ("dtmf", digit)              the PBX sent a DTMF digit
"""
import itertools
import queue
import re
import threading
import time

import pjsua2 as pj

DTMF_IS_UPDATE = 1
_keys = itertools.count(1)


class PbxError(Exception):
    pass


def err_text(e):
    info = getattr(e, "info", None)
    try:
        return info() if callable(info) else repr(e)
    except Exception:
        return repr(e)


def uri_user(uri):
    m = re.search(r"sips?:([^@>;]+)@", uri or "")
    return m.group(1) if m else ""


class _LogWriter(pj.LogWriter):
    def __init__(self, sink):
        pj.LogWriter.__init__(self)
        self.sink = sink

    def write(self, entry):
        msg = entry.msg.strip()
        if msg:
            self.sink("PJSIP: " + msg)


class BridgePort(pj.AudioMediaPort):
    """Audio port that connects a pjsua2 call to a PhoneRtpLeg."""

    def __init__(self, leg, log):
        pj.AudioMediaPort.__init__(self)
        self.leg = leg
        self.log = log
        self.failed = False

    def onFrameRequested(self, frame):
        try:
            data = self.leg.read_frame(frame.size)
            frame.type = pj.PJMEDIA_FRAME_TYPE_AUDIO
            frame.buf = pj.ByteVector(list(data))
            frame.size = len(data)
        except Exception as e:
            self._fail(e)

    def onFrameReceived(self, frame):
        try:
            self.leg.write_frame(bytes(frame.buf))
        except Exception as e:
            self._fail(e)

    def _fail(self, e):
        if not self.failed:
            self.failed = True
            self.log(f"Audio port error: {e!r}")


class CallHandle:
    """Thread safe view of a PBX call. Safe to use from any thread."""

    def __init__(self, engine):
        self.engine = engine
        self.key = next(_keys)
        self.events = queue.Queue()
        self.ext = ""           # the extension this call belongs to
        self.caller = ""        # caller number for inbound calls
        self.incoming = False

    def emit(self, *event):
        self.events.put(event)

    def set_leg(self, leg):
        self.engine.submit(self.engine._set_leg, self.key, leg)

    def ring(self):
        self.engine.submit(self.engine._answer, self.key, 180)

    def answer(self):
        self.engine.submit(self.engine._answer, self.key, 200)

    def reject(self, code=486):
        self.engine.submit(self.engine._answer, self.key, code)

    def hangup(self):
        self.engine.submit(self.engine._hangup, self.key)

    def send_dtmf(self, digit):
        self.engine.submit(self.engine._send_dtmf, self.key, digit)


class PbxAccount(pj.Account):
    def __init__(self, engine, ext, creds):
        pj.Account.__init__(self)
        self.engine = engine
        self.ext = ext
        self.creds = creds
        self.removing = False

    def onRegState(self, prm):
        self.engine._on_reg_state(self, prm)

    def onIncomingCall(self, prm):
        self.engine._on_incoming(self, prm)


class PbxCall(pj.Call):
    def __init__(self, engine, acc, handle, call_id=pj.PJSUA_INVALID_ID):
        pj.Call.__init__(self, acc, call_id)
        self.engine = engine
        self.handle = handle
        self.leg = None
        self.port = None

    def onCallState(self, prm):
        ci = self.getInfo()
        if ci.state == pj.PJSIP_INV_STATE_EARLY and ci.role == pj.PJSIP_ROLE_UAC:
            self.handle.emit("early", ci.lastStatusCode)
        elif ci.state == pj.PJSIP_INV_STATE_CONFIRMED:
            self.handle.emit("answered")
        elif ci.state == pj.PJSIP_INV_STATE_DISCONNECTED:
            self.handle.emit("ended", ci.lastStatusCode, ci.lastReason)
            # Free the call after this callback has returned.
            self.engine.submit(self.engine._release, self.handle.key)

    def onCallMediaState(self, prm):
        self.engine._connect_media(self)

    def onDtmfEvent(self, prm):
        # RFC 2833 events are reported more than once while the key is held.
        if not prm.flags & DTMF_IS_UPDATE:
            self.handle.emit("dtmf", prm.digit)

    def onCallTransferRequest(self, prm):
        # Transfers are not supported across the bridge.
        prm.statusCode = pj.PJSIP_SC_DECLINE

    def onCallRedirected(self, prm):
        return pj.PJSIP_REDIRECT_STOP


class PbxEngine:
    def __init__(self, bind_ip, domain, pbx_ip, pbx_port=5060, sip_port=5062,
                 rtp_port=12400, rtp_range=400, use_proxy=False,
                 user_agent="Shorebridge/1.0", debug=False, log=print,
                 on_reg_state=None, on_incoming=None):
        self.bind_ip = bind_ip
        self.domain = domain
        self.pbx_ip = pbx_ip
        self.pbx_port = pbx_port
        self.sip_port = sip_port
        self.rtp_port = rtp_port
        self.rtp_range = rtp_range
        self.use_proxy = use_proxy
        self.user_agent = user_agent
        self.debug = debug
        self.log = log
        self.on_reg_state = on_reg_state    # called as (ext, ok, detail) on the engine thread
        self.on_incoming = on_incoming      # called as (CallHandle) on the engine thread
        self.ep = None
        self._tasks = queue.Queue()
        self._accounts = {}
        self._calls = {}
        self._thread = None
        self._ready = threading.Event()
        self._error = None
        self._stopping = False
        self._log_writer = None
        self._null_dev = None

    # Lifecycle

    def start(self):
        self._thread = threading.Thread(target=self._run, name="pjsua2", daemon=True)
        self._thread.start()
        if not self._ready.wait(30):
            raise PbxError("pjsua2 did not start in time")
        if self._error:
            raise PbxError(self._error)

    def stop(self, timeout=8):
        self._stopping = True
        if self._thread:
            self._thread.join(timeout)

    def submit(self, fn, *args):
        self._tasks.put((fn, args))

    def _run(self):
        try:
            self._init_lib()
        except Exception as e:
            self._error = err_text(e)
            self._abort_init()
            self._ready.set()
            return
        self._ready.set()
        while not self._stopping:
            self._run_tasks()
            try:
                self.ep.libHandleEvents(20)
            except Exception as e:
                self.log(f"PBX event loop error: {err_text(e)}")
                time.sleep(0.2)
        self._shutdown()

    def _abort_init(self):
        # Destroy a half started library on this thread, so that no pjsua2 object is
        # left for another thread to free.
        try:
            if self.ep:
                self.ep.libDestroy()
        except Exception:
            pass
        self.ep = None
        self._log_writer = None

    def _run_tasks(self):
        while True:
            try:
                fn, args = self._tasks.get_nowait()
            except queue.Empty:
                return
            try:
                fn(*args)
            except Exception as e:
                self.log(f"PBX task {fn.__name__} failed: {err_text(e)}")

    def _init_lib(self):
        ep = pj.Endpoint()
        ep.libCreate()
        self.ep = ep
        cfg = pj.EpConfig()
        cfg.uaConfig.threadCnt = 0
        cfg.uaConfig.mainThreadOnly = True
        cfg.uaConfig.userAgent = self.user_agent
        cfg.medConfig.clockRate = 8000
        cfg.medConfig.sndClockRate = 8000
        cfg.medConfig.noVad = True
        cfg.medConfig.ecTailLen = 0
        cfg.logConfig.level = 5 if self.debug else 2
        cfg.logConfig.consoleLevel = 0
        cfg.logConfig.msgLogging = 1 if self.debug else 0
        cfg.logConfig.decor = pj.PJ_LOG_HAS_SENDER
        self._log_writer = _LogWriter(self.log)
        # The library deletes the writer when it shuts down, so Python must not.
        self._log_writer.thisown = False
        cfg.logConfig.writer = self._log_writer
        ep.libInit(cfg)
        tc = pj.TransportConfig()
        tc.port = self.sip_port
        tc.boundAddress = self.bind_ip
        ep.transportCreate(pj.PJSIP_TRANSPORT_UDP, tc)
        ep.libStart()
        # No sound card is used. The null device only supplies the media clock.
        self._null_dev = ep.audDevManager().setNullDev()
        # The phone leg is PCMU only, so offer nothing else to the PBX.
        for ci in ep.codecEnum2():
            ep.codecSetPriority(ci.codecId, 255 if ci.codecId.startswith("PCMU/") else 0)
        self.log(f"PBX interface ready: pjsua2 {ep.libVersion().full}, SIP {self.bind_ip}:{self.sip_port}")

    def _shutdown(self):
        try:
            self.ep.hangupAllCalls()
            for acc in self._accounts.values():
                acc.removing = True
                try:
                    acc.setRegistration(False)
                except Exception:
                    pass
            end = time.time() + 1.5
            while time.time() < end:
                self.ep.libHandleEvents(50)
            self._calls.clear()
            self._accounts.clear()
            self._null_dev = None
            self.ep.libDestroy()
        except Exception as e:
            self.log(f"PBX shutdown error: {err_text(e)}")

    # Accounts

    def sync_accounts(self, wanted):
        """Make the registered accounts match wanted, a dict of ext -> (auth_id, password)."""
        self.submit(self._sync_accounts, dict(wanted))

    def _account_config(self, ext, authid, password):
        cfg = pj.AccountConfig()
        cfg.idUri = f"sip:{ext}@{self.domain}"
        cfg.regConfig.registrarUri = f"sip:{self.domain}"
        cfg.regConfig.timeoutSec = 120
        cfg.regConfig.retryIntervalSec = 15
        cfg.regConfig.firstRetryIntervalSec = 15
        cfg.sipConfig.authCreds.append(pj.AuthCredInfo("digest", "*", authid, 0, password))
        if self.use_proxy:
            cfg.sipConfig.proxies.append(f"sip:{self.pbx_ip}:{self.pbx_port};lr")
        # Keep the Contact and Via exactly as configured instead of rewriting them.
        nat = cfg.natConfig
        nat.contactRewriteUse = 0
        nat.viaRewriteUse = 0
        nat.sdpNatRewriteUse = 0
        nat.sipOutboundUse = 0
        nat.udpKaIntervalSec = 0
        nat.sipStunUse = pj.PJSUA_STUN_USE_DISABLED
        nat.mediaStunUse = pj.PJSUA_STUN_USE_DISABLED
        nat.iceEnabled = False
        mt = cfg.mediaConfig.transportConfig
        mt.port = self.rtp_port
        mt.portRange = self.rtp_range
        mt.boundAddress = self.bind_ip
        mt.publicAddress = self.bind_ip
        cfg.mediaConfig.srtpUse = pj.PJMEDIA_SRTP_DISABLED
        return cfg

    def _sync_accounts(self, wanted):
        for ext, creds in wanted.items():
            acc = self._accounts.get(ext)
            try:
                if acc is None:
                    acc = PbxAccount(self, ext, creds)
                    acc.create(self._account_config(ext, *creds))
                    self._accounts[ext] = acc
                    self.log(f"Starting PBX registration for ext {ext}")
                elif acc.creds != creds:
                    acc.creds = creds
                    acc.modify(self._account_config(ext, *creds))
                    self.log(f"Updated PBX credentials for ext {ext}")
            except pj.Error as e:
                self.log(f"Could not set up PBX account for ext {ext}: {err_text(e)}")
        for ext in [e for e in self._accounts if e not in wanted]:
            acc = self._accounts.pop(ext)
            acc.removing = True
            try:
                acc.setRegistration(False)
            except pj.Error:
                pass
            self.log(f"Stopped PBX registration for ext {ext} (phone removed)")

    def _on_reg_state(self, acc, prm):
        if acc.removing or not self.on_reg_state:
            return
        ok = bool(acc.getInfo().regIsActive) and 200 <= prm.code < 300
        self.on_reg_state(acc.ext, ok, f"{prm.code} {prm.reason}".strip())

    # Calls

    def make_call(self, ext, dst, leg):
        """Start an outbound call from ext. Returns a CallHandle at once."""
        handle = CallHandle(self)
        handle.ext = ext
        self.submit(self._make_call, handle, dst, leg)
        return handle

    def _make_call(self, handle, dst, leg):
        acc = self._accounts.get(handle.ext)
        if acc is None:
            handle.emit("ended", 480, "No PBX account for this extension")
            return
        call = PbxCall(self, acc, handle)
        call.leg = leg
        self._calls[handle.key] = call
        prm = pj.CallOpParam(True)
        prm.opt.audioCount = 1
        prm.opt.videoCount = 0
        try:
            call.makeCall(f"sip:{dst}@{self.domain}", prm)
        except pj.Error as e:
            handle.emit("ended", 500, err_text(e))
            self._calls.pop(handle.key, None)

    def _on_incoming(self, acc, prm):
        handle = CallHandle(self)
        handle.incoming = True
        call = PbxCall(self, acc, handle, prm.callId)
        self._calls[handle.key] = call
        ci = call.getInfo()
        handle.ext = uri_user(ci.localUri) or acc.ext
        handle.caller = uri_user(ci.remoteUri) or "unknown"
        if self.on_incoming and not self._stopping:
            self.on_incoming(handle)
        else:
            handle.reject(503)

    def _call(self, key):
        return self._calls.get(key)

    def _set_leg(self, key, leg):
        call = self._call(key)
        if call:
            call.leg = leg

    def _answer(self, key, code):
        call = self._call(key)
        if call:
            prm = pj.CallOpParam()
            prm.statusCode = code
            call.answer(prm)

    def _hangup(self, key):
        call = self._call(key)
        if call:
            try:
                call.hangup(pj.CallOpParam())
            except pj.Error:
                pass    # Already disconnected.

    def _send_dtmf(self, key, digit):
        call = self._call(key)
        if not call:
            return
        try:
            call.dialDtmf(digit)
        except pj.Error:
            # The PBX did not offer telephone-event, so fall back to SIP INFO.
            try:
                prm = pj.CallSendDtmfParam()
                prm.method = pj.PJSUA_DTMF_METHOD_SIP_INFO
                prm.digits = digit
                call.sendDtmf(prm)
            except pj.Error as e:
                self.log(f"Could not send DTMF {digit} to the PBX: {err_text(e)}")

    def _connect_media(self, call):
        if call.leg is None:
            return
        # Keep the CallInfo alive, its media vector is only a view into it.
        ci = call.getInfo()
        for mi in ci.media:
            if mi.type == pj.PJMEDIA_TYPE_AUDIO and mi.status == pj.PJSUA_CALL_MEDIA_ACTIVE:
                am = call.getAudioMedia(mi.index)
                if call.port is None:
                    fmt = pj.MediaFormatAudio()
                    fmt.type = pj.PJMEDIA_TYPE_AUDIO
                    fmt.clockRate = 8000
                    fmt.channelCount = 1
                    fmt.bitsPerSample = 16
                    fmt.frameTimeUsec = 20000
                    fmt.avgBps = fmt.maxBps = 128000
                    call.port = BridgePort(call.leg, self.log)
                    call.port.createPort("shorebridge", fmt)
                am.startTransmit(call.port)
                call.port.startTransmit(am)

    def _release(self, key):
        # Dropping the last references here destroys the pjsua2 objects on this thread.
        call = self._calls.pop(key, None)
        if call:
            call.port = None
            call.leg = None
