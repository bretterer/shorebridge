"""
shorebridge connectors - pluggable sources of PBX extension data.

A connector lets shorebridge pull extension info (number, display name, SIP auth id
and password) from a PBX's own source of truth, so the admin UI can offer a dropdown
of real extensions instead of blank fields, and so display names/directory can be
synced. Connectors are OPTIONAL. The default 'manual' connector provides nothing and
you type credentials by hand. Calls never depend on a connector being reachable -
resolved credentials are persisted to phones.json.

Write your own connector:
  1. subclass Connector, set `type` and `label`
  2. implement list_extensions() -> list[Extension]
  3. register it with @register
Either add the class here and open a PR, or drop a .py file defining + registering
your class into  <data_dir>/connectors.d/  (auto-imported at startup) for a private
connector with no fork required.
"""
import json, ssl, urllib.request, urllib.parse

# ----------------------------- interface -----------------------------
class Extension:
    __slots__ = ("number", "display_name", "auth_id", "password")
    def __init__(self, number, display_name="", auth_id="", password=""):
        self.number = str(number)
        self.display_name = display_name or ""
        self.auth_id = auth_id or str(number)
        self.password = password or ""

class Connector:
    """Interface every connector implements."""
    type = "base"      # unique key used in config: [connector] type = ...
    label = "Base"     # human name shown in the UI
    def __init__(self, config):
        self.config = config or {}          # the [connector] section as a dict
    def list_extensions(self):
        """Return list[Extension] known to the PBX. Empty = no catalog (manual entry)."""
        return []
    def status(self):
        """Short human-readable health string for logs/UI."""
        return "ok"

REGISTRY = {}
def register(cls):
    REGISTRY[cls.type] = cls
    return cls
def make(type_, config):
    return REGISTRY.get(type_, ManualConnector)(config)

# ----------------------------- built-in: manual -----------------------------
@register
class ManualConnector(Connector):
    type = "manual"
    label = "Manual (type credentials)"

# ----------------------------- built-in: 3CX -----------------------------
@register
class ThreeCXConnector(Connector):
    """
    Pulls extensions from a 3CX v20 Configuration API (XAPI).

    [connector]
    type          = 3cx
    api_base      = https://yourpbx.3cx.us   ; your 3CX MANAGEMENT console URL (not the SBC)
    client_id     = shorebridge              ; from Admin > Integrations > API > + Add
    client_secret = <the secret it shows>
    insecure      = false                    ; true to skip TLS verification

    Auth is OAuth client-credentials: POST /connect/token, then GET /xapi/v1/Users.
    If your 3CX doesn't expose the SIP password over the API, extensions still come
    through with number + name (you type the password once in the UI). All failures
    are swallowed (returns []), so a misconfigured connector never breaks calling.
    """
    type = "3cx"
    label = "3CX"

    def _ctx(self):
        ctx = ssl.create_default_context()
        if self.config.get("insecure", "").lower() in ("1", "true", "yes"):
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _token(self, base, ctx):
        # allow a pre-obtained bearer token, else client-credentials
        if self.config.get("token"):
            return self.config["token"]
        cid = self.config.get("client_id"); secret = self.config.get("client_secret")
        if not (cid and secret):
            return None
        body = urllib.parse.urlencode({"client_id": cid, "client_secret": secret,
                                       "grant_type": "client_credentials"}).encode()
        req = urllib.request.Request(base + "/connect/token", data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            return json.loads(r.read().decode()).get("access_token")

    def list_extensions(self):
        base = self.config.get("api_base", "").rstrip("/")
        if not base:
            return []
        ctx = self._ctx()
        try:
            token = self._token(base, ctx)
            if not token:
                return []
            endpoint = self.config.get("endpoint", "/xapi/v1/Users?$top=5000")
            req = urllib.request.Request(base + endpoint,
                                         headers={"Authorization": f"Bearer {token}",
                                                  "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                data = json.loads(r.read().decode())
        except Exception:
            return []
        items = data.get("value") if isinstance(data, dict) else data
        out = []
        for it in (items or []):
            num = it.get("Number") or it.get("number")
            if not num:
                continue
            name = (it.get("DisplayName")
                    or " ".join(x for x in (it.get("FirstName"), it.get("LastName")) if x).strip())
            authid = it.get("AuthID") or it.get("AuthId") or it.get("AuthenticationId") or ""
            pw = (it.get("AuthPassword") or it.get("AuthPass")
                  or it.get("Password") or it.get("SIPPassword") or "")
            out.append(Extension(num, name, authid, pw))
        return out

    def status(self):
        return f"3cx {self.config.get('api_base', '(no api_base set)')}"

# ----------------------------- drop-in third-party connectors -----------------------------
def load_dropins(path):
    """Import every .py in `path` so third-party connectors can self-register."""
    import os, importlib.util
    if not os.path.isdir(path):
        return
    for fn in sorted(os.listdir(path)):
        if not fn.endswith(".py"):
            continue
        try:
            spec = importlib.util.spec_from_file_location("sb_conn_" + fn[:-3], os.path.join(path, fn))
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
        except Exception as e:
            print(f"connector drop-in load error ({fn}): {e}", flush=True)
