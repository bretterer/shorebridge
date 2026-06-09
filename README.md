# shorebridge

Use **ShoreTel / Mitel IP400-series desk phones (IP480, IP480g, IP485g)** with **any standard SIP PBX**, 3CX, FreePBX/Asterisk, FreeSWITCH, etc.

These phones are everywhere on the secondhand market for almost nothing, but once converted to the Mitel/RingCentral "generic SIP" firmware they're locked down hard: they speak SIP **only over TLS**, and they **pin the server's certificate to a CA they download from their config server**. Point one at a normal PBX and it just says *No Service*. shorebridge gets them working anyway.

> Status: working. Outbound and inbound calls with two-way audio and clean hang-up, verified against 3CX (cloud + local SBC). Single bridge process, Python standard library only, no dependencies.

## How it works

shorebridge is a small **back-to-back user agent (B2BUA)** that wears two faces:

- **To the phone** it impersonates a ShoreTel switch: it serves the phone's config files and its trust CA over HTTP, answers on the CAS (certificate authority) port, terminates the phone's TLS on 5061, accepts its anonymous/MAC registration, and acks its `uaCSTA` health messages.
- **To your PBX** it is an ordinary SIP extension: it REGISTERs with digest auth and relays calls.

The phone thinks it's talking to its mothership; the PBX thinks it's talking to a softphone. In between, shorebridge bridges the SIP dialogs and relays the RTP (plain PCMU, no SRTP).

```
  ShoreTel IP480 ──TLS/SIP(5061)──▶ shorebridge ──UDP/SIP(5060)──▶ your PBX / 3CX SBC
       (cert-pinned)                (fake switch + B2BUA)            (normal extension)
```

### The trust trick (the part that makes it possible)

The phone validates the switch's TLS cert against a CA it **downloads at boot** from `/keystore/certs/hq_ca.crt` on its config server. A factory reset clears its cached trust. So: serve the phone **our own CA** as `hq_ca.crt`, issue the switch's TLS cert from that CA, and the phone trusts us. The cert pinning is defeated without touching the firmware. The installer generates this CA for you.

## Requirements

- A ShoreTel/Mitel IP480/480g/485g already on the Mitel "generic SIP" firmware (the load that boots to a Mitel logo and shows *No Service* / *SIP registration failed*).
- An always-on Linux host on the same LAN (Raspberry Pi is ideal, it can sit right next to / on the same box as a 3CX SBC). Needs free ports **80, 5061, 5448, 5062** and an RTP range around 12000.
- An extension on your PBX for the phone (number, auth ID, password).

## Install

On the Linux host, as root:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/bretterer/shorebridge/main/install.sh)"
```

It checks prerequisites, optionally installs the 3CX SBC if missing, asks for your PBX details, generates the trust CA + switch cert, writes the config, and starts `shorebridge` as a systemd service.

Or from a clone:

```bash
git clone https://github.com/bretterer/shorebridge && cd shorebridge
sudo ./install.sh
```

## Point a phone at it

1. Factory reset: `Mute` + `25327#`
2. As the phone reboots, **press any key when it prompts you** to interrupt boot and enter the setup menu (or from the idle screen use `Mute` + `73887#`, admin password `1234`)
3. Set **Config Server** to the bridge's IP
4. Reboot / save: `Mute` + `73738#`

The phone pulls its config + trust cert, registers over TLS, and shows up on your PBX as your extension. Place and receive calls normally. (Answer incoming calls with the **Answer softkey / Speaker button**, see Limitations.)

## Multiple phones

Each physical phone maps to its own PBX extension, identified by the **MAC** it announces when it registers. The **first** phone to connect auto-claims the extension from the installer config, so a single-phone setup is zero-touch. For more phones, use the web admin UI:

```
http://<bridge-ip>:8910
```

Point a new phone's Config Server at the bridge; it shows up in the UI under **"New phones seen"**. Click **assign**, enter its PBX extension + auth ID + password, Save, and it goes in service, no file editing, no restart. Mappings are stored in `/etc/shorebridge/phones.json`. (The UI is LAN-only and unauthenticated for now; keep `:8910` off untrusted networks.)

## Managing it

The installer drops a `shorebridge` CLI:

```bash
sudo shorebridge update     # pull the latest version (pinned to newest commit) and restart
shorebridge logs            # follow the service log
shorebridge status          # service status
sudo shorebridge config     # edit settings
shorebridge ui              # print the admin UI url
```

## Configuration

`/etc/shorebridge/config.ini` (see [`config.example.ini`](config.example.ini)). Edit (`sudo shorebridge config`) and `sudo shorebridge restart`. Logs: `shorebridge logs`.

## Connectors (optional)

By default you type each phone's extension/auth/password into the UI. A **connector** lets shorebridge pull that from your PBX's own source of truth, so the UI shows a **dropdown of real extensions** instead (credentials are resolved server-side and never sent to the browser). Calls never depend on a connector being reachable, resolved credentials are persisted to `phones.json`.

`type = manual` (default) means no catalog. A `3cx` connector ships in the box.

### Enabling the 3CX connector

1. In the 3CX admin console (as System Owner): **Admin → Integrations → API → "+ Add"**, Department `DEFAULT`, Role `System Owner`. Save and copy the **Client Secret**.
2. Edit `/etc/shorebridge/config.ini`:
   ```ini
   [connector]
   type = 3cx
   api_base      = https://yourpbx.3cx.us   ; your 3CX admin-console URL (not the SBC)
   client_id     = shorebridge
   client_secret = <the secret>
   ```
3. `sudo systemctl restart shorebridge`, the add-phone form now shows a dropdown of your real 3CX extensions.

(Auth is OAuth client-credentials against `/connect/token`. If your 3CX doesn't return the SIP password over the API, extensions still come through with number + name and you type the password once.)

### Write a connector

Connectors implement a tiny interface, so adding support for FreePBX, NetSapiens, etc. is a single file. Subclass `Connector`, implement `list_extensions()`, register it:

```python
from connectors import Connector, Extension, register

@register
class MyPBXConnector(Connector):
    type = "mypbx"
    label = "My PBX"
    def list_extensions(self):
        # fetch from your PBX API; return Extension(number, display_name, auth_id, password)
        return [Extension("100", "Front Desk", "100", "secret")]
```

Add it to `connectors.py` (PR welcome) or drop the file into `/opt/shorebridge/connectors.d/` for a private connector, no fork needed. It auto-registers at startup and appears as a `type` option.

## Limitations / roadmap

Calls and multi-phone work. The remaining items are the proprietary `uaCSTA` "feels native" layer (all pushed from the switch over the same channel):

- [ ] **Display name + company name** on the idle screen (the user's name and a system label).
- [ ] **Off-hook answer** — lifting the handset doesn't answer a ringing call yet (use the Answer/Speaker key); the phone reports off-hook over uaCSTA and expects the switch to connect it.
- [ ] **Instant N-digit auto-dial** — no digit map pushed, so you press **Dial** (or wait for the inter-digit timeout) instead of it sending on the last digit.
- [ ] **Directory button**, message-waiting indicator, BLF.

These share the same uaCSTA plumbing and are good contribution targets.

## How the firmware conversion happened (context)

The phones were moved from native ShoreTel firmware to the Mitel/RingCentral "generic SIP" load by pointing their Config Server at the Mitel conversion service and rebooting. That conversion is one-way. shorebridge does **not** flash firmware; it works with the phone as-is on that generic-SIP load.

## License

MIT, see [LICENSE](LICENSE).
