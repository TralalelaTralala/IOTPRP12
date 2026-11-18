"""
OCF-шлюз для openHAB: OCF Client + Onboarding Tool (OBT) + HTTP API.

  * Discovery: multicast CoAP GET /oic/res на ff02::158 (All OCF Nodes), фільтр ?rt=, далі /oic/d, /oic/p, doxm, pstat.
  * Onboarding (Just Works, oxm 0): doxm -> власник -> PSK у /oic/sec/cred -> owned=true -> RFPRO (DTLS) -> acl2 -> RFNOP.
  * CRUDN: Retrieve (GET), Update (POST), Create (POST ?if=oic.if.create), Delete (DELETE), Notify (Observe) через coaps.
  * HTTP API для openHAB HTTP binding (/api/state, /api/cmd/*) і push станів у openHAB через REST.
  * Resource browser: веб-сторінка "/" (вбудована в sitemap через Webview), журнал подій через SSE.
"""
import asyncio
import base64
import json
import logging
import os
import socket
import time
import uuid
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

import aiocoap
import cbor2
from aiocoap import Message
from aiohttp import ClientSession, ClientTimeout, web

log = logging.getLogger("ocf-gateway")

OH_URL = os.getenv("OPENHAB_URL", "http://openhab:8080").rstrip("/")
IFACE = os.getenv("IFACE", "eth0")
DATA = Path(os.getenv("DATA_DIR", "/data"))
OBT_UUID = str(uuid.uuid5(uuid.NAMESPACE_URL, "iotprp12:obt"))
CF_CBOR, CF_JSON = 10000, 50


def cfnum(cf) -> int | None:
    """ContentFormat (aiocoap >= 0.4.8 — не int) -> числовий код."""
    if cf is None:
        return None
    return int(getattr(cf, "value", cf))
DOS = {0: "RESET", 1: "RFOTM", 2: "RFPRO", 3: "RFNOP", 4: "SRESET"}
MCAST = "ff02::158"

# OCF-властивість -> openHAB item
ITEMS = {
    ("lamp", "/lamp/switch", "value"): ("Lamp_Switch", "switch"),
    ("lamp", "/lamp/brightness", "brightness"): ("Lamp_Brightness", "num"),
    ("sensor", "/sensor/temperature", "temperature"): ("Sensor_Temperature", "num"),
    ("sensor", "/sensor/humidity", "humidity"): ("Sensor_Humidity", "num"),
    ("plug", "/plug/switch", "value"): ("Plug_Switch", "switch"),
    ("plug", "/plug/energy", "power"): ("Plug_Power", "num"),
    ("plug", "/plug/energy", "energy"): ("Plug_Energy", "num"),
}
# команда openHAB -> (пристрій, href, властивість, тип)
COMMANDS = {
    "lamp_switch": ("lamp", "/lamp/switch", "value", "bool"),
    "lamp_brightness": ("lamp", "/lamp/brightness", "brightness", "int"),
    "plug_switch": ("plug", "/plug/switch", "value", "bool"),
}
SEC_ITEMS = {"lamp": "Lamp_Sec", "sensor": "Sensor_Sec", "plug": "Plug_Sec"}


def code_str(code) -> str:
    return str(code)  # напр. "2.05 Content"


def decode(msg):
    if not msg.payload:
        return None
    cf = msg.opt.content_format
    try:
        if cfnum(cf) == CF_JSON:
            return json.loads(msg.payload.decode())
        if cfnum(cf) in (CF_CBOR, 60):
            return cbor2.loads(msg.payload)
    except Exception:
        pass
    return msg.payload.decode("utf-8", "replace")


class Gateway:
    def __init__(self):
        self.ctx = None
        self.devices: dict[str, dict] = {}      # name -> {di, ip, d, p, doxm, pstat, links}
        self.values: dict[str, dict] = {}       # name -> {href: rep}
        self.store = {"psk": {}}                 # di -> psk hex (облікові дані OBT)
        self.events = deque(maxlen=200)
        self.listeners: set[asyncio.Queue] = set()
        self.observers: dict[tuple, asyncio.Task] = {}
        self.sctx: dict[str, aiocoap.Context] = {}
        self.notifications = 0
        self.http = None
        self.last_discovery = []

    # ------------------------------------------------------------ службове
    def event(self, kind: str, text: str, **extra):
        ev = {"t": datetime.now().strftime("%H:%M:%S"), "kind": kind, "text": text, **extra}
        self.events.append(ev)
        log.info("[%s] %s", kind, text)
        for qu in list(self.listeners):
            qu.put_nowait(ev)
        if kind != "notify":
            asyncio.get_running_loop().create_task(self.oh_update("OCF_LastEvent", f"{ev['t']} {kind}: {text}"[:250]))

    def load_store(self):
        f = DATA / "obt.json"
        if f.exists():
            self.store = json.loads(f.read_text())

    def save_store(self):
        DATA.mkdir(parents=True, exist_ok=True)
        (DATA / "obt.json").write_text(json.dumps(self.store, indent=1))

    async def secure_ctx(self, dev: dict):
        """Окремий клієнтський контекст (і DTLS-сесія) на кожен пристрій."""
        ctx = self.sctx.get(dev["di"])
        if ctx is None:
            ctx = await aiocoap.Context.create_client_context()
            self.sctx[dev["di"]] = ctx
            self.install_client_psk(dev)
        return ctx

    async def drop_secure(self, dev: dict, why: str = ""):
        """Скидає DTLS-сесію пристрою: після RESET/перезапуску пристрій її вже не знає."""
        ctx = self.sctx.pop(dev["di"], None)
        if ctx is not None:
            if why:
                log.info("drop DTLS session %s: %s", dev.get("name"), why)
            try:
                await asyncio.wait_for(ctx.shutdown(), 3)
            except Exception:
                pass

    def install_client_psk(self, dev: dict):
        psk = self.store["psk"].get(dev["di"])
        ctx = self.sctx.get(dev["di"])
        if psk and ctx is not None:
            ctx.client_credentials.load_from_dict({
                f"coaps://[{dev['ip']}]/*": {"dtls": {"psk": {"hex": psk}, "client-identity": {"ascii": OBT_UUID.replace("-", "")}}}})

    async def oh_update(self, item: str, value) -> None:
        try:
            async with self.http.put(f"{OH_URL}/rest/items/{item}/state", data=str(value),
                                     headers={"Content-Type": "text/plain"}) as r:
                if r.status >= 400:
                    log.debug("openHAB %s -> %s", item, r.status)
        except Exception as exc:
            log.debug("openHAB unavailable: %s", exc)

    # ------------------------------------------------------------ CoAP
    async def coap(self, method, dev: dict, href: str, payload=None, query=(), secure=None, timeout=8.0):
        if secure is None:
            secure = dev["di"] in self.store["psk"] and dev.get("owned")
        scheme = "coaps" if secure else "coap"
        uri = f"{scheme}://[{dev['ip']}]{href}"
        msg = Message(code=method, uri=uri, accept=CF_CBOR)
        if query:
            msg.opt.uri_query = tuple(query)
        if payload is not None:
            msg.payload, msg.opt.content_format = cbor2.dumps(payload), CF_CBOR
        if not secure:
            resp = await asyncio.wait_for(self.ctx.request(msg).response, timeout)
            return resp, decode(resp), scheme
        for attempt in (1, 2):
            ctx = await self.secure_ctx(dev)
            try:
                resp = await asyncio.wait_for(ctx.request(msg).response, timeout)
                return resp, decode(resp), scheme
            except (asyncio.TimeoutError, aiocoap.error.NetworkError) as exc:
                if attempt == 2:
                    raise
                await self.drop_secure(dev, f"{type(exc).__name__}, нова DTLS-сесія")
                msg = Message(code=method, uri=uri, accept=CF_CBOR)
                if query:
                    msg.opt.uri_query = tuple(query)
                if payload is not None:
                    msg.payload, msg.opt.content_format = cbor2.dumps(payload), CF_CBOR

    # ------------------------------------------------------------ discovery
    def _multicast(self, rt: str | None, timeout: float = 2.0):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(0.25)
        idx = socket.if_nametoindex(IFACE)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
        token = os.urandom(4)
        m = Message(code=aiocoap.GET, mtype=aiocoap.NON, mid=int.from_bytes(os.urandom(2), "big"), token=token,
                    uri_path=("oic", "res"), accept=CF_CBOR)
        if rt:
            m.opt.uri_query = (f"rt={rt}",)
        s.sendto(m.encode(), (MCAST, 5683, 0, idx))
        end, out = time.time() + timeout, []
        while time.time() < end:
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                continue
            r = Message.decode(data)
            if r.token != token:
                continue
            out.append((addr[0], r))
        s.close()
        return out

    async def discover(self, rt: str | None = None):
        self.event("discovery", f"multicast GET coap://[{MCAST}]/oic/res" + (f"?rt={rt}" if rt else ""))
        replies = await asyncio.to_thread(self._multicast, rt)
        found = []
        for ip, r in replies:
            if not r.code.is_successful():
                continue
            links = decode(r)
            if r.opt.block2 is not None and r.opt.block2.more:
                # відповідь > 1 блоку (Block2): дочитуємо повний /oic/res unicast-запитом до того, хто відповів
                tmp = {"ip": f"{ip}%{IFACE}", "di": ""}
                full, links, _ = await self.coap(aiocoap.GET, tmp, "/oic/res", query=(f"rt={rt}",) if rt else (), secure=False)
                self.event("discovery", f"[{ip}] Block2: {r.opt.block2.size_exponent and 2 ** (r.opt.block2.size_exponent + 4)} Б блоки -> повний /oic/res {len(full.payload)} Б")
                r = full
            if not isinstance(links, list) or not links:
                continue
            anchor = links[0].get("anchor", "")
            # multicast-відповідь приходить з link-local адреси; для unicast беремо endpoint з eps
            ep = next((e["ep"] for l in links for e in l.get("eps", []) if e["ep"].startswith("coap://")), None)
            if ep:
                ip = ep.split("[", 1)[1].split("]", 1)[0]
            found.append({"ip": ip, "anchor": anchor, "links": links, "bytes": len(r.payload)})
        self.event("discovery", f"відповіли {len(found)} пристроїв (CBOR, {sum(f['bytes'] for f in found)} байт)")
        if rt:
            self.last_discovery = found
            return found
        for f in found:
            dev = {"ip": f["ip"], "di": f["anchor"].replace("ocf://", ""), "links": f["links"]}
            try:
                _, dev["d"], _ = await self.coap(aiocoap.GET, dev, "/oic/d", secure=False)
                _, dev["p"], _ = await self.coap(aiocoap.GET, dev, "/oic/p", secure=False)
                _, dev["doxm"], _ = await self.coap(aiocoap.GET, dev, "/oic/sec/doxm", secure=False)
                _, dev["pstat"], _ = await self.coap(aiocoap.GET, dev, "/oic/sec/pstat", secure=False)
            except Exception as exc:
                self.event("error", f"{f['ip']}: {exc}")
                continue
            name = dev["d"]["n"]
            dev["name"], dev["owned"] = name, dev["doxm"]["owned"]
            new = name not in self.devices
            old = self.devices.get(name)
            self.devices[name] = dev
            if old is not None and old["pstat"]["dos"]["s"] != dev["pstat"]["dos"]["s"]:
                await self.drop_secure(dev, "стан безпеки змінився")
            self.event("discovery", f"{'новий ' if new else ''}{name}: {dev['d']['rt'][1]} di={dev['di'][:8]}… "
                                    f"owned={dev['owned']} {DOS[dev['pstat']['dos']['s']]}")
            await self.oh_update(SEC_ITEMS.get(name, "OCF_LastEvent"), self.sec_text(dev))
            if dev["owned"] and dev["di"] in self.store["psk"]:
                self.start_observers(dev)
        await self.oh_update("OCF_DeviceCount", len(self.devices))
        await self.oh_update("OCF_Discovered", ", ".join(f"{n} ({d['d']['rt'][1]})" for n, d in sorted(self.devices.items())))
        return found

    def sec_text(self, dev) -> str:
        s = DOS[dev["pstat"]["dos"]["s"]]
        return f"{s}, owned={'так' if dev['doxm']['owned'] else 'ні'}" + (", DTLS PSK" if dev["di"] in self.store["psk"] else "")

    # ------------------------------------------------------------ onboarding
    async def onboard(self, name: str):
        dev = self.devices[name]
        if dev["doxm"]["owned"]:
            if dev["di"] in self.store["psk"]:
                self.event("onboarding", f"{name}: вже у власності OBT")
                return True
            self.event("error", f"{name}: належить іншому власнику, потрібен RESET пристрою")
            return False
        step = lambda t: self.event("onboarding", f"{name}: {t}")
        G, P = aiocoap.GET, aiocoap.POST
        r, doxm, _ = await self.coap(G, dev, "/oic/sec/doxm", secure=False)
        step(f"1. GET doxm -> owned={doxm['owned']}, oxms={doxm['oxms']} (0 = Just Works)")
        r, _, _ = await self.coap(P, dev, "/oic/sec/doxm", {"oxmsel": 0}, secure=False)
        step(f"2. POST doxm oxmsel=0 -> {code_str(r.code)}")
        r, _, _ = await self.coap(P, dev, "/oic/sec/doxm", {"devowneruuid": OBT_UUID, "rowneruuid": OBT_UUID}, secure=False)
        step(f"3. POST doxm devowneruuid={OBT_UUID[:8]}… -> {code_str(r.code)}")
        psk = os.urandom(16)
        cred = {"creds": [{"subjectuuid": OBT_UUID, "credtype": 1, "credusage": "oic.sec.cred.pairwise",
                           "privatedata": {"encoding": "oic.sec.encoding.base64", "data": base64.b64encode(psk).decode()}}],
                "rowneruuid": OBT_UUID}
        r, _, _ = await self.coap(P, dev, "/oic/sec/cred", cred, secure=False)
        step(f"4. POST cred: PSK 128 біт (credtype 1, pairwise) -> {code_str(r.code)}")
        r, _, _ = await self.coap(P, dev, "/oic/sec/doxm", {"owned": True}, secure=False)
        step(f"5. POST doxm owned=true -> {code_str(r.code)}")
        self.store["psk"][dev["di"]] = psk.hex()
        self.save_store()
        dev["owned"] = True
        await self.drop_secure(dev)  # нова PSK -> нова DTLS-сесія
        r, _, _ = await self.coap(P, dev, "/oic/sec/pstat", {"dos": {"s": 2}, "rowneruuid": OBT_UUID}, secure=True)
        step(f"6. DTLS PSK сесія встановлена, POST pstat RFOTM->RFPRO -> {code_str(r.code)}")
        acl = {"aclist2": [
            {"subject": {"conntype": "anon-clear"}, "resources": [{"wc": "+"}], "permission": 2 | 16},
            {"subject": {"uuid": OBT_UUID}, "resources": [{"wc": "*"}], "permission": 31},
        ], "rowneruuid": OBT_UUID}
        r, _, _ = await self.coap(P, dev, "/oic/sec/acl2", acl, secure=True)
        step(f"7. POST acl2: anon-clear R+N, власник CRUDN -> {code_str(r.code)}")
        r, pstat, _ = await self.coap(P, dev, "/oic/sec/pstat", {"dos": {"s": 3}}, secure=True)
        step(f"8. POST pstat RFPRO->RFNOP -> {code_str(r.code)}, isop={pstat.get('isop')}")
        _, dev["doxm"], _ = await self.coap(G, dev, "/oic/sec/doxm", secure=False)
        _, dev["pstat"], _ = await self.coap(G, dev, "/oic/sec/pstat", secure=False)
        await self.oh_update(SEC_ITEMS[name], self.sec_text(dev))
        self.start_observers(dev)
        return True

    async def reset(self, name: str):
        dev = self.devices[name]
        r, _, _ = await self.coap(aiocoap.POST, dev, "/oic/sec/pstat", {"dos": {"s": 0}}, secure=True)
        self.event("security", f"{name}: POST pstat RESET -> {code_str(r.code)} (ACL і облікові дані очищено)")
        for key in [k for k in self.observers if k[0] == name]:
            self.observers.pop(key).cancel()
        self.store["psk"].pop(dev["di"], None)
        self.save_store()
        await self.drop_secure(dev)
        _, dev["doxm"], _ = await self.coap(aiocoap.GET, dev, "/oic/sec/doxm", secure=False)
        _, dev["pstat"], _ = await self.coap(aiocoap.GET, dev, "/oic/sec/pstat", secure=False)
        dev["owned"] = False
        await self.oh_update(SEC_ITEMS[name], self.sec_text(dev))

    # ------------------------------------------------------------ NOTIFY (observe)
    def start_observers(self, dev: dict):
        for link in dev["links"]:
            if link["href"].startswith("/oic") or not link.get("p", {}).get("bm", 0) & 2:
                continue
            if "oic.wk.col" in link["rt"]:
                continue
            key = (dev["name"], link["href"])
            if key not in self.observers or self.observers[key].done():
                self.observers[key] = asyncio.get_running_loop().create_task(self.observe(dev, link["href"]))

    async def observe(self, dev: dict, href: str):
        delay = 1.0
        while True:
            try:
                msg = Message(code=aiocoap.GET, uri=f"coaps://[{dev['ip']}]{href}", observe=0, accept=CF_CBOR)
                req = (await self.secure_ctx(dev)).request(msg)
                first = await asyncio.wait_for(req.response, 10)
                await self.store_value(dev["name"], href, decode(first))
                self.event("observe", f"{dev['name']} {href}: підписка (Observe) {code_str(first.code)}")
                delay = 1.0
                async for r in req.observation:
                    self.notifications += 1
                    await self.store_value(dev["name"], href, decode(r), notify=True)
                raise ConnectionError("observation ended")
            except asyncio.CancelledError:
                return
            except Exception as exc:
                log.warning("observe %s %s: %s, retry in %.0f s", dev["name"], href, exc, delay)
                if isinstance(exc, (asyncio.TimeoutError, aiocoap.error.NetworkError)):
                    await self.drop_secure(dev, "observe failed")
                await asyncio.sleep(delay)
                delay = min(delay * 2, 30)

    async def store_value(self, name, href, rep, notify=False):
        if not isinstance(rep, dict):
            return
        old = self.values.setdefault(name, {}).get(href, {})
        self.values[name][href] = rep
        if notify:
            changed = {k: v for k, v in rep.items() if old.get(k) != v}
            if changed:
                self.event("notify", f"{name} {href} {json.dumps(changed, ensure_ascii=False)}", name=name, href=href, rep=rep)
            if self.notifications % 5 == 0:
                await self.oh_update("OCF_Notifications", self.notifications)
        for (dn, h, prop), (item, kind) in ITEMS.items():
            if dn == name and h == href and prop in rep and old.get(prop) != rep[prop]:
                val = ("ON" if rep[prop] else "OFF") if kind == "switch" else rep[prop]
                await self.oh_update(item, val)

    # ------------------------------------------------------------ HTTP API
    def dev_or_404(self, name):
        if name not in self.devices:
            raise web.HTTPNotFound(text=json.dumps({"error": f"unknown device {name}"}), content_type="application/json")
        return self.devices[name]

    async def h_devices(self, request):
        out = []
        for n, d in sorted(self.devices.items()):
            out.append({"name": n, "ip": d["ip"], "di": d["di"], "device": d["d"], "platform": d["p"],
                        "doxm": d["doxm"], "pstat": d["pstat"], "state": DOS[d["pstat"]["dos"]["s"]],
                        "secure": d["di"] in self.store["psk"], "links": d["links"], "values": self.values.get(n, {})})
        return web.json_response(out)

    async def h_resources(self, request):
        rt, iface, dname = request.query.get("rt"), request.query.get("if"), request.query.get("device")
        res = []
        for n, d in sorted(self.devices.items()):
            if dname and dname != n:
                continue
            for l in d["links"]:
                if rt and rt not in l["rt"]:
                    continue
                if iface and iface not in l["if"]:
                    continue
                res.append({"device": n, "href": l["href"], "rt": l["rt"], "if": l["if"]})
        if request.query.get("format") == "text":
            return web.Response(text="; ".join(f"{r['device']} {r['href']}" for r in res) or "немає збігів")
        return web.json_response(res)

    async def h_discover(self, request):
        rt = request.query.get("rt") or None
        found = await self.discover(rt)
        if rt:
            text = "; ".join(f"[{f['ip']}] " + ", ".join(l["href"] for l in f["links"]) for f in found) or "немає збігів"
            await self.oh_update("OCF_FilterResult", text[:250])
        return web.json_response([{"ip": f["ip"], "anchor": f["anchor"], "links": f["links"]} for f in found])

    async def h_onboard(self, request):
        name = request.match_info["name"]
        names = sorted(self.devices) if name == "all" else [self.dev_or_404(name)["name"]]
        result = {}
        for n in names:
            try:
                result[n] = await self.onboard(n)
            except Exception as exc:
                self.event("error", f"{n}: onboarding failed: {exc}")
                result[n] = False
        return web.json_response(result)

    async def h_reset(self, request):
        await self.reset(self.dev_or_404(request.match_info["name"])["name"])
        return web.json_response({"ok": True})

    async def crudn(self, op, dev, href, payload=None, query=(), secure=None):
        meth = {"retrieve": aiocoap.GET, "update": aiocoap.POST, "create": aiocoap.POST, "delete": aiocoap.DELETE}[op]
        t0 = time.monotonic()
        r, body, scheme = await self.coap(meth, dev, href, payload, query=query, secure=secure)
        ms = (time.monotonic() - t0) * 1000
        q = ("?" + "&".join(query)) if query else ""
        self.event(op, f"{dev['name']} {op.upper()} {scheme}://…{href}{q} -> {code_str(r.code)} ({ms:.0f} мс)")
        out = {"code": code_str(r.code), "ok": r.code.is_successful(), "scheme": scheme, "rep": body,
               "content_format": cfnum(r.opt.content_format),
               "bytes": len(r.payload), "location": "/" + "/".join(r.opt.location_path) if r.opt.location_path else None}
        if op in ("retrieve", "update") and r.code.is_successful() and isinstance(body, dict):
            await self.store_value(dev["name"], href, {**self.values.get(dev["name"], {}).get(href, {}), **body})
        return out

    def sec_param(self, request):
        s = request.query.get("secure")
        return None if s is None else s in ("1", "true")

    async def h_res(self, request):
        dev = self.dev_or_404(request.match_info["name"])
        href = "/" + request.match_info["href"]
        query = tuple(f"{k}={v}" for k, v in request.query.items() if k in ("if", "rt"))
        secure = self.sec_param(request)
        try:
            if request.method == "GET":
                out = await self.crudn("retrieve", dev, href, query=query, secure=secure)
            elif request.method == "POST":
                out = await self.crudn("update", dev, href, await request.json(), query=query, secure=secure)
            elif request.method == "PUT":
                out = await self.crudn("create", dev, href, await request.json(), query=("if=oic.if.create",), secure=secure)
                await self.refresh_links(dev)
            else:
                out = await self.crudn("delete", dev, href, secure=secure)
                await self.refresh_links(dev)
        except asyncio.TimeoutError:
            return web.json_response({"code": "timeout", "ok": False, "error": "CoAP timeout"}, status=504)
        except aiocoap.error.NetworkError as exc:
            return web.json_response({"code": "network error", "ok": False, "error": str(exc)}, status=502)
        return web.json_response(out, status=200 if out["ok"] else 400)

    async def refresh_links(self, dev):
        _, links, _ = await self.coap(aiocoap.GET, dev, "/oic/res", secure=False)
        if isinstance(links, list):
            dev["links"] = links
        if dev["name"] == "plug":
            n = sum(1 for l in dev["links"] if "x.org.iotprp12.schedule" in l["rt"])
            await self.oh_update("Plug_Schedules", n)

    async def h_state(self, request):
        v = self.values
        g = lambda n, h, k, d=None: v.get(n, {}).get(h, {}).get(k, d)
        st = {n: DOS[d["pstat"]["dos"]["s"]] for n, d in self.devices.items()}
        return web.json_response({
            "lamp": {"switch": g("lamp", "/lamp/switch", "value", False), "brightness": g("lamp", "/lamp/brightness", "brightness", 0), "sec": st.get("lamp")},
            "sensor": {"temperature": g("sensor", "/sensor/temperature", "temperature"), "humidity": g("sensor", "/sensor/humidity", "humidity"), "sec": st.get("sensor")},
            "plug": {"switch": g("plug", "/plug/switch", "value", False), "power": g("plug", "/plug/energy", "power"), "energy": g("plug", "/plug/energy", "energy"), "sec": st.get("plug")},
            "devices": len(self.devices), "notifications": self.notifications,
        })

    async def h_cmd(self, request):
        key = request.match_info["key"]
        if key not in COMMANDS:
            raise web.HTTPNotFound(text=f"unknown command {key}")
        name, href, prop, kind = COMMANDS[key]
        raw = (await request.text()).strip()
        if kind == "bool":
            value = raw.lower() in ("true", "on", "1")
        else:  # Dimmer може надіслати ON/OFF замість відсотків
            value = {"ON": 100, "OFF": 0}.get(raw.upper())
            if value is None:
                try:
                    value = int(round(float(raw)))
                except ValueError:
                    raise web.HTTPBadRequest(text=f"bad value {raw!r}")
        dev = self.dev_or_404(name)
        out = await self.crudn("update", dev, href, {prop: value})
        return web.json_response(out, status=200 if out["ok"] else 400)

    async def h_schedule(self, request):
        dev = self.dev_or_404("plug")
        if request.method == "DELETE":
            ids = sorted((l["href"] for l in dev["links"] if "x.org.iotprp12.schedule" in l["rt"]), key=lambda h: int(h.rsplit("/", 1)[1]))
            if not ids:
                return web.json_response({"error": "no schedules"}, status=404)
            out = await self.crudn("delete", dev, ids[-1])
        else:
            at = (datetime.now() + timedelta(minutes=1)).strftime("%H:%M")
            body = {"rt": ["x.org.iotprp12.schedule"], "rep": {"at": at, "value": True}}
            out = await self.crudn("create", dev, "/plug/schedules", body, query=("if=oic.if.create",))
        await self.refresh_links(dev)
        return web.json_response(out, status=200 if out["ok"] else 400)

    async def h_events(self, request):
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"})
        await resp.prepare(request)
        qu: asyncio.Queue = asyncio.Queue()
        self.listeners.add(qu)
        try:
            for ev in list(self.events)[-40:]:
                await resp.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode())
            while True:
                try:
                    ev = await asyncio.wait_for(qu.get(), 15)
                    await resp.write(f"data: {json.dumps(ev, ensure_ascii=False)}\n\n".encode())
                except asyncio.TimeoutError:
                    await resp.write(b": ping\n\n")
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            self.listeners.discard(qu)
        return resp

    async def h_index(self, request):
        return web.FileResponse(Path(__file__).with_name("ui.html"))

    async def periodic(self):
        await asyncio.sleep(3)
        while True:
            try:
                await self.discover()
            except Exception as exc:
                log.warning("discovery failed: %s", exc)
            await asyncio.sleep(60)

    async def run(self):
        self.load_store()
        self.ctx = await aiocoap.Context.create_client_context()
        self.http = ClientSession(timeout=ClientTimeout(total=3))
        app = web.Application()
        app.add_routes([
            web.get("/", self.h_index),
            web.get("/api/devices", self.h_devices),
            web.get("/api/resources", self.h_resources),
            web.post("/api/discover", self.h_discover),
            web.post("/api/onboard/{name}", self.h_onboard),
            web.post("/api/reset/{name}", self.h_reset),
            web.route("*", "/api/res/{name}/{href:.*}", self.h_res),
            web.get("/api/state", self.h_state),
            web.post("/api/cmd/{key}", self.h_cmd),
            web.post("/api/schedule", self.h_schedule),
            web.delete("/api/schedule", self.h_schedule),
            web.get("/api/events", self.h_events),
        ])
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", 8090).start()
        log.info("OCF gateway: http://0.0.0.0:8090  OBT uuid=%s", OBT_UUID)
        await self.periodic()


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")
    for noisy in ("coap", "coap-server", "aiohttp.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    asyncio.run(Gateway().run())
