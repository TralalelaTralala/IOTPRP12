"""
Емулятор OCF-пристрою (Open Connectivity Foundation, OCF Core 2.x) на CoAP (aiocoap).

DEVICE=lamp | sensor | plug — тип пристрою (oic.d.light / oic.d.sensor / oic.d.smartplug).

Ресурси:
  /oic/res          oic.wk.res   discovery (фільтри ?rt= та ?if=), multicast ff02::158 / ff03::158
  /oic/d            oic.wk.d     інформація про пристрій (n, di, piid, icv, dmv)
  /oic/p            oic.wk.p     інформація про платформу (pi, mnmn, mnmo, mnfv ...)
  /oic/sec/doxm     oic.r.doxm   ownership transfer (Just Works, oxm 0)
  /oic/sec/pstat    oic.r.pstat  стан провізіонування: RESET / RFOTM / RFPRO / RFNOP
  /oic/sec/cred     oic.r.cred   облікові дані (PSK власника) -> DTLS
  /oic/sec/acl2     oic.r.acl2   список контролю доступу (CRUDN-біти)
  /<dev>            oic.wk.col   колекція ресурсів пристрою: oic.if.ll, oic.if.b (batch), oic.if.baseline
  /<dev>/...        oic.r.*      ресурси пристрою (switch.binary, light.brightness, temperature, humidity, energy.consumption)
  /plug/schedules   oic.wk.col   колекція з CREATE (oic.if.create) та DELETE дочірніх ресурсів

Транспорт: coap://[::]:5683 (незахищений) і coaps://[ip]:5684 (DTLS PSK після onboarding).
Формат: application/vnd.ocf+cbor (10000) за замовчуванням, application/json (50) за Accept.
"""
import asyncio
import base64
import json
import logging
import math
import os
import random
import socket
import time
import uuid
from datetime import datetime, timezone

import aiocoap
import aiocoap.resource as resource
import cbor2

log = logging.getLogger("ocf-device")

DEVICE = os.getenv("DEVICE", "lamp")
NAME = os.getenv("NAME", DEVICE)
IFACE = os.getenv("IFACE", "eth0")
DI = str(uuid.uuid5(uuid.NAMESPACE_URL, f"iotprp12:device:{NAME}"))
PIID = str(uuid.uuid5(uuid.NAMESPACE_URL, f"iotprp12:piid:{NAME}"))
PI = str(uuid.uuid5(uuid.NAMESPACE_URL, f"iotprp12:platform:{NAME}"))
NIL_UUID = "00000000-0000-0000-0000-000000000000"

CF_CBOR, CF_JSON = 10000, 50


def cfnum(cf) -> int | None:
    """ContentFormat (aiocoap >= 0.4.8 — не int) -> числовий код."""
    if cf is None:
        return None
    return int(getattr(cf, "value", cf))
# CRUDN permission bits (OCF Security spec, oic.r.acl2)
C, R, U, D, N = 1, 2, 4, 8, 16
DOS = {0: "RESET", 1: "RFOTM", 2: "RFPRO", 3: "RFNOP", 4: "SRESET"}

DEVICE_TYPES = {"lamp": "oic.d.light", "sensor": "oic.d.sensor", "plug": "oic.d.smartplug"}
MODELS = {"lamp": "IOTPR-Lamp-L1", "sensor": "IOTPR-Climate-S2", "plug": "IOTPR-Plug-P3"}


# ------------------------------------------------------------------ helpers
def q(request) -> dict:
    out = {}
    for item in request.opt.uri_query:
        k, _, v = item.partition("=")
        out[k] = v
    return out


def respond(request, obj, code=aiocoap.CONTENT, **kw) -> aiocoap.Message:
    accept = request.opt.accept
    if cfnum(accept) == CF_JSON:
        return aiocoap.Message(code=code, payload=json.dumps(obj, ensure_ascii=False).encode(), content_format=CF_JSON, **kw)
    return aiocoap.Message(code=code, payload=cbor2.dumps(obj), content_format=CF_CBOR, **kw)


def error(code, text: str) -> aiocoap.Message:
    return aiocoap.Message(code=code, payload=text.encode(), content_format=0)


def decode(request):
    if not request.payload:
        return {}
    cf = request.opt.content_format
    if cfnum(cf) == CF_JSON:
        return json.loads(request.payload.decode())
    return cbor2.loads(request.payload)


def subject_of(request) -> str | None:
    """uuid автентифікованого через DTLS клієнта (мітка облікових даних ':<uuid>') або None."""
    claims = list(getattr(request.remote, "authenticated_claims", None) or [])
    for c in claims:
        if isinstance(c, str) and c.startswith(":"):
            return c[1:]
    return None


# ------------------------------------------------------------------ безпека
class Security:
    def __init__(self, device):
        self.device = device
        self.reset()

    def reset(self):
        self.doxm = {"rt": ["oic.r.doxm"], "if": ["oic.if.baseline"], "oxms": [0], "oxmsel": 0, "sct": 1,
                     "owned": False, "deviceuuid": DI, "devowneruuid": NIL_UUID, "rowneruuid": NIL_UUID}
        self.pstat = {"rt": ["oic.r.pstat"], "if": ["oic.if.baseline"], "dos": {"s": 1, "p": False}, "isop": False,
                      "cm": 2, "tm": 0, "om": 4, "sm": 4, "rowneruuid": NIL_UUID}
        self.cred = {"rt": ["oic.r.cred"], "if": ["oic.if.baseline"], "creds": [], "rowneruuid": NIL_UUID}
        self.acl2 = {"rt": ["oic.r.acl2"], "if": ["oic.if.baseline"], "aclist2": [], "rowneruuid": NIL_UUID}

    @property
    def state(self) -> int:
        return self.pstat["dos"]["s"]

    def is_owner(self, request) -> bool:
        s = subject_of(request)
        return s is not None and s == self.doxm["devowneruuid"]

    def allowed(self, request, href: str, perm: int) -> bool:
        """Перевірка ACL2 для ресурсу href і запитаної дії (біт CRUDN)."""
        if self.state != 3:  # поки пристрій не в RFNOP, прикладні ресурси закриті
            return False
        secure = request.remote.scheme == "coaps"
        subj = subject_of(request)
        for ace in self.acl2["aclist2"]:
            sub = ace.get("subject", {})
            if "conntype" in sub:
                ok = (sub["conntype"] == "anon-clear" and not secure) or (sub["conntype"] == "auth-crypt" and secure)
            else:
                ok = subj is not None and sub.get("uuid") == subj
            if not ok or not (ace.get("permission", 0) & perm):
                continue
            for r in ace.get("resources", []):
                if r.get("wc") in ("*", "+") or r.get("href") == href:
                    return True
        return False

    def deny(self, request) -> aiocoap.Message:
        if self.state != 3:
            return error(aiocoap.UNAUTHORIZED, f"device not provisioned ({DOS[self.state]}), onboarding required")
        if request.remote.scheme != "coaps":
            return error(aiocoap.UNAUTHORIZED, "access denied by ACL for anon-clear, use coaps (DTLS)")
        return error(aiocoap.FORBIDDEN, "access denied by ACL")

    def install_psk(self):
        """Реєструє PSK власника в DTLS-сервері: після цього coaps-клієнт автентифікується як ':<uuid>'."""
        creds = {}
        for c in self.cred["creds"]:
            if c.get("credtype") == 1 and "privatedata" in c:
                key = base64.b64decode(c["privatedata"]["data"])
                creds[":" + c["subjectuuid"]] = {"dtls": {"psk": {"hex": key.hex()}, "client-identity": {"ascii": c["subjectuuid"].replace("-", "")}}}  # tinydtls: identity <= 32 байти
        dctx = self.device.dtls_ctx
        if dctx is not None:
            dctx.server_credentials.clear()
            dctx.server_credentials.load_from_dict(creds)
        log.info("DTLS PSK credentials installed: %s", list(creds))


class SecResource(resource.Resource):
    """Ресурси /oic/sec/*: у RFOTM доступні без DTLS (Just Works), далі — лише власнику через DTLS."""

    def __init__(self, sec: Security, name: str):
        super().__init__()
        self.sec, self.name = sec, name

    def rep(self):
        return getattr(self.sec, self.name)

    async def render_get(self, request):
        if self.name in ("cred",) and self.sec.state != 1 and not self.sec.is_owner(request):
            return self.sec.deny(request)
        rep = dict(self.rep())
        if self.name == "cred":  # приватні ключі назовні не віддаються
            rep["creds"] = [{k: v for k, v in c.items() if k != "privatedata"} for c in rep["creds"]]
        return respond(request, rep)

    async def render_post(self, request):
        sec = self.sec
        if sec.state != 1 and not sec.is_owner(request):
            return sec.deny(request)
        try:
            body = decode(request)
        except Exception:
            return error(aiocoap.BAD_REQUEST, "malformed payload")
        rep = self.rep()
        if self.name == "doxm":
            for k in ("oxmsel", "devowneruuid", "rowneruuid"):
                if k in body:
                    rep[k] = body[k]
            if body.get("owned") is True:
                owner = rep["devowneruuid"]
                if owner == NIL_UUID or not any(c["subjectuuid"] == owner for c in sec.cred["creds"]):
                    return error(aiocoap.NOT_ACCEPTABLE, "owner uuid and owner credential required before owned=true")
                rep["owned"] = True
                log.info("ownership transferred to %s", owner)
        elif self.name == "pstat":
            target = body.get("dos", {}).get("s")
            if target is not None:
                cur = sec.state
                if target == 0:  # RESET -> повертаємось у RFOTM з очищенням стану
                    sec.reset()
                    sec.install_psk()
                    log.warning("device RESET -> RFOTM")
                    sec.device.reindex()
                    return respond(request, sec.pstat, code=aiocoap.CHANGED)
                allowed = {(1, 2), (2, 3), (3, 2)}
                if (cur, target) not in allowed or (target == 2 and not sec.doxm["owned"]):
                    return error(aiocoap.NOT_ACCEPTABLE, f"invalid dos transition {DOS[cur]} -> {DOS.get(target)}")
                rep["dos"] = {"s": target, "p": False}
                rep["isop"] = target == 3
                log.info("pstat: %s -> %s", DOS[cur], DOS[target])
            if "rowneruuid" in body:
                rep["rowneruuid"] = body["rowneruuid"]
        elif self.name == "cred":
            for c in body.get("creds", []):
                if not {"subjectuuid", "credtype", "privatedata"} <= set(c):
                    return error(aiocoap.BAD_REQUEST, "cred requires subjectuuid, credtype, privatedata")
                c.setdefault("credid", len(rep["creds"]) + 1)
                rep["creds"] = [x for x in rep["creds"] if x["subjectuuid"] != c["subjectuuid"]] + [c]
            sec.install_psk()
        elif self.name == "acl2":
            for i, ace in enumerate(body.get("aclist2", []), 1):
                ace.setdefault("aceid", len(rep["aclist2"]) + i)
            rep["aclist2"] = rep["aclist2"] + body.get("aclist2", [])
            log.info("acl2: %d ACEs", len(rep["aclist2"]))
        return respond(request, {k: v for k, v in rep.items() if k != "creds"} if self.name == "cred" else rep, code=aiocoap.CHANGED)


# ------------------------------------------------------------------ прикладні ресурси
class OcfResource(resource.ObservableResource):
    def __init__(self, device, href, rt, ifs, props, writable=(), schema=None, name=None):
        super().__init__()
        self.device, self.href, self.rt, self.ifs = device, href, rt, ifs
        self.props, self.writable, self.schema = props, set(writable), schema or {}
        self.n = name or href.rsplit("/", 1)[-1]

    def representation(self, iface: str) -> dict:
        rep = dict(self.props)
        if iface == "oic.if.baseline":
            rep = {"rt": self.rt, "if": self.ifs, "n": self.n, **rep}
        return rep

    def link(self) -> dict:
        return {"href": self.href, "rt": self.rt, "if": self.ifs}

    def iface(self, request):
        i = q(request).get("if", self.ifs[0])
        return i if i in self.ifs else None

    async def render_get(self, request):
        if not self.device.sec.allowed(request, self.href, R):
            return self.device.sec.deny(request)
        i = self.iface(request)
        if i is None:
            return error(aiocoap.BAD_REQUEST, f"unsupported interface, supported: {self.ifs}")
        return respond(request, self.representation(i))

    def validate(self, body: dict) -> str | None:
        for k, v in body.items():
            if k in ("rt", "if", "n"):
                continue
            if k not in self.writable:
                return f"property '{k}' is read-only or unknown"
            kind = self.schema.get(k)
            if kind == "bool" and not isinstance(v, bool):
                return f"'{k}' must be boolean"
            if isinstance(kind, tuple):
                if not isinstance(v, (int, float)) or isinstance(v, bool) or not kind[0] <= v <= kind[1]:
                    return f"'{k}' must be a number in range {list(kind)}"
            if kind == "str" and not isinstance(v, str):
                return f"'{k}' must be string"
        return None

    def apply(self, body: dict):
        for k, v in body.items():
            if k in self.writable:
                self.props[k] = v
        self.updated_state()

    async def render_post(self, request):
        """UPDATE (OCF використовує POST для часткового оновлення)."""
        if not self.writable:
            return error(aiocoap.METHOD_NOT_ALLOWED, "read-only resource (oic.if.s)")
        if not self.device.sec.allowed(request, self.href, U):
            return self.device.sec.deny(request)
        try:
            body = decode(request)
        except Exception:
            return error(aiocoap.BAD_REQUEST, "malformed payload")
        msg = self.validate(body)
        if msg:
            return error(aiocoap.BAD_REQUEST, msg)
        self.apply(body)
        log.info("UPDATE %s %s by %s", self.href, body, subject_of(request) or request.remote.hostinfo)
        return respond(request, self.representation("oic.if.a"), code=aiocoap.CHANGED)

    async def add_observation(self, request, serverobservation):
        # NOTIFY лише для тих, кому ACL дозволяє біт N
        if self.device.sec.allowed(request, self.href, N):
            await super().add_observation(request, serverobservation)


class Collection(OcfResource):
    """oic.wk.col: oic.if.ll — посилання, oic.if.b — пакетні Retrieve/Update, oic.if.baseline."""

    def __init__(self, device, href, children, extra_rt=(), ifs=("oic.if.ll", "oic.if.b", "oic.if.baseline")):
        super().__init__(device, href, ["oic.wk.col", *extra_rt], list(ifs), {})
        self.children = children  # список OcfResource

    def links(self):
        return [c.link() for c in self.children]

    def representation(self, iface):
        if iface == "oic.if.ll":
            return self.links()
        if iface == "oic.if.b":
            return [{"href": c.href, "rep": c.representation("oic.if.a")} for c in self.children]
        return {"rt": self.rt, "if": self.ifs, "n": self.n, "links": self.links()}

    async def render_post(self, request):
        i = q(request).get("if")
        if i != "oic.if.b":
            return error(aiocoap.BAD_REQUEST, "collection update requires ?if=oic.if.b")
        try:
            items = decode(request)
        except Exception:
            return error(aiocoap.BAD_REQUEST, "malformed payload")
        if not isinstance(items, list):
            return error(aiocoap.BAD_REQUEST, "batch payload must be an array of {href, rep}")
        by_href = {c.href: c for c in self.children}
        # спочатку перевіряємо все, потім застосовуємо (атомарний batch)
        for it in items:
            child = by_href.get(it.get("href"))
            if child is None:
                return error(aiocoap.NOT_FOUND, f"no child {it.get('href')}")
            if not self.device.sec.allowed(request, child.href, U):
                return self.device.sec.deny(request)
            msg = child.validate(it.get("rep", {}))
            if msg:
                return error(aiocoap.BAD_REQUEST, f"{child.href}: {msg}")
        for it in items:
            by_href[it["href"]].apply(it["rep"])
        log.info("BATCH UPDATE %s: %d resources", self.href, len(items))
        return respond(request, self.representation("oic.if.b"), code=aiocoap.CHANGED)


class ScheduleCollection(Collection):
    """Колекція з CREATE/DELETE: POST ?if=oic.if.create створює дочірній ресурс x.org.iotprp12.schedule."""

    def __init__(self, device, href):
        super().__init__(device, href, [], extra_rt=("x.org.iotprp12.schedules",), ifs=("oic.if.ll", "oic.if.create", "oic.if.baseline"))
        self.next_id = 1

    async def render_post(self, request):
        if q(request).get("if") != "oic.if.create":
            return error(aiocoap.BAD_REQUEST, "use ?if=oic.if.create to CREATE a schedule")
        if not self.device.sec.allowed(request, self.href, C):
            return self.device.sec.deny(request)
        try:
            body = decode(request)
        except Exception:
            return error(aiocoap.BAD_REQUEST, "malformed payload")
        rep = body.get("rep", body)
        at, value = rep.get("at"), rep.get("value")
        if not isinstance(at, str) or len(at) != 5 or at[2] != ":" or not isinstance(value, bool):
            return error(aiocoap.BAD_REQUEST, "schedule requires rep {at: 'HH:MM', value: bool}")
        sid = str(self.next_id)
        self.next_id += 1
        href = f"{self.href}/{sid}"
        child = ScheduleResource(self.device, href, {"at": at, "value": value, "enabled": True})
        self.children.append(child)
        self.device.site.add_resource(tuple(href.strip("/").split("/")), child)
        self.device.reindex()
        self.updated_state()
        log.info("CREATE %s %s", href, child.props)
        return respond(request, {"href": href, **child.representation("oic.if.baseline")}, code=aiocoap.CREATED,
                       location_path=tuple(href.strip("/").split("/")))


class ScheduleResource(OcfResource):
    def __init__(self, device, href, props):
        super().__init__(device, href, ["x.org.iotprp12.schedule"], ["oic.if.rw", "oic.if.baseline"], props,
                         writable=("at", "value", "enabled"), schema={"value": "bool", "enabled": "bool", "at": "str"})

    async def render_delete(self, request):
        if not self.device.sec.allowed(request, self.href, D):
            return self.device.sec.deny(request)
        col = self.device.schedules
        col.children = [c for c in col.children if c is not self]
        self.device.site._resources.pop(tuple(self.href.strip("/").split("/")), None)
        self.device.reindex()
        col.updated_state()
        log.info("DELETE %s", self.href)
        return aiocoap.Message(code=aiocoap.DELETED)


# ------------------------------------------------------------------ discovery ресурси
class ResDiscovery(resource.Resource):
    """/oic/res (oic.wk.res), oic.if.ll: посилання на всі ресурси з anchor ocf://<di> та endpoints."""

    def __init__(self, device):
        super().__init__()
        self.device = device

    async def render_get(self, request):
        f = q(request)
        links = []
        for r in self.device.discoverable():
            if "rt" in f and f["rt"] not in r["rt"]:
                continue
            if "if" in f and f["if"] not in r["if"]:
                continue
            links.append({"anchor": f"ocf://{DI}", **r, "eps": self.device.eps(r["href"])})
        if not links:
            # без збігів — 4.04 (шлюз ігнорує такі відповіді на multicast-запит)
            return error(aiocoap.NOT_FOUND, "no matching resources")
        return respond(request, links)


class DeviceInfo(resource.Resource):
    def __init__(self, device):
        super().__init__()
        self.device = device

    async def render_get(self, request):
        return respond(request, {
            "rt": ["oic.wk.d", DEVICE_TYPES[DEVICE]], "if": ["oic.if.r", "oic.if.baseline"],
            "n": NAME, "di": DI, "piid": PIID, "icv": "ocf.2.0.5", "dmv": "ocf.res.1.3.0,ocf.sh.1.3.0",
            "dmno": MODELS[DEVICE], "dmn": [{"language": "uk", "value": "IOTPR Labs"}],
        })


class PlatformInfo(resource.Resource):
    def __init__(self, device):
        super().__init__()
        self.device = device

    async def render_get(self, request):
        return respond(request, {
            "rt": ["oic.wk.p"], "if": ["oic.if.r", "oic.if.baseline"], "pi": PI,
            "mnmn": "IOTPR Labs", "mnml": "https://example.org/iotpr", "mnmo": MODELS[DEVICE],
            "mndt": "2026-11-01", "mnpv": "virtual-1.0", "mnos": "Debian 12 (Docker)", "mnhw": "emulated",
            "mnfv": "1.2.0", "st": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })


# ------------------------------------------------------------------ пристрій
class Device:
    def __init__(self):
        self.site = resource.Site()
        self.sec = Security(self)
        self.dtls_ctx = None
        self.ip = None
        self.app: list[OcfResource] = []
        self.schedules = None

        s = self.site
        s.add_resource(("oic", "res"), ResDiscovery(self))
        s.add_resource(("oic", "d"), DeviceInfo(self))
        s.add_resource(("oic", "p"), PlatformInfo(self))
        for name in ("doxm", "pstat", "cred", "acl2"):
            s.add_resource(("oic", "sec", name), SecResource(self.sec, name))

        if DEVICE == "lamp":
            self.app = [
                OcfResource(self, "/lamp/switch", ["oic.r.switch.binary"], ["oic.if.a", "oic.if.baseline"],
                            {"value": False}, writable=("value",), schema={"value": "bool"}),
                OcfResource(self, "/lamp/brightness", ["oic.r.light.brightness"], ["oic.if.a", "oic.if.baseline"],
                            {"brightness": 70}, writable=("brightness",), schema={"brightness": (0, 100)}),
            ]
        elif DEVICE == "sensor":
            self.app = [
                OcfResource(self, "/sensor/temperature", ["oic.r.temperature"], ["oic.if.s", "oic.if.baseline"],
                            {"temperature": 22.5, "units": "C", "range": [-40.0, 85.0]}),
                OcfResource(self, "/sensor/humidity", ["oic.r.humidity"], ["oic.if.s", "oic.if.baseline"],
                            {"humidity": 45}),
            ]
        elif DEVICE == "plug":
            self.app = [
                OcfResource(self, "/plug/switch", ["oic.r.switch.binary"], ["oic.if.a", "oic.if.baseline"],
                            {"value": False}, writable=("value",), schema={"value": "bool"}),
                OcfResource(self, "/plug/energy", ["oic.r.energy.consumption"], ["oic.if.s", "oic.if.baseline"],
                            {"power": 0.0, "energy": 0.0}),
            ]
        for r in self.app:
            s.add_resource(tuple(r.href.strip("/").split("/")), r)
        col = Collection(self, f"/{DEVICE}", list(self.app))
        s.add_resource((DEVICE,), col)
        self.collection = col
        if DEVICE == "plug":
            self.schedules = ScheduleCollection(self, "/plug/schedules")
            s.add_resource(("plug", "schedules"), self.schedules)

    def reindex(self):
        pass  # /oic/res будується динамічно з discoverable()

    def discoverable(self):
        out = [
            {"href": "/oic/res", "rt": ["oic.wk.res"], "if": ["oic.if.ll", "oic.if.baseline"], "p": {"bm": 1}},
            {"href": "/oic/d", "rt": ["oic.wk.d", DEVICE_TYPES[DEVICE]], "if": ["oic.if.r", "oic.if.baseline"], "p": {"bm": 1}},
            {"href": "/oic/p", "rt": ["oic.wk.p"], "if": ["oic.if.r", "oic.if.baseline"], "p": {"bm": 1}},
            {"href": "/oic/sec/doxm", "rt": ["oic.r.doxm"], "if": ["oic.if.baseline"], "p": {"bm": 1}},
            {"href": "/oic/sec/pstat", "rt": ["oic.r.pstat"], "if": ["oic.if.baseline"], "p": {"bm": 1}},
            {"href": self.collection.href, "rt": self.collection.rt, "if": self.collection.ifs, "p": {"bm": 3}},
        ]
        for r in self.app:
            out.append({**r.link(), "p": {"bm": 3}})  # bm: 1 discoverable | 2 observable
        if self.schedules is not None:
            out.append({**self.schedules.link(), "p": {"bm": 3}})
            out += [{**c.link(), "p": {"bm": 3}} for c in self.schedules.children]
        return out

    def eps(self, href):
        if href.startswith("/oic/sec/cred") or href.startswith("/oic/sec/acl2"):
            return [{"ep": f"coaps://[{self.ip}]:5684"}]
        return [{"ep": f"coap://[{self.ip}]:5683"}, {"ep": f"coaps://[{self.ip}]:5684"}]

    async def simulate(self):
        """Зміна показників: датчик температури/вологості, лічильник енергії розетки -> NOTIFY спостерігачам."""
        t0 = time.monotonic()
        while True:
            await asyncio.sleep(2.0)
            if DEVICE == "sensor":
                t, h = self.app
                phase = (time.monotonic() - t0) / 60
                t.props["temperature"] = round(22.0 + 2.5 * math.sin(phase) + random.uniform(-0.15, 0.15), 1)
                h.props["humidity"] = int(round(45 + 6 * math.cos(phase) + random.uniform(-1, 1)))
                t.updated_state()
                h.updated_state()
            elif DEVICE == "plug":
                sw, en = self.app
                on = sw.props["value"]
                en.props["power"] = round(random.uniform(55.0, 65.0), 1) if on else 0.0
                en.props["energy"] = round(en.props["energy"] + en.props["power"] * 2 / 3600, 3)
                en.updated_state()
                now = datetime.now().strftime("%H:%M")
                for sch in self.schedules.children:
                    if sch.props.get("enabled") and sch.props["at"] == now and sw.props["value"] != sch.props["value"]:
                        sw.apply({"value": sch.props["value"]})
                        log.info("schedule %s fired: switch -> %s", sch.href, sch.props["value"])

    async def run(self):
        addrs = [a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
                 if not a[4][0].startswith("fe80")]
        self.ip = addrs[0]
        await self.start_coap()
        # aiocoap прив'язує DTLS-сервер до конкретної адреси, порт = 5683 + 1 = 5684
        self.dtls_ctx = await aiocoap.Context.create_server_context(self.site, bind=(self.ip, 5683), transports=["tinydtls_server"])
        log.info("OCF %s '%s' di=%s  coap://[::]:5683 (multicast ff02::158) coaps://[%s]:5684  state=%s",
                 DEVICE_TYPES[DEVICE], NAME, DI, self.ip, DOS[self.sec.state])
        asyncio.get_running_loop().create_task(self.watchdog())
        await self.simulate()

    async def start_coap(self):
        # IPv6 multicast групи OCF: ff02::158 (link-local), ff03::158 (realm-local)
        groups = [("ff02::158", IFACE), ("ff03::158", IFACE)]
        self.coap_ctx = await aiocoap.Context.create_server_context(self.site, bind=("::", 5683), multicast=groups, transports=["udp6"])

    @staticmethod
    def coap_socket_alive() -> bool:
        with open("/proc/net/udp6") as f:
            return any(line.split()[1] == "00000000000000000000000000000000:1633" for line in f.readlines()[1:])

    async def watchdog(self):
        """aiocoap udp6 закриває транспорт на деяких ICMP-помилках (errqueue) — тоді піднімаємо сервер 5683 знову."""
        while True:
            await asyncio.sleep(2.0)
            if not self.coap_socket_alive():
                log.warning("coap transport on :5683 lost, restarting CoAP server")
                try:
                    await self.coap_ctx.shutdown()
                except Exception:
                    pass
                try:
                    await self.start_coap()
                    log.info("CoAP server on :5683 restarted")
                except Exception as exc:
                    log.error("CoAP restart failed: %s", exc)


def _loop_exceptions(loop, context):
    log.error("asyncio: %s %r", context.get("message"), context.get("exception"))


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("coap-server").setLevel(logging.WARNING)
    logging.getLogger("coap").setLevel(logging.WARNING)
    async def _main():
        asyncio.get_running_loop().set_exception_handler(_loop_exceptions)
        await Device().run()

    asyncio.run(_main())
