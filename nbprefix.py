#!/usr/bin/env python3
"""
nbprefix - lesende prefiks-utforsker for NetBox IPAM.

Kjører en lokal webserver på 127.0.0.1 og åpner nettleseren.
Kun standardbiblioteket - ingen pip-avhengigheter. Python 3.8+.

Konfig: nbprefix.json i samme mappe som scriptet:
  {"netbox_url": "https://netbox.example.no", "token": "....", "verify_tls": true}
Valgfritt: "ca_file": "C:/sti/til/ca.pem", "port": 8765

Token:
  v1 (NetBox < 4.5, utfaset): 40 tegn, sendes som "Authorization: Token <token>"
  v2 (NetBox 4.5+):           "nbt_<nøkkel>.<token>", sendes som "Authorization: Bearer ..."
  NetBox viser nøkkel (Key) og token hver for seg når et v2-token opprettes. Oppgi enten
  hele verdien "nbt_<nøkkel>.<token>" i "token", eller nøkkelen i eget felt "token_key".

Bruk:  python nbprefix.py [--port N] [--no-browser]
"""
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
CONFIG_PATH = os.path.join(APP_DIR, "nbprefix.json")
DEFAULT_PORT = 8765

BITS = {4: 32, 6: 128}
MASKS = {f: [((1 << b) - 1) ^ ((1 << (b - l)) - 1) for l in range(b + 1)] for f, b in BITS.items()}


# --------------------------------------------------------------------------- config

def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_config(cfg):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


def is_configured(cfg):
    return bool(cfg.get("netbox_url") and cfg.get("token"))


# --------------------------------------------------------------------------- NetBox (kun GET)

class NetBoxError(Exception):
    pass


V2_PREFIX = "nbt_"
_RE_V2 = re.compile(r"^(?:nbt_)?([A-Za-z0-9]{8,24})\.([A-Za-z0-9]{32,64})$")
_RE_V2_SECRET_ONLY = re.compile(r"^[A-Za-z0-9]{40}$")
_RE_HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")


def _strip_scheme(s):
    s = (s or "").strip()
    for p in ("token ", "bearer "):
        if s.lower().startswith(p):
            s = s[len(p):].strip()
    return s


def normalize_token(token, key=""):
    """Returnerer (tokenverdi slik den skal sendes, versjon 1 eller 2).

    Godtar v1-token (40 tegn), komplett v2-token "nbt_<nøkkel>.<token>",
    "<nøkkel>.<token>" uten prefiks, eller nøkkel og token hver for seg.
    """
    tok = _strip_scheme(token)
    key = _strip_scheme(key)
    if key.startswith(V2_PREFIX):
        key = key[len(V2_PREFIX):]
    if "." in key and not tok:                     # hele verdien limt inn i nøkkelfeltet
        tok, key = key, ""
    if not tok:
        raise NetBoxError("Token mangler")
    if key:
        m = _RE_V2.match(tok)
        if m and m.group(1) == key:
            pass                                   # samme nøkkel oppgitt to ganger
        elif m or tok.startswith(V2_PREFIX):
            raise NetBoxError("Token-feltet inneholder allerede en nøkkel (nbt_<nøkkel>.<token>). "
                              "Fyll inn nøkkelfeltet bare når token-feltet har token-delen alene.")
        else:
            tok = f"{key}.{tok}"
    m = _RE_V2.match(tok)
    if m:
        return f"{V2_PREFIX}{m.group(1)}.{m.group(2)}", 2
    if tok.startswith(V2_PREFIX):
        raise NetBoxError("v2-token har feil form. Forventet nbt_<nøkkel>.<token>")
    return tok, 1


def token_version_of(cfg):
    try:
        return normalize_token(cfg.get("token", ""), cfg.get("token_key", ""))[1]
    except NetBoxError:
        return None


def token_hint(token, version, body):
    """Forklarende tillegg når NetBox avviser tokenet."""
    b = body.lower()
    if version == 1 and "v1 token" in b:
        if _RE_V2_SECRET_ONLY.match(token) and not _RE_HEX40.match(token):
            return ("Dette ser ut som bare token-delen av et v2-token (NetBox 4.5+). NetBox viser "
                    "nøkkel (Key) og token hver for seg: oppgi nøkkelen i tillegg, eller lim inn "
                    "hele verdien på formen nbt_<nøkkel>.<token>.")
        return ("Tokenet ble avvist som v1-token. Sjekk at det er riktig, aktivert og ikke utløpt. "
                "Et v2-token (NetBox 4.5+) må oppgis komplett: nbt_<nøkkel>.<token>.")
    if version == 2:
        if "v2 token" in b or "invalid token" in b:
            return ("v2-tokenet ble avvist. Sjekk at nøkkel og token hører sammen, "
                    "og at tokenet er aktivert og ikke utløpt.")
        if "not provided" in b:
            return ("Serveren godtok ikke Bearer-autentisering. v2-token krever NetBox 4.5 "
                    "eller nyere; eldre NetBox må bruke v1-token.")
    return ""


class NetBox:
    def __init__(self, cfg):
        self.base = cfg["netbox_url"].strip().rstrip("/")
        if not self.base.startswith(("http://", "https://")):
            self.base = "https://" + self.base
        self.token, self.token_version = normalize_token(cfg.get("token", ""), cfg.get("token_key", ""))
        # NetBox 4.5+ v2-token "nbt_<nøkkel>.<token>" sendes som Bearer, eldre v1 som Token.
        self.auth = ("Bearer " if self.token_version == 2 else "Token ") + self.token
        if cfg.get("verify_tls", True):
            self.ctx = ssl.create_default_context(cafile=cfg.get("ca_file") or None)
        else:
            self.ctx = ssl._create_unverified_context()

    def get(self, path, params=None):
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, method="GET", headers={
            "Authorization": self.auth,
            "Accept": "application/json",
            "User-Agent": "nbprefix/1.1",
        })
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=90) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300]
            msg = f"NetBox svarte HTTP {e.code} på {path}: {body}"
            hint = token_hint(self.token, self.token_version, body) if e.code in (401, 403) else ""
            raise NetBoxError(f"{msg} \u2013 {hint}" if hint else msg)
        except urllib.error.URLError as e:
            raise NetBoxError(f"Får ikke kontakt med {self.base}: {e.reason}")

    def get_all(self, path, params=None):
        params = dict(params or {})
        params["limit"] = 1000
        offset, out = 0, []
        while True:
            params["offset"] = offset
            d = self.get(path, params)
            res = d.get("results", [])
            out.extend(res)
            offset += len(res)
            if not res or not d.get("next") or offset >= d.get("count", 0):
                return out


def _name(o, *keys):
    if not o:
        return ""
    if isinstance(o, dict):
        for k in keys:
            if o.get(k):
                return str(o[k])
        return ""
    return str(o)


def normalize_prefix(rec, base):
    net = ipaddress.ip_network(rec["prefix"], strict=False)
    vrf = rec.get("vrf")
    st = rec.get("status")
    scope = rec.get("scope")
    scope_type = rec.get("scope_type") or ""
    if not scope and rec.get("site"):          # NetBox < 4.2
        scope, scope_type = rec["site"], "dcim.site"
    stype = scope_type.split(".")[-1] if scope_type else ""
    return {
        "id": rec["id"],
        "prefix": str(net),
        "fam": net.version,
        "net": int(net.network_address),
        "plen": net.prefixlen,
        "vrf_id": vrf["id"] if vrf else None,
        "vrf": _name(vrf, "name", "display"),
        "rd": (vrf or {}).get("rd") or "",
        "status": (st.get("value") if isinstance(st, dict) else st) or "",
        "status_label": (st.get("label") if isinstance(st, dict) else st) or "",
        "description": rec.get("description") or "",
        "tenant": _name(rec.get("tenant"), "name", "display"),
        "scope": _name(scope, "name", "display"),
        "scope_type": stype,
        "role": _name(rec.get("role"), "name", "display"),
        "vlan": _name(rec.get("vlan"), "display", "name"),
        "is_pool": bool(rec.get("is_pool")),
        "url": f"{base}/ipam/prefixes/{rec['id']}/",
    }


class DataStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.prefixes = []
        self.vrfs = []
        self.version = ""
        self.loaded_at = None
        self.error = None

    def load(self, cfg):
        nb = NetBox(cfg)
        status = nb.get("/api/status/")
        vrfs = nb.get_all("/api/ipam/vrfs/")
        recs = nb.get_all("/api/ipam/prefixes/")
        prefixes = [normalize_prefix(r, nb.base) for r in recs]
        with self.lock:
            self.version = str(status.get("netbox-version", ""))
            self.vrfs = [{"id": v["id"], "name": v.get("name") or v.get("display", ""),
                          "rd": v.get("rd") or ""} for v in vrfs]
            self.prefixes = prefixes
            self.loaded_at = time.time()
            self.error = None


STORE = DataStore()


# --------------------------------------------------------------------------- tre + ledig

def fmt_int(n):
    if n < 10 ** 9:
        return f"{n:,}".replace(",", "\u202f")
    k = n.bit_length() - 1
    return f"2^{k}" if n == 1 << k else f"\u2248 2^{k}"


def fmt_size(fam, n):
    if fam == 6 and n >= 1 << 64 and n % (1 << 64) == 0:
        return f"{fmt_int(n >> 64)} \u00d7 /64"
    return f"{fmt_int(n)} adr"


def addr_str(fam, v):
    return str(ipaddress.IPv4Address(v) if fam == 4 else ipaddress.IPv6Address(v))


def split_range(start, end, bits):
    """Dekomponer [start, end] i minst mulig antall CIDR-blokker."""
    out = []
    while start <= end:
        sb = (start & -start).bit_length() - 1 if start else bits
        while (1 << sb) > end - start + 1:
            sb -= 1
        out.append((start, bits - sb))
        start += 1 << sb
    return out


class Ids:
    def __init__(self):
        self.n = 0

    def __call__(self):
        self.n += 1
        return self.n


def free_node(fam, s, plen, ids):
    bits = BITS[fam]
    size = 1 << (bits - plen)
    return {"k": "f", "id": ids(), "fam": fam, "prefix": f"{addr_str(fam, s)}/{plen}",
            "plen": plen, "s": format(s, "x"), "e": format(s + size - 1, "x"),
            "desc": fmt_size(fam, size)}


def gap_node(fam, s, e, ids):
    blocks = split_range(s, e, BITS[fam])
    if len(blocks) == 1:
        return free_node(fam, blocks[0][0], blocks[0][1], ids)
    big = min(b[1] for b in blocks)
    return {"k": "g", "id": ids(), "fam": fam, "s": format(s, "x"), "e": format(e, "x"),
            "label": f"{addr_str(fam, s)} \u2013 {addr_str(fam, e)}", "n": len(blocks), "big": big,
            "desc": f"{len(blocks)} blokker \u00b7 største /{big} \u00b7 {fmt_size(fam, e - s + 1)}",
            "c": [free_node(fam, bs, bl, ids) for bs, bl in blocks]}


def _pick_parent(cands, p, prefixes):
    for c in cands:                       # samme VRF først
        if prefixes[c]["vrf_id"] == p["vrf_id"]:
            return c
    for c in cands:                       # deretter global
        if prefixes[c]["vrf_id"] is None:
            return c
    return cands[0]


def build_forest(prefixes, ids):
    idx = {}
    for i, p in enumerate(prefixes):
        idx.setdefault((p["fam"], p["net"], p["plen"]), []).append(i)
    kids = [[] for _ in prefixes]
    roots = []
    for i, p in enumerate(prefixes):
        m = MASKS[p["fam"]]
        parent = None
        for l in range(p["plen"] - 1, -1, -1):
            c = idx.get((p["fam"], p["net"] & m[l], l))
            if c:
                parent = _pick_parent(c, p, prefixes)
                break
        (kids[parent] if parent is not None else roots).append(i)

    def key(i):
        p = prefixes[i]
        return (p["fam"], p["net"], p["plen"], p["vrf"].lower(), p["id"])

    def make(i):
        p = prefixes[i]
        fam = p["fam"]
        size = 1 << (BITS[fam] - p["plen"])
        start = p["net"]
        end = start + size - 1
        ch = sorted(kids[i], key=key)
        entries = []
        cursor, covered, nd = start, 0, 0
        for k in ch:
            node = make(k)
            nd += 1 + node["nd"]
            cs = prefixes[k]["net"]
            ce = cs + (1 << (BITS[fam] - prefixes[k]["plen"])) - 1
            if cs > cursor:
                entries.append((cursor, gap_node(fam, cursor, cs - 1, ids)))
            entries.append((cs, node))
            if ce >= cursor:
                covered += ce - max(cs, cursor) + 1
                cursor = ce + 1
        if ch and cursor <= end:
            entries.append((cursor, gap_node(fam, cursor, end, ids)))
        entries.sort(key=lambda t: t[0])
        node = {k: p[k] for k in ("prefix", "fam", "plen", "vrf", "rd", "status", "status_label",
                                  "description", "tenant", "scope", "scope_type", "role",
                                  "vlan", "is_pool", "url") if p[k] not in ("", None, False)}
        node.update({"k": "p", "id": ids(), "s": format(start, "x"), "e": format(end, "x"),
                     "nc": len(ch), "nd": nd,
                     "cov": (covered / size) if (ch or p["status"] == "container") else None})
        if entries:
            node["c"] = [e for _, e in entries]
        return node

    return [make(i) for i in sorted(roots, key=key)]


def global_containers_for(vrf_prefixes, global_prefixes):
    """Globale containere som inneholder minst ett prefiks i VRF-en."""
    gidx = {}
    for g in global_prefixes:
        if g["status"] == "container":
            gidx.setdefault((g["fam"], g["net"], g["plen"]), []).append(g)
    keep = {}
    for p in vrf_prefixes:
        m = MASKS[p["fam"]]
        for l in range(p["plen"], -1, -1):
            for g in gidx.get((p["fam"], p["net"] & m[l], l), ()):
                keep[g["id"]] = g
    return list(keep.values())


def build_view(mode, fam, gc):
    with STORE.lock:
        prefixes = STORE.prefixes
        vrfs = {v["id"]: v for v in STORE.vrfs}
    if fam in ("4", "6"):
        prefixes = [p for p in prefixes if p["fam"] == int(fam)]
    ids = Ids()
    if mode == "all":
        return build_forest(prefixes, ids)
    if mode == "global":
        return build_forest([p for p in prefixes if p["vrf_id"] is None], ids)
    if mode == "grouped":
        groups = {}
        for p in prefixes:
            groups.setdefault(p["vrf_id"], []).append(p)
        order = sorted(groups, key=lambda v: (v is not None, (vrfs.get(v, {}).get("name") or "").lower()))
        out = []
        for v in order:
            name = "Global" if v is None else (vrfs.get(v, {}).get("name") or groups[v][0]["vrf"])
            rd = "" if v is None else (vrfs.get(v, {}).get("rd") or "")
            out.append({"k": "v", "id": ids(), "name": name, "rd": rd, "n": len(groups[v]),
                        "c": build_forest(groups[v], ids)})
        return out
    if mode.startswith("vrf:"):
        vid = int(mode[4:])
        sel = [p for p in prefixes if p["vrf_id"] == vid]
        if gc:
            sel += global_containers_for(sel, [p for p in prefixes if p["vrf_id"] is None])
        return build_forest(sel, ids)
    raise ValueError("ukjent modus")


# --------------------------------------------------------------------------- HTTP

def state_payload():
    cfg = load_config()
    with STORE.lock:
        counts = {}
        for p in STORE.prefixes:
            counts[p["vrf_id"]] = counts.get(p["vrf_id"], 0) + 1
        return {
            "configured": is_configured(cfg),
            "netbox_url": cfg.get("netbox_url", ""),
            "verify_tls": cfg.get("verify_tls", True),
            "loaded": STORE.loaded_at is not None,
            "loaded_at": STORE.loaded_at,
            "version": STORE.version,
            "token_version": token_version_of(cfg),
            "total": len(STORE.prefixes),
            "global_count": counts.get(None, 0),
            "vrfs": sorted([dict(v, count=counts.get(v["id"], 0)) for v in STORE.vrfs],
                           key=lambda v: v["name"].lower()),
            "error": STORE.error,
        }


class Handler(BaseHTTPRequestHandler):
    server_version = "nbprefix"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if not isinstance(body, bytes):
            body = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if u.path == "/":
                return self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
            if u.path == "/api/state":
                return self._send(200, state_payload())
            if u.path == "/api/tree":
                t0 = time.time()
                nodes = build_view(q.get("mode", ["all"])[0], q.get("fam", ["all"])[0],
                                   q.get("gc", ["0"])[0] == "1")
                return self._send(200, {"nodes": nodes, "ms": int((time.time() - t0) * 1000)})
            self._send(404, {"error": "ikke funnet"})
        except Exception as e:  # noqa
            self._send(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        # Enkel beskyttelse mot at andre nettsider poster til localhost
        origin = self.headers.get("Origin")
        if origin and not origin.startswith(("http://127.0.0.1", "http://localhost")):
            return self._send(403, {"error": "feil origin"})
        try:
            if u.path == "/api/load":
                cfg = load_config()
                if not is_configured(cfg):
                    return self._send(400, {"error": "Ikke konfigurert"})
                try:
                    STORE.load(cfg)
                except NetBoxError as e:
                    STORE.error = str(e)
                    return self._send(502, {"error": str(e)})
                return self._send(200, state_payload())
            if u.path == "/api/config":
                b = self._body()
                cfg = load_config()
                new = dict(cfg)
                new["netbox_url"] = (b.get("netbox_url") or "").strip().rstrip("/")
                tok = (b.get("token") or "").strip()
                key = (b.get("token_key") or "").strip()
                if tok or key:
                    try:   # bare nøkkel oppgitt -> kombiner med lagret token
                        new["token"], _ = normalize_token(tok or cfg.get("token", ""), key)
                    except NetBoxError as e:
                        return self._send(400, {"error": str(e)})
                    new.pop("token_key", None)
                new["verify_tls"] = bool(b.get("verify_tls", True))
                if not is_configured(new):
                    return self._send(400, {"error": "Server og token må fylles ut"})
                try:
                    NetBox(new).get("/api/ipam/prefixes/", {"limit": 1})
                except NetBoxError as e:
                    return self._send(502, {"error": str(e)})
                save_config(new)
                try:
                    STORE.load(new)
                except NetBoxError as e:
                    STORE.error = str(e)
                    return self._send(502, {"error": str(e)})
                return self._send(200, state_payload())
            self._send(404, {"error": "ikke funnet"})
        except Exception as e:  # noqa
            self._send(500, {"error": f"{type(e).__name__}: {e}"})


def main():
    args = sys.argv[1:]
    cfg = load_config()
    port = int(cfg.get("port") or DEFAULT_PORT)
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    srv = None
    for p in range(port, port + 10):
        try:
            srv = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if not srv:
        sys.exit(f"Fant ingen ledig port fra {port}")
    url = f"http://127.0.0.1:{port}/"
    print(f"nbprefix kjører på {url}  (Ctrl+C for å stoppe)")
    print(f"Konfig: {CONFIG_PATH}")
    if "--no-browser" not in args:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# --------------------------------------------------------------------------- GUI

PAGE = r"""<!doctype html>
<html lang="no"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetBox prefikser</title>
<style>
:root{--bg:#f5f6f8;--panel:#fff;--fg:#1c2230;--muted:#6b7280;--line:#e2e5ea;--hover:#edf2fb;
 --accent:#2f6fde;--free:#0f7a45;--freebg:#eaf7ef;--hit:#fff4c2;--bar:#dde2e8;--barfill:#5b8def;--barhi:#d9822b;
 --mono:"Cascadia Mono",Consolas,ui-monospace,monospace}
@media (prefers-color-scheme:dark){:root{--bg:#13161b;--panel:#1a1e25;--fg:#e3e6eb;--muted:#98a1ad;--line:#2a3039;
 --hover:#212938;--accent:#6aa0ff;--free:#4fd08b;--freebg:#14261d;--hit:#3d3613;--bar:#2c333d;--barfill:#5b8def;--barhi:#e0954a}}
*{box-sizing:border-box}
body{margin:0;font:13px/1.35 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{position:sticky;top:0;z-index:5;background:var(--panel);border-bottom:1px solid var(--line);padding:8px 12px}
.bar1{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.bar1 h1{font-size:15px;margin:0 8px 0 0;font-weight:600}
select,input[type=text],input[type=password],button{font:inherit;color:inherit;background:var(--panel);
 border:1px solid var(--line);border-radius:5px;padding:4px 8px}
input[type=text]#q{width:270px}
button{cursor:pointer}button:hover{background:var(--hover)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
label.ck{display:flex;gap:4px;align-items:center;white-space:nowrap}
.spacer{flex:1}
.status{margin-top:6px;color:var(--muted);font-size:12px;display:flex;gap:14px;flex-wrap:wrap}
.status .err{color:#d33}
main{padding:0 0 40px}
table{width:100%;border-collapse:collapse;table-layout:fixed;background:var(--panel)}
thead th{position:sticky;top:var(--hh,74px);z-index:4;background:var(--panel);text-align:left;font-weight:600;
 color:var(--muted);font-size:12px;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:3px 8px;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;vertical-align:middle}
tr:hover td{background:var(--hover)}
.pfx{font-family:var(--mono);font-size:12.5px}
.tg{display:inline-block;width:16px;height:16px;line-height:14px;text-align:center;border:1px solid var(--muted);
 border-radius:3px;font-family:var(--mono);font-size:12px;cursor:pointer;margin-right:6px;user-select:none;color:var(--muted)}
.tg:hover{border-color:var(--accent);color:var(--accent)}
.tg.none{border-color:transparent;cursor:default}
.d0 .pfx b{font-weight:700}
tr.free td{background:var(--freebg)}
tr.free:hover td{background:var(--hover)}
tr.hit td,tr.free.hit td{background:var(--hit)}
tr.free .pfx,tr.free .txt{color:var(--free)}
tr.vrfh td{background:var(--bg);font-weight:600;border-top:2px solid var(--line)}
.badge{display:inline-block;padding:0 6px;border-radius:9px;font-size:11px;line-height:17px;border:1px solid var(--line);color:var(--muted)}
.st-active{color:#1d6fd8;border-color:#9cc0f0}
.st-container{color:var(--muted)}
.st-reserved{color:#b26b00;border-color:#e6c27a}
.st-deprecated{color:#c0392b;border-color:#e8a59d}
.st-free{color:var(--free);border-color:var(--free);font-weight:600}
.cov{display:flex;align-items:center;gap:6px}
.cov .b{flex:1;height:7px;background:var(--bar);border-radius:4px;overflow:hidden;min-width:40px}
.cov .b i{display:block;height:100%;background:var(--barfill)}
.cov .b i.hi{background:var(--barhi)}
.cov span{font-size:11.5px;color:var(--muted);width:38px;text-align:right}
.muted{color:var(--muted)}
a.lnk{color:var(--muted);text-decoration:none}a.lnk:hover{color:var(--accent)}
.empty{padding:40px;text-align:center;color:var(--muted)}
dialog{border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--fg);padding:18px;width:460px;max-width:95vw}
dialog::backdrop{background:rgba(0,0,0,.35)}
dialog label{display:block;margin:10px 0 3px;font-size:12px;color:var(--muted)}
dialog input[type=text],dialog input[type=password]{width:100%}
dialog .row{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
#cfgerr{color:#d33;margin-top:8px;font-size:12px;white-space:pre-wrap}
</style></head><body>
<header id="hdr">
 <div class="bar1">
  <h1>NetBox prefikser</h1>
  <select id="mode" title="VRF-visning"></select>
  <select id="fam" title="Adressefamilie"><option value="all">IPv4 + IPv6</option><option value="4">IPv4</option><option value="6">IPv6</option></select>
  <label class="ck" id="gcw" title="Ta med globale container-prefikser som omslutter VRF-ens prefikser"><input type="checkbox" id="gc"> globale containere</label>
  <label class="ck"><input type="checkbox" id="showfree" checked> vis ledig</label>
  <input type="text" id="q" placeholder="Søk: tekst, IP eller prefiks (Esc tømmer)">
  <button id="collapse">Lukk alle</button>
  <button id="expand1" title="Åpne ett nivå til under det som er åpent">Åpne +1 nivå</button>
  <span class="spacer"></span>
  <button id="reload">Oppdater fra NetBox</button>
  <button id="settings">Innstillinger</button>
 </div>
 <div class="status" id="status"></div>
</header>
<main>
 <table><colgroup>
  <col style="width:380px"><col style="width:88px"><col style="min-width:200px"><col style="width:110px"><col style="width:120px">
  <col style="width:140px"><col style="width:100px"><col style="width:110px"><col style="width:120px"><col style="width:64px"><col style="width:28px">
 </colgroup>
 <thead><tr><th>Prefiks</th><th>Status</th><th>Beskrivelse</th><th>VRF</th><th>Tenant</th><th>Scope</th><th>Rolle</th><th>VLAN</th><th>Dekning</th><th title="Direkte / totalt antall underprefikser">Under</th><th></th></tr></thead>
 <tbody id="tb"></tbody></table>
 <div class="empty" id="empty" hidden></div>
</main>

<dialog id="cfg">
 <h3 style="margin:0 0 4px">Tilkobling til NetBox</h3>
 <div class="muted" style="font-size:12px">Lagres lokalt i nbprefix.json. Verktøyet gjør kun GET-kall.</div>
 <label>NetBox-server (URL)</label><input type="text" id="c_url" placeholder="https://netbox.example.no">
 <label>API-token</label><input type="password" id="c_tok" autocomplete="off">
 <label>Nøkkel (Key) – bare for v2-token når nøkkel og token er oppgitt hver for seg</label><input type="text" id="c_key" autocomplete="off" placeholder="f.eks. 4F9DAouzURLb">
 <div class="muted" style="font-size:12px;margin-top:6px">NetBox 4.5+ lager v2-token og viser nøkkel og token separat: lim inn begge, eller hele verdien
  <code>nbt_&lt;nøkkel&gt;.&lt;token&gt;</code> i token-feltet. Eldre NetBox bruker v1-token (40 tegn).</div>
 <label class="ck" style="margin-top:10px;color:inherit"><input type="checkbox" id="c_tls" checked> Verifiser TLS-sertifikat</label>
 <div id="cfgerr"></div>
 <div class="row"><button id="c_cancel">Avbryt</button><button class="primary" id="c_save">Lagre og test</button></div>
</dialog>

<script>
const $=id=>document.getElementById(id);
let state=null, tree=[], byId=new Map(), parentOf=new Map();
let expanded=new Set(), savedExpanded=null, pathSet=null, hitSet=null;
const ls={get(k,d){try{const v=localStorage.getItem('nbp.'+k);return v===null?d:JSON.parse(v)}catch(e){return d}},
          set(k,v){try{localStorage.setItem('nbp.'+k,JSON.stringify(v))}catch(e){}}};

async function api(path,opts){
  const r=await fetch(path,opts);
  let j; try{j=await r.json()}catch(e){j={error:r.statusText}}
  if(!r.ok) throw new Error(j.error||r.statusText);
  return j;
}
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));

function setStatus(extra){
  const s=state; if(!s) return;
  const parts=[];
  if(s.netbox_url) parts.push(esc(s.netbox_url.replace(/^https?:\/\//,'')));
  if(s.version) parts.push('NetBox '+esc(s.version));
  if(s.token_version) parts.push('token v'+s.token_version);
  if(s.loaded){
    parts.push(s.total.toLocaleString('nb-NO')+' prefikser');
    parts.push(s.vrfs.length+' VRF');
    parts.push('hentet '+new Date(s.loaded_at*1000).toLocaleTimeString('nb-NO'));
  }
  if(extra) parts.push(extra);
  if(s.error) parts.push('<span class="err">'+esc(s.error)+'</span>');
  $('status').innerHTML=parts.map(p=>'<span>'+p+'</span>').join('');
  document.documentElement.style.setProperty('--hh',$('hdr').offsetHeight+'px');
}

function fillModes(){
  const m=$('mode'), cur=ls.get('mode','all');
  const o=[['all','Alle VRF (samlet tre)'],['grouped','Alle VRF (gruppert per VRF)'],
           ['global','Global (uten VRF) – '+state.global_count]];
  for(const v of state.vrfs) o.push(['vrf:'+v.id,'VRF '+v.name+(v.rd?' ('+v.rd+')':'')+' – '+v.count]);
  m.innerHTML=o.map(([v,t])=>'<option value="'+esc(v)+'">'+esc(t)+'</option>').join('');
  m.value=o.some(x=>x[0]===cur)?cur:'all';
  syncGc();
}
function syncGc(){ const v=$('mode').value.startsWith('vrf:'); $('gc').disabled=!v; $('gcw').style.opacity=v?1:.45; }

function indexTree(nodes,parent){
  for(const n of nodes){
    byId.set(n.id,n); parentOf.set(n.id,parent);
    if(n.s!==undefined){ n.sB=BigInt('0x'+n.s); n.eB=BigInt('0x'+n.e); }
    if(n.k==='p') n.hay=[n.prefix,n.description,n.tenant,n.vrf,n.rd,n.scope,n.role,n.vlan,n.status_label].join('\u0001').toLowerCase();
    if(n.c) indexTree(n.c,n.id);
  }
}

async function loadTree(){
  const mode=$('mode').value, fam=$('fam').value, gc=$('gc').checked?'1':'0';
  ls.set('mode',mode); ls.set('fam',fam); ls.set('gc',gc==='1');
  setStatus('bygger tre…');
  const t0=performance.now();
  const j=await api('/api/tree?mode='+encodeURIComponent(mode)+'&fam='+fam+'&gc='+gc);
  tree=j.nodes; byId=new Map(); parentOf=new Map(); indexTree(tree,null);
  expanded=new Set(); savedExpanded=null;
  if(mode==='grouped') for(const n of tree) expanded.add(n.id);
  applySearch();
  setStatus('tre '+Math.round(performance.now()-t0)+' ms');
}

// ---------- søk
function parseIP(q){
  q=q.trim(); if(!q) return null;
  const [a,l,...rest]=q.split('/'); if(rest.length) return null;
  let fam,v,bits;
  if(/^\d{1,3}(\.\d{1,3}){3}$/.test(a)){
    const o=a.split('.').map(Number); if(o.some(x=>x>255)) return null;
    v=0n; for(const x of o) v=(v<<8n)|BigInt(x); fam=4; bits=32;
  } else if(a.includes(':') && /^[0-9a-f:]+$/i.test(a)){
    const d=a.split('::'); if(d.length>2) return null;
    const h=d[0]?d[0].split(':'):[], t=(d.length===2&&d[1])?d[1].split(':'):[];
    const fill=d.length===2?8-h.length-t.length:0; if(fill<0) return null;
    const p=[...h,...Array(fill).fill('0'),...t];
    if(p.length!==8||p.some(x=>!/^[0-9a-f]{1,4}$/i.test(x))) return null;
    v=0n; for(const x of p) v=(v<<16n)|BigInt(parseInt(x,16)); fam=6; bits=128;
  } else return null;
  const len=l===undefined?bits:Number(l); if(!Number.isInteger(len)||len<0||len>bits) return null;
  const host=(1n<<BigInt(bits-len))-1n; const s=v&~host;
  return {fam,s,e:s|host};
}
function ancestorsOf(id,set){ let p=parentOf.get(id); while(p!=null){ set.add(p); p=parentOf.get(p);} }

function applySearch(){
  const q=$('q').value.trim();
  if(!q){
    pathSet=hitSet=null;
    if(savedExpanded){ expanded=savedExpanded; savedExpanded=null; }
    return render();
  }
  if(!savedExpanded) savedExpanded=new Set(expanded);
  const hits=[]; const ip=parseIP(q);
  if(ip){
    const cont=[];
    for(const n of byId.values()) if(n.sB!==undefined&&n.fam===ip.fam&&n.sB<=ip.s&&n.eB>=ip.e) cont.push(n);
    if(cont.length){
      const cs=new Set(cont.map(n=>n.id));
      for(const n of cont) if(!(n.c||[]).some(c=>cs.has(c.id))) hits.push(n);
    } else {
      for(const n of byId.values()){
        if(n.sB===undefined||n.fam!==ip.fam||n.k==='f') continue;
        if(n.sB>=ip.s&&n.eB<=ip.e){
          const p=byId.get(parentOf.get(n.id));
          if(!p||p.sB===undefined||!(p.sB>=ip.s&&p.eB<=ip.e)) hits.push(n);
        }
      }
    }
  } else {
    const ql=q.toLowerCase();
    for(const n of byId.values()) if(n.hay&&n.hay.includes(ql)) hits.push(n);
  }
  hitSet=new Set(hits.map(n=>n.id)); pathSet=new Set(hitSet);
  const anc=new Set(); for(const id of hitSet) ancestorsOf(id,anc);
  for(const a of anc) pathSet.add(a);
  expanded=anc;
  render(hits.length+' treff');
}

// ---------- render
const showFree=()=>$('showfree').checked;
const isFreeK=k=>k==='f'||k==='g';
function visKids(n){ if(!n.c) return []; return showFree()?n.c:n.c.filter(c=>!isFreeK(c.k)); }

function rows(){
  const out=[];
  const walk=(nodes,d,inside)=>{
    for(const n of nodes){
      if(!showFree()&&isFreeK(n.k)&&!(hitSet&&hitSet.has(n.id))) continue;
      if(pathSet&&!inside&&!pathSet.has(n.id)) continue;
      out.push([n,d]);
      if(n.c&&expanded.has(n.id)) walk(n.c,d+1,inside||(hitSet&&hitSet.has(n.id)));
    }
  };
  walk(tree,0,false); return out;
}

function covCell(c){
  if(c==null) return '';
  const pct=c*100, w=Math.max(pct,pct>0?1:0);
  const t=pct===0?'0 %':pct<1?'<1 %':pct>99&&pct<100?'>99 %':Math.round(pct)+' %';
  return '<div class="cov"><div class="b"><i'+(pct>=90?' class="hi"':'')+' style="width:'+w.toFixed(1)+'%"></i></div><span>'+t+'</span></div>';
}

function rowHtml(n,d){
  const kids=visKids(n).length;
  const tg=kids?'<span class="tg" data-id="'+n.id+'">'+(expanded.has(n.id)?'−':'+')+'</span>':'<span class="tg none"></span>';
  const pad='padding-left:'+(8+d*18)+'px';
  const hit=hitSet&&hitSet.has(n.id)?' hit':'';
  if(n.k==='v'){
    return '<tr class="vrfh'+hit+'"><td style="'+pad+'">'+tg+esc(n.name)+(n.rd?' <span class="muted">'+esc(n.rd)+'</span>':'')+
      '</td><td colspan="8" class="muted">'+n.n+' prefikser</td><td></td><td></td></tr>';
  }
  if(n.k==='f'||n.k==='g'){
    const lbl=n.k==='f'?esc(n.prefix):esc(n.label);
    return '<tr class="free'+hit+'"><td style="'+pad+'" class="pfx" title="'+lbl+'">'+tg+lbl+'</td><td><span class="badge st-free">LEDIG</span></td>'+
      '<td class="txt" colspan="4">'+esc(n.desc)+'</td><td colspan="5"></td></tr>';
  }
  const scope=n.scope?(n.scope_type?'<span class="muted">'+esc(n.scope_type)+':</span> ':'')+esc(n.scope):'';
  const under=n.nc?(n.nc+(n.nd>n.nc?' / '+n.nd:'')):'';
  return '<tr class="d'+d+hit+'"><td style="'+pad+'" class="pfx" title="'+esc(n.prefix)+'">'+tg+(d===0?'<b>'+esc(n.prefix)+'</b>':esc(n.prefix))+
    (n.is_pool?' <span class="badge" title="is_pool">pool</span>':'')+'</td>'+
    '<td><span class="badge st-'+esc(n.status)+'">'+esc(n.status_label)+'</span></td>'+
    '<td title="'+esc(n.description)+'">'+esc(n.description)+'</td>'+
    '<td title="'+esc(n.rd)+'">'+(n.vrf?esc(n.vrf):'<span class="muted">Global</span>')+'</td>'+
    '<td title="'+esc(n.tenant)+'">'+esc(n.tenant)+'</td>'+
    '<td title="'+esc((n.scope_type?n.scope_type+': ':'')+n.scope)+'">'+scope+'</td>'+
    '<td>'+esc(n.role)+'</td><td title="'+esc(n.vlan)+'">'+esc(n.vlan)+'</td>'+
    '<td>'+covCell(n.cov)+'</td><td class="muted">'+under+'</td>'+
    '<td><a class="lnk" href="'+esc(n.url)+'" target="_blank" rel="noopener" title="Åpne i NetBox">↗</a></td></tr>';
}

function render(extra){
  const r=rows();
  $('tb').innerHTML=r.map(([n,d])=>rowHtml(n,d)).join('');
  const em=$('empty');
  if(!state||!state.configured){ em.hidden=false; em.textContent='Ikke konfigurert – trykk «Innstillinger».'; }
  else if(!r.length){ em.hidden=false; em.textContent=pathSet?'Ingen treff.':'Ingen prefikser i dette utvalget.'; }
  else em.hidden=true;
  setStatus((extra?extra+' · ':'')+r.length.toLocaleString('nb-NO')+' rader vist');
}

$('tb').addEventListener('click',e=>{
  const t=e.target.closest('.tg'); if(!t||!t.dataset.id) return;
  const id=Number(t.dataset.id);
  expanded.has(id)?expanded.delete(id):expanded.add(id);
  render();
});
$('mode').onchange=()=>{syncGc();loadTree().catch(err)};
$('fam').onchange=()=>loadTree().catch(err);
$('gc').onchange=()=>loadTree().catch(err);
$('showfree').onchange=()=>{ls.set('showfree',$('showfree').checked);render()};
let qt; $('q').addEventListener('input',()=>{clearTimeout(qt);qt=setTimeout(applySearch,180)});
$('q').addEventListener('keydown',e=>{if(e.key==='Escape'){$('q').value='';applySearch()}});
$('collapse').onclick=()=>{ $('q').value=''; pathSet=hitSet=null; savedExpanded=null;
  expanded=new Set(); if($('mode').value==='grouped') for(const n of tree) expanded.add(n.id); render(); };
$('expand1').onclick=()=>{
  for(const [n] of rows()) if(n.c&&!expanded.has(n.id)&&n.k!=='g'&&visKids(n).length) expanded.add(n.id);
  render();
};
$('reload').onclick=async()=>{
  try{ setStatus('henter fra NetBox…'); state=await api('/api/load',{method:'POST'}); fillModes(); await loadTree(); }
  catch(e){ err(e); }
};
function err(e){ if(state) state.error=e.message; setStatus(); }

// ---------- innstillinger
function openCfg(){
  $('c_url').value=state?.netbox_url||''; $('c_tok').value=''; $('c_key').value='';
  $('c_tok').placeholder=state?.configured?'(uendret – fyll inn for å bytte)':'v1: 40 tegn · v2: nbt_<nøkkel>.<token>';
  $('c_tls').checked=state?state.verify_tls!==false:true; $('cfgerr').textContent='';
  $('cfg').showModal();
}
$('settings').onclick=openCfg;
$('c_cancel').onclick=()=>$('cfg').close();
$('c_save').onclick=async()=>{
  $('cfgerr').textContent='Tester tilkobling og henter prefikser…';
  try{
    state=await api('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({netbox_url:$('c_url').value,token:$('c_tok').value,token_key:$('c_key').value,verify_tls:$('c_tls').checked})});
    $('cfg').close(); fillModes(); await loadTree();
  }catch(e){ $('cfgerr').textContent=e.message; }
};

// ---------- oppstart
(async()=>{
  $('fam').value=ls.get('fam','all'); $('gc').checked=ls.get('gc',false); $('showfree').checked=ls.get('showfree',true);
  try{
    state=await api('/api/state');
    if(!state.configured){ render(); openCfg(); return; }
    if(!state.loaded){ setStatus('henter fra NetBox…'); state=await api('/api/load',{method:'POST'}); }
    fillModes(); await loadTree();
  }catch(e){ err(e); render(); }
})();
window.addEventListener('resize',()=>document.documentElement.style.setProperty('--hh',$('hdr').offsetHeight+'px'));
</script>
</body></html>
"""

if __name__ == "__main__":
    main()
