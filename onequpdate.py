"""Update check for oneq components (relay, Python node): is a newer release on GitHub, and download it with SHA-256 verification.

Nothing is ever installed or executed: the file is only downloaded, verified and left in a directory for the operator.
Source: GitHub Releases API of ad-go/oneq (override: `update_url`, or $ONEQ_UPDATE_URL; the override may be plain
http://127.0.0.1:PORT/... for tests, nothing else may be plain http). Result objects have the shape of the shared specification:

  check():    {"current","latest","update_available","status": newer|current|unknown|error,"url","notes","asset": {name,size,download_url}|None,
               "checked_at","error"}
  download(): {"ok": True, "path","name","size","sha256"}  or  {"ok": False, "error"}

Network policy: https only (loopback override aside), at most 5 redirects, every hop https on an allowed GitHub host, timeouts 10 s connect /
30 s per read, API response <= 1 MB, SHA256SUMS <= 64 KB, download <= 200 MB. No cookies, no identifiers.

TLS note: the oneq processes load pq_openssl.cnf (pqtls), which restricts every TLS context to the group X25519MLKEM768. GitHub is an
ordinary classical server, so this module's context overrides the group list for its own connections only (see _tls_context).
"""
try:                      # keep the order "pqtls before ssl" when this module is the first to be imported in a process
    import pqtls  # noqa: F401
except ImportError:       # pragma: no cover
    pass

import asyncio
import hashlib
import http.client
import ipaddress
import os
import random
import re
import ssl
import threading
import time
import json
from urllib.parse import urljoin, urlsplit

DEFAULT_URL = "https://api.github.com/repos/ad-go/oneq/releases/latest"
ALLOWED_HOSTS = ("api.github.com", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com")
MAX_REDIRECTS = 5
CONNECT_TIMEOUT, READ_TIMEOUT = 10, 30
MAX_API, MAX_SUMS, MAX_DOWNLOAD = 1 << 20, 64 << 10, 200 << 20
CACHE_TTL, MANUAL_MIN_INTERVAL, AUTO_INTERVAL = 6 * 3600, 60, 24 * 3600
ASSET_RE = re.compile(r"^[A-Za-z0-9._-]+$")
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
KINDS = ("relay", "node", "windows", "macos-arm64", "macos-x64", "android", "chromium", "firefox")


class UpdateError(Exception):
    pass


# ------------------------------------------------------------------ versions
def parse_version(s):
    """'v0.0.2' -> (0, 0, 2); suffixes after '-' or '+' are ignored; None when it does not parse."""
    if not isinstance(s, str):
        return None
    s = s.strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    s = re.split(r"[-+]", s, maxsplit=1)[0]
    parts = s.split(".")
    if not 1 <= len(parts) <= 6 or not all(p.isascii() and p.isdigit() and len(p) <= 9 for p in parts):
        return None
    return tuple(int(p) for p in parts)


def compare(local, remote):
    """'newer' if remote > local, 'current' otherwise, 'unknown' if either side does not parse."""
    a, b = parse_version(local), parse_version(remote)
    if a is None or b is None:
        return "unknown"
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return "newer" if b > a else "current"


def version_text(tag):
    t = parse_version(tag)
    return ".".join(map(str, t)) if t else None


# ------------------------------------------------------------------ release JSON, SHA256SUMS
def asset_name_for(kind, version, server_pkg=False):
    if kind == "relay":
        return f"oneq-server_{version}_all.deb" if server_pkg else f"oneqrelay_{version}_amd64.deb"
    return {"node": f"oneqnode_{version}_amd64.deb", "windows": "oneq-node-windows-x64.msi",
            "macos-arm64": "oneq-node-macos-arm64.tar.gz", "macos-x64": "oneq-node-macos-x64.tar.gz",
            "android": "oneq-android.apk", "chromium": f"oneq-mesh-chromium-{version}.zip",
            "firefox": f"oneq-mesh-firefox-{version}.zip"}.get(kind)


def server_package_installed():
    return os.path.exists("/var/lib/dpkg/info/oneq-server.list")


def _assets(rel):
    out = {}
    for a in rel.get("assets") or []:
        if isinstance(a, dict) and isinstance(a.get("name"), str) and ASSET_RE.match(a["name"]) and isinstance(a.get("browser_download_url"), str):
            size = a.get("size")
            out[a["name"]] = {"name": a["name"], "size": size if isinstance(size, int) and not isinstance(size, bool) else 0,
                              "download_url": a["browser_download_url"]}
    return out


def select_asset(rel, kind, version, server_pkg=None):
    """The asset of release `rel` (dict from the API) this kind of component offers, or None."""
    assets = _assets(rel)
    if kind == "relay":
        if server_pkg is None:
            server_pkg = server_package_installed()
        if server_pkg:
            a = assets.get(asset_name_for(kind, version, True))
            if a:
                return a
        return assets.get(asset_name_for(kind, version, False))
    n = asset_name_for(kind, version)
    return assets.get(n) if n else None


def parse_sums(text):
    """{basename: lowercase hex}. Accepts '<hex> *name', '<hex>  name', names with './' or a directory prefix."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", line)
        if m:
            name = m.group(2).replace("\\", "/").rsplit("/", 1)[-1]
            if name:
                out[name] = m.group(1).lower()
    return out


def clean_notes(body):
    t = re.sub(r"<[^>]{0,200}>", "", body if isinstance(body, str) else "")
    t = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", t).strip()
    return t[:600]


# ------------------------------------------------------------------ network
def _is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_url(url=None):
    """Explicit argument, else $ONEQ_UPDATE_URL, else GitHub. Plain http is accepted for loopback only."""
    u = url or os.environ.get("ONEQ_UPDATE_URL") or DEFAULT_URL
    p = urlsplit(u)
    if p.scheme == "https" and p.hostname:
        return u
    if p.scheme == "http" and p.hostname and _is_loopback(p.hostname):
        return u
    raise UpdateError("update URL must be https (plain http only for loopback)")


def _tls_context():
    """Classical TLS client context for GitHub, verified against the system CA store.

    pqtls sets OPENSSL_CONF to a file that limits the key-exchange groups to X25519MLKEM768, which an ordinary web server may not offer.
    SSL_CTX_set_tmp_ecdh (ctx.set_ecdh_curve) replaces the group list of the context, so the context offers X25519 and its own
    settings do not touch any other connection of the process (the tunnel and relay contexts keep the PQ-only list)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, ssl.SSLError):
        pass
    if os.environ.get("OPENSSL_CONF", "").endswith("pq_openssl.cnf"):
        ctx.set_ecdh_curve("X25519")
    return ctx


class Fetcher:
    """GET with redirect policy and size limits. `origin_url` is the configured update URL: its host is trusted too."""

    def __init__(self, origin_url, cafile=None):
        p = urlsplit(origin_url)
        self.origin = (p.scheme, p.hostname, p.port)
        self.extra_host = p.hostname
        self.cafile = cafile
        self._ctx = None

    def allowed(self, url):
        p = urlsplit(url)
        host = (p.hostname or "").lower()
        if p.scheme == "https":
            if p.username or p.password:
                return False
            return host in ALLOWED_HOSTS or host.endswith(".githubusercontent.com") or host == (self.extra_host or "").lower()
        if p.scheme == "http":      # loopback override: the configured origin only
            return _is_loopback(host) and (p.scheme, p.hostname, p.port) == self.origin
        return False

    def _context(self):
        if self._ctx is None:
            self._ctx = _tls_context()
            if self.cafile:
                self._ctx.load_verify_locations(self.cafile)
        return self._ctx

    def open(self, url, accept):
        """Returns (connection, response) of the final hop, status 200. Caller reads and closes."""
        for hop in range(MAX_REDIRECTS + 1):
            if not self.allowed(url):
                raise UpdateError("refused: host or scheme not allowed")
            p = urlsplit(url)
            port = p.port or (443 if p.scheme == "https" else 80)
            if p.scheme == "https":
                conn = http.client.HTTPSConnection(p.hostname, port, timeout=CONNECT_TIMEOUT, context=self._context())
            else:
                conn = http.client.HTTPConnection(p.hostname, port, timeout=CONNECT_TIMEOUT)
            try:
                conn.connect()
                conn.sock.settimeout(READ_TIMEOUT)
                path = (p.path or "/") + ("?" + p.query if p.query else "")
            except (OSError, ssl.SSLError, http.client.HTTPException) as e:
                conn.close()
                raise UpdateError(f"cannot connect: {_short(e)}")
            try:
                conn.request("GET", path, headers={"User-Agent": f"oneq/{USER_AGENT_VERSION}", "Accept": accept, "Accept-Encoding": "identity"})
                r = conn.getresponse()
            except (OSError, ssl.SSLError, http.client.HTTPException) as e:
                conn.close()
                raise UpdateError(f"request failed: {_short(e)}")
            if r.status in (301, 302, 303, 307, 308):
                loc = r.getheader("Location")
                conn.close()
                if not loc:
                    raise UpdateError("redirect without location")
                url = urljoin(url, loc)
                continue
            if r.status != 200:
                conn.close()
                raise UpdateError(f"HTTP {r.status}" + (" (no release published yet)" if r.status == 404 else ""))
            return conn, r
        raise UpdateError("too many redirects")

    def read(self, url, limit, accept="application/vnd.github+json"):
        conn, r = self.open(url, accept)
        try:
            cl = r.getheader("Content-Length")
            if cl and cl.isdigit() and int(cl) > limit:
                raise UpdateError("response too large")
            data = r.read(limit + 1)
            if len(data) > limit:
                raise UpdateError("response too large")
            return data
        except (OSError, http.client.HTTPException) as e:
            raise UpdateError(f"read failed: {_short(e)}")
        finally:
            conn.close()


USER_AGENT_VERSION = "0.0.1"


def _short(e):
    return (str(e) or type(e).__name__)[:120]


def set_user_agent_version(v):
    global USER_AGENT_VERSION
    USER_AGENT_VERSION = str(v)[:20]


def _release(fetcher, url):
    try:
        rel = json.loads(fetcher.read(url, MAX_API).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise UpdateError("bad release JSON")
    if not isinstance(rel, dict):
        raise UpdateError("bad release JSON")
    return rel


# ------------------------------------------------------------------ check / download
def check(current, kind, url=None, cafile=None, server_pkg=None):
    """Blocking. Never raises: failures are reported in the result (status "error")."""
    res = {"current": str(current), "latest": None, "update_available": False, "status": "error", "url": None, "notes": "",
           "asset": None, "checked_at": int(time.time()), "error": None}
    try:
        if kind not in KINDS:
            raise UpdateError("unknown component")
        u = resolve_url(url)
        rel = _release(Fetcher(u, cafile), u)
        if rel.get("draft") is True or rel.get("prerelease") is True:
            res.update(status="current", latest=str(current))
            return res
        latest = version_text(rel.get("tag_name"))
        if latest is None:
            res.update(status="unknown", error="release tag is not a version")
            return res
        res["latest"] = latest
        hu = rel.get("html_url")
        res["url"] = hu if isinstance(hu, str) and hu.startswith("https://") else None
        res["notes"] = clean_notes(rel.get("body"))
        st = compare(current, latest)
        res["status"] = st
        if st == "newer":
            res["asset"] = select_asset(rel, kind, latest, server_pkg)
            res["update_available"] = True
            if res["asset"] is None:
                res["error"] = "release has no file for this component"
    except UpdateError as e:
        res["error"] = str(e)
    except Exception as e:                         # never crash the caller
        res["error"] = f"{type(e).__name__}: {_short(e)}"
    return res


_dl_lock = threading.Lock()


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def download(result, directory, url=None, cafile=None):
    """Blocking. Download result["asset"] into `directory`, verified against the SHA256SUMS of the same release. Never raises."""
    if not _dl_lock.acquire(blocking=False):
        return {"ok": False, "error": "another download is in progress"}
    part = None
    try:
        asset = (result or {}).get("asset")
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            return {"ok": False, "error": "no file to download"}
        name = asset["name"]
        if not ASSET_RE.match(name) or name in (".", "..") or name.startswith("."):
            return {"ok": False, "error": "bad file name"}
        u = resolve_url(url)
        fetcher = Fetcher(u, cafile)
        rel = _release(fetcher, u)       # the URLs come from the release itself, not from the caller
        assets = _assets(rel)
        if name not in assets or "SHA256SUMS" not in assets:
            return {"ok": False, "error": "SHA256SUMS or the file is missing in the release; nothing was kept" if name in assets
                    else "file not found in the release"}
        sums = parse_sums(fetcher.read(assets["SHA256SUMS"]["download_url"], MAX_SUMS, "application/octet-stream").decode("utf-8", "replace"))
        want = sums.get(name)
        if not want:
            return {"ok": False, "error": "no SHA-256 entry for this file in SHA256SUMS; nothing was kept"}
        os.makedirs(directory, mode=0o755, exist_ok=True)
        final = os.path.join(directory, name)
        if os.path.isfile(final) and not os.path.islink(final) and _sha256_file(final) == want:
            return {"ok": True, "path": final, "name": name, "size": os.path.getsize(final), "sha256": want}
        part = final + ".part"
        try:
            os.unlink(part)
        except FileNotFoundError:
            pass
        conn, r = fetcher.open(assets[name]["download_url"], "application/octet-stream")
        h, n = hashlib.sha256(), 0
        try:
            cl = r.getheader("Content-Length")
            if cl and cl.isdigit() and int(cl) > MAX_DOWNLOAD:
                return {"ok": False, "error": "file too large"}
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
            fd = os.open(part, flags, 0o644)
            with os.fdopen(fd, "wb") as f:
                while True:
                    b = r.read(1 << 16)
                    if not b:
                        break
                    n += len(b)
                    if n > MAX_DOWNLOAD:
                        return {"ok": False, "error": "file too large"}
                    h.update(b)
                    f.write(b)
        finally:
            conn.close()
        if h.hexdigest() != want:
            return {"ok": False, "error": "SHA-256 does not match SHA256SUMS; the file was deleted"}
        os.replace(part, final)
        part = None
        return {"ok": True, "path": final, "name": name, "size": n, "sha256": want}
    except UpdateError as e:
        return {"ok": False, "error": str(e)}
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        return {"ok": False, "error": f"download failed: {_short(e)}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {_short(e)}"}
    finally:
        if part:
            try:
                os.unlink(part)
            except OSError:
                pass
        _dl_lock.release()


# ------------------------------------------------------------------ cache, scheduling, asyncio wrappers
class Checker:
    """Remembers the last result for 6 h; a manual check bypasses the cache but not more than once per 60 s."""

    def __init__(self, current, kind, url=None, cafile=None, enabled=True):
        self.current, self.kind, self.url, self.cafile, self.enabled = current, kind, url, cafile, enabled
        self.result = None
        self.fetched = 0.0
        self.last_manual = 0.0
        self.announced = None
        self._lock = threading.Lock()
        set_user_agent_version(current)

    def get(self, force=False):
        with self._lock:
            now = time.time()
            if self.result is not None:
                fresh = now - self.fetched < CACHE_TTL
                if not force and fresh:
                    return self.result
                if force and now - self.last_manual < MANUAL_MIN_INTERVAL:
                    return self.result
            if force:
                self.last_manual = now
            self.result = check(self.current, self.kind, self.url, self.cafile)
            self.fetched = now
            return self.result

    async def aget(self, force=False):
        return await asyncio.get_running_loop().run_in_executor(None, self.get, force)

    async def adownload(self, directory):
        res = self.result or await self.aget()
        return await asyncio.get_running_loop().run_in_executor(None, download, res, directory, self.url, self.cafile)

    async def loop(self, log, first_delay=None, interval=AUTO_INTERVAL):
        """Background task: first check after 30-120 s, then every 24 h, one log line per newly seen version. Never raises."""
        try:
            await asyncio.sleep(random.uniform(30, 120) if first_delay is None else first_delay)
            while True:
                try:
                    r = await self.aget(force=False)
                    if r.get("update_available") and self.announced != r.get("latest"):
                        self.announced = r.get("latest")
                        log.info("oneq %s is available (this is %s); download it from the admin page / `update-download`: %s",
                                 r["latest"], r["current"], r.get("url") or "")
                    elif r.get("error"):
                        log.debug("update check: %s", r["error"])
                except Exception as e:      # pragma: no cover
                    log.debug("update check failed: %s", e)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            raise
