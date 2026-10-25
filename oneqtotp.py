"""Time-based one-time passwords (RFC 6238, HMAC-SHA1, 6 digits, 30 s) for the admin page: the codes of any authenticator app
(Google Authenticator, Microsoft Authenticator, Aegis, FreeOTP, 1Password, ...) work.

The secret lives in a file of the service user (mode 600) together with the SHA-256 hashes of ten one-time recovery codes and the
last accepted time step, so that a code can never be used twice (a phished or shoulder-surfed code is useless after the owner used it,
and a code is not valid for a second login within its 90 s window). Educational project, not independently audited.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import tempfile
import threading
import time
from typing import Optional
from urllib.parse import quote

PERIOD = 30
DIGITS = 6
WINDOW = 1                                  # accept the previous and the next step: clocks differ by seconds
RECOVERY_CODES = 10


def new_secret() -> str:
    """160 random bits as base32 (the format authenticator apps take), without padding."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    mac = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    n = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(n).zfill(digits)


def totp_now(secret_b32: str, t: Optional[float] = None, digits: int = DIGITS) -> str:
    return hotp(secret_b32, int((time.time() if t is None else t) // PERIOD), digits)


def match(secret_b32: str, code: str, t: Optional[float] = None, last: int = -1) -> Optional[int]:
    """The time step `code` belongs to (within the window around now), or None. Steps <= `last` are refused (replay)."""
    code = "".join(c for c in code if c.isdigit())
    if len(code) != DIGITS:
        return None
    step = int((time.time() if t is None else t) // PERIOD)
    found = None
    for c in range(step - WINDOW, step + WINDOW + 1):          # every candidate is compared: no early exit that leaks timing
        if hmac.compare_digest(hotp(secret_b32, c), code) and c > last:
            found = c
    return found


def otpauth_uri(secret_b32: str, account: str, issuer: str) -> str:
    return (f"otpauth://totp/{quote(issuer + ':' + account)}?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")


def _hash(code: str) -> str:
    return hashlib.sha256(b"oneq-recovery" + code.encode()).hexdigest()


def normalize_recovery(code: str) -> str:
    return "".join(c for c in code.lower() if c.isalnum())


class TotpStore:
    """The second factor of the admin page: TOTP secret, recovery codes, replay protection. Thread safe."""

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        if os.name == "posix" and os.stat(path).st_mode & 0o077:
            raise SystemExit(f"{path}: the second-factor file must be mode 600")
        self.secret = d["secret"]
        self.recovery = list(d.get("recovery", []))
        self.last = int(d.get("last", -1))
        _key(self.secret)                                       # raises on a damaged secret

    @staticmethod
    def create(path: str, force: bool = False):
        """Writes a new file (mode 600) and returns (secret, plain recovery codes). Refuses to overwrite unless `force`."""
        secret = new_secret()
        codes = [secrets.token_hex(5) for _ in range(RECOVERY_CODES)]
        shown = [c[:5] + "-" + c[5:] for c in codes]
        data = {"secret": secret, "recovery": [_hash(c) for c in codes], "last": -1}
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return secret, shown

    def _save(self):
        """Atomic (temporary file + rename) when the directory is writable. The file normally lives in /etc/oneq, which the
        service user cannot write to: then the file itself (owned by that user) is rewritten in place and flushed. If even that
        is impossible OSError is raised and the code that needed the state change is refused."""
        data = json.dumps({"secret": self.secret, "recovery": self.recovery, "last": self.last})
        d = os.path.dirname(os.path.abspath(self.path))
        try:
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".totp.")
        except PermissionError:
            fd = os.open(self.path, os.O_WRONLY | os.O_TRUNC)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            return
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def check(self, code: str, t: Optional[float] = None) -> bool:
        """True and consumed: a valid authenticator code of a not yet used time step, or an unused recovery code.
        If the state cannot be saved the code is refused (a code that could be replayed must not count)."""
        with self.lock:
            step = match(self.secret, code, t, self.last)
            if step is not None:
                old = self.last
                self.last = step
                try:
                    self._save()
                except OSError:
                    self.last = old
                    return False
                return True
            rc = normalize_recovery(code)
            if len(rc) == 10:
                h = _hash(rc)
                hit = [x for x in self.recovery if hmac.compare_digest(x, h)]
                if hit:
                    self.recovery.remove(hit[0])
                    try:
                        self._save()
                    except OSError:
                        self.recovery.append(hit[0])
                        return False
                    return True
            return False

    def ensure_writable(self):
        """Called at start: the state (last used step, spent recovery codes) must be savable, otherwise every login would be
        refused. Under systemd the service sees /etc read-only (ProtectSystem=strict): keep this file in /var/lib/oneq/relay."""
        try:
            with self.lock:
                self._save()
        except OSError as e:
            raise SystemExit(f"{self.path}: the service cannot write the second-factor file ({e.strerror}); it must be in a directory the "
                             f"service may write to, e.g. /var/lib/oneq/relay/admin.totp (under systemd /etc is read-only for it)")

    def uri(self, account: str, issuer: str) -> str:
        return otpauth_uri(self.secret, account, issuer)
