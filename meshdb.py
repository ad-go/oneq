"""Replicated state for the federated oneqrelays: a small LWW store on SQLite, plus the
registry logic on top of it (communities, users with scrypt passwords, session tokens,
nodes, automatic IP/MAC allocation, ephemeral presence).

Replication model
  * Every record is (kind, key) -> JSON value with a hybrid-logical-clock timestamp `ts` and the
    `origin` oneqrelay that wrote it. The record with the greater (ts, origin) wins (last writer wins).
    Deletions are tombstones. Presence records carry an expiry (`exp`) and are dropped when expired.
  * Anti-entropy is a per-peer cursor over the *local* change counter `lseq` (bumped whenever a
    record is written or a remote record is applied). A peer asks "records with lseq > cursor";
    multi-hop and out-of-order delivery therefore cannot lose updates, and a wiped peer is detected
    through the store `epoch`.
Educational project, not independently audited.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import sqlite3
import threading
import time
from typing import Optional

KINDS = {"comm", "user", "node", "pres", "rel", "dlg", "route"}
EPHEMERAL = {"pres", "rel"}
# Routes (record kind "route", key "<comm>/<network>_<prefix>", e.g. "oneq/192.168.16.0_24"): an administrator tells the members that a network
# is reachable through a member node (the gateway: a node that forwards IP packets to that network, normally with NAT). Members that opted in
# (accept_routes) send packets for that network to the gateway's MAC address. Relays older than this record kind ignore it.
ROUTE_MIN_PREFIX, MAX_ROUTES_PER_COMM = 8, 64
# The same network may be announced through several gateways (redundancy): one record per (network, gateway), key "<comm>/<network>_<prefix>/<node id>"
# (older records have no gateway in the key). `prio` orders them (lower first); the members fail over to the next one that is alive.
ROUTE_MAX_GATEWAYS, ROUTE_DEFAULT_PRIO, ROUTE_MAX_PRIO = 4, 100, 1000
PRESENCE_TTL_MS = 90_000
# Delegated relay nodes (record kind "dlg", key "<comm>/<node id>"): an administrator lets a member node forward the (end-to-end encrypted)
# datagrams of other members. The node must have offered to ("offer" in its node record) and be reachable from outside.
RELAY_MIN_KBPS, RELAY_MAX_KBPS, RELAY_DEFAULT_KBPS = 100, 1_000_000, 20_000
RELAY_NAT_OK = ("open", "cone")
MAX_VAL = 8192
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
TOKEN_TTL = 3600
NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")


class RegistryError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- store

class Store:
    def __init__(self, path: str, origin: str, clock=time.time):
        if not NAME_RE.match(origin):
            raise ValueError("bad origin id")
        self.origin, self.clock = origin, clock
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=15)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS rec(kind TEXT, key TEXT, val TEXT, ts INTEGER, origin TEXT,
                exp INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0, lseq INTEGER,
                PRIMARY KEY(kind, key));
            CREATE INDEX IF NOT EXISTS rec_lseq ON rec(lseq);
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);""")
        self._x("INSERT OR IGNORE INTO meta VALUES('epoch', ?)", (secrets.token_hex(8),), many=False)

    # ---- every statement goes through here: one connection shared by the event loop and executor threads
    def _x(self, sql, args=(), one=False, many=True):
        with self.lock:
            cur = self.db.execute(sql, args)
            if one:
                return cur.fetchone()
            return cur.fetchall() if many else None

    # ---- meta helpers
    def _meta(self, k, default=None):
        r = self._x("SELECT v FROM meta WHERE k=?", (k,), one=True)
        return r[0] if r else default

    def _set_meta(self, k, v):
        self._x("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, str(v)), many=False)

    @property
    def epoch(self) -> str:
        return self._meta("epoch")

    def now_ms(self) -> int:
        return int(self.clock() * 1000)

    def _hlc(self) -> int:
        ts = max(self.now_ms(), int(self._meta("hlc", 0)) + 1)
        self._set_meta("hlc", ts)
        return ts

    def _next_lseq(self) -> int:
        n = int(self._meta("lseq", 0)) + 1
        self._set_meta("lseq", n)
        return n

    def max_lseq(self) -> int:
        return int(self._meta("lseq", 0))

    # ---- local writes
    def put(self, kind: str, key: str, val: dict, ttl_ms: int = 0, deleted: bool = False) -> dict:
        if kind not in KINDS:
            raise ValueError("bad kind")
        sval = json.dumps(val, sort_keys=True, separators=(",", ":"))
        if len(sval) > MAX_VAL:
            raise RegistryError("value too large", 413)
        with self.lock:
            ts = self._hlc()
            exp = self.now_ms() + ttl_ms if ttl_ms else 0
            self._x("INSERT OR REPLACE INTO rec VALUES(?,?,?,?,?,?,?,?)",
                    (kind, key, sval, ts, self.origin, exp, int(deleted), self._next_lseq()), many=False)
        return {"kind": kind, "key": key, "val": val, "ts": ts, "origin": self.origin, "exp": exp,
                "deleted": deleted}

    def delete(self, kind: str, key: str):
        return self.put(kind, key, {}, deleted=True)

    # ---- reads
    def _row(self, kind, key):
        return self._x("SELECT val,ts,origin,exp,deleted FROM rec WHERE kind=? AND key=?", (kind, key), one=True)

    def get(self, kind: str, key: str) -> Optional[dict]:
        r = self._row(kind, key)
        if not r or r[4] or (r[3] and r[3] <= self.now_ms()):
            return None
        return json.loads(r[0])

    def get_meta(self, kind: str, key: str) -> Optional[dict]:
        """Like get(), plus ts/origin."""
        r = self._row(kind, key)
        if not r or r[4] or (r[3] and r[3] <= self.now_ms()):
            return None
        return {"val": json.loads(r[0]), "ts": r[1], "origin": r[2], "exp": r[3]}

    def list(self, kind: str, prefix: str = ""):
        now = self.now_ms()
        rows = self._x("SELECT key,val,ts,origin FROM rec WHERE kind=? AND deleted=0 AND key LIKE ? ESCAPE '\\' "
                       "AND (exp=0 OR exp>?) ORDER BY key",
                       (kind, prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%", now))
        return [(k, json.loads(v), ts, o) for k, v, ts, o in rows]

    # ---- replication
    @staticmethod
    def _valid(r) -> bool:
        try:
            return (r["kind"] in KINDS and isinstance(r["key"], str) and 0 < len(r["key"]) <= 200
                    and isinstance(r["val"], dict) and isinstance(r["ts"], int) and isinstance(r["exp"], int)
                    and isinstance(r["deleted"], bool) and NAME_RE.match(r["origin"])
                    and len(json.dumps(r["val"])) <= MAX_VAL)
        except (KeyError, TypeError):
            return False

    def merge(self, records: list) -> int:
        """Apply remote records. Returns the number of records that changed local state."""
        changed = 0
        with self.lock:
            for r in records:
                if not self._valid(r):
                    continue
                if r["exp"] and r["exp"] <= self.now_ms():
                    continue
                cur = self._row(r["kind"], r["key"])
                if cur and (cur[1], cur[2]) >= (r["ts"], r["origin"]):
                    continue
                self._x("INSERT OR REPLACE INTO rec VALUES(?,?,?,?,?,?,?,?)",
                        (r["kind"], r["key"], json.dumps(r["val"], sort_keys=True, separators=(",", ":")),
                         r["ts"], r["origin"], r["exp"], int(r["deleted"]), self._next_lseq()), many=False)
                if r["ts"] > int(self._meta("hlc", 0)):
                    self._set_meta("hlc", r["ts"])
                changed += 1
        return changed

    def changes_since(self, cursor: int, limit: int = 500):
        now = self.now_ms()
        rows = self._x("SELECT kind,key,val,ts,origin,exp,deleted,lseq FROM rec WHERE lseq>? "
                       "AND (exp=0 OR exp>?) ORDER BY lseq LIMIT ?", (cursor, now, limit))
        recs = [{"kind": k, "key": key, "val": json.loads(v), "ts": ts, "origin": o, "exp": e, "deleted": bool(d)}
                for k, key, v, ts, o, e, d, _ in rows]
        last = rows[-1][7] if rows else cursor
        return recs, last, self.max_lseq()

    def cursor(self, peer: str):
        ep, cur = (self._meta("cur:" + peer, "|0") + "").split("|")
        return ep, int(cur)

    def set_cursor(self, peer: str, epoch: str, cur: int):
        self._set_meta("cur:" + peer, f"{epoch}|{cur}")

    def gc(self):
        with self.lock:
            self._x("DELETE FROM rec WHERE exp>0 AND exp<=?", (self.now_ms() - 60_000,), many=False)

    def snapshot(self) -> dict:
        """Converged state, independent of local counters (used by tests)."""
        rows = self._x("SELECT kind,key,val,ts,origin,deleted FROM rec WHERE exp=0 ORDER BY kind,key")
        return {(k, key): (v, ts, o, d) for k, key, v, ts, o, d in rows}


# ---------------------------------------------------------------- passwords and tokens

def hash_password(password: str, n: int = None) -> str:
    n = n or SCRYPT_N
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, dklen=32, maxmem=256 * 1024 * 1024)
    return f"scrypt${n}${SCRYPT_R}${SCRYPT_P}${b64u(salt)}${b64u(h)}"


def check_password(stored: str, password: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=unb64u(salt), n=int(n), r=int(r), p=int(p), dklen=32,
                              maxmem=256 * 1024 * 1024)
        return hmac.compare_digest(calc, unb64u(h))
    except (ValueError, TypeError):
        return False


_DUMMY = None


def dummy_check(password: str):
    """Spend the same time as a real check so unknown users cannot be told apart."""
    global _DUMMY
    if _DUMMY is None or int(_DUMMY.split("$")[1]) != SCRYPT_N:
        _DUMMY = hash_password("dummy")
    check_password(_DUMMY, password)


def make_token(secret: bytes, comm: str, user: str, role: str, tokgen: int, ttl: int = TOKEN_TTL,
               now: Optional[float] = None) -> str:
    payload = json.dumps({"c": comm, "u": user, "r": role, "g": tokgen, "e": int((now or time.time()) + ttl)},
                         separators=(",", ":")).encode()
    return "v2." + b64u(payload) + "." + b64u(hmac.new(secret, b"token" + payload, hashlib.sha256).digest())


def parse_token(secret: bytes, token: str, now: Optional[float] = None) -> Optional[dict]:
    try:
        v, p, s = token.split(".")
        payload = unb64u(p)
        if v != "v2" or not hmac.compare_digest(unb64u(s), hmac.new(secret, b"token" + payload, hashlib.sha256).digest()):
            return None
        d = json.loads(payload)
        return d if d["e"] > (now or time.time()) else None
    except (ValueError, KeyError, TypeError):
        return None


def fed_signature(secret: bytes, origin: str, ts: int, method: str, path: str, body_hash: str) -> str:
    msg = f"{origin}|{ts}|{method}|{path}|{body_hash}".encode()
    return hmac.new(secret, b"fed" + msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- registry

def derive_mac(node_id: bytes, salt: int = 0) -> str:
    d = hashlib.sha256(b"mac" + node_id + bytes([salt])).digest()
    b = bytes([0x02]) + d[:5]                  # locally administered, unicast
    return ":".join(f"{x:02x}" for x in b)


class Registry:
    def __init__(self, store: Store, secret: bytes):
        self.s, self.secret = store, secret

    # ---- communities and users (admin operations)
    def create_community(self, name: str, subnet: str, mtu: int = 1380, max_nodes: int = 200):
        if not NAME_RE.match(name):
            raise RegistryError("bad community name")
        net = ipaddress.ip_network(subnet)
        if net.version != 4 or net.prefixlen > 29 or net.prefixlen < 16:
            raise RegistryError("subnet must be IPv4 between /16 and /29")
        if not 1000 <= mtu <= 1500:
            raise RegistryError("bad mtu")
        self.s.put("comm", name, {"subnet": str(net), "mtu": mtu, "max_nodes": max_nodes})

    def community(self, name: str) -> Optional[dict]:
        return self.s.get("comm", name)

    def add_user(self, comm: str, user: str, password: str, role: str = "user", max_nodes: int = 5):
        if self.community(comm) is None:
            raise RegistryError("unknown community", 404)
        if not NAME_RE.match(user) or role not in ("user", "admin") or len(password) < 8:
            raise RegistryError("bad user name, role or password (min 8 chars)")
        old = self.s.get("user", f"{comm}/{user}")
        self.s.put("user", f"{comm}/{user}", {"hash": hash_password(password), "role": role, "max_nodes": max_nodes,
                                              "disabled": False, "tokgen": (old or {}).get("tokgen", 0) + (1 if old else 0)})

    def set_password(self, comm: str, user: str, password: str):
        u = self.s.get("user", f"{comm}/{user}")
        if not u:
            raise RegistryError("unknown user", 404)
        if len(password) < 8:
            raise RegistryError("password too short (min 8)")
        u.update(hash=hash_password(password), tokgen=u["tokgen"] + 1)      # revokes every issued token
        self.s.put("user", f"{comm}/{user}", u)

    def rename_user(self, comm: str, old: str, new: str) -> int:
        """Renames an account: password hash, role and quota stay, the nodes of the account move to the new name, every issued token is
        revoked (the token generation goes up). Returns the number of nodes that changed owner."""
        if not NAME_RE.match(new or ""):
            raise RegistryError("bad user name")
        with self.s.lock:
            u = self.s.get("user", f"{comm}/{old}")
            if not u:
                raise RegistryError("unknown user", 404)
            if old == new:
                return 0
            if self.s.get("user", f"{comm}/{new}"):
                raise RegistryError("the new name is already taken", 409)
            self.s.put("user", f"{comm}/{new}", dict(u, tokgen=u["tokgen"] + 1))
            moved = 0
            for nid, v, _, _ in self.nodes(comm):
                if v.get("owner") == old:
                    self.s.put("node", f"{comm}/{nid}", dict(v, owner=new))
                    moved += 1
            self.s.delete("user", f"{comm}/{old}")
        return moved

    def set_disabled(self, comm: str, user: str, disabled: bool):
        u = self.s.get("user", f"{comm}/{user}")
        if not u:
            raise RegistryError("unknown user", 404)
        u.update(disabled=disabled, tokgen=u["tokgen"] + 1)
        self.s.put("user", f"{comm}/{user}", u)

    def delete_user(self, comm: str, user: str):
        self.s.delete("user", f"{comm}/{user}")

    # ---- administration (used by the admin page)
    def users(self, comm: str) -> list:
        """Accounts of a community without their password hashes."""
        owned = {}
        for _, v, _, _ in self.nodes(comm):
            owned[v["owner"]] = owned.get(v["owner"], 0) + 1
        return [{"user": k.split("/", 1)[1], "role": v["role"], "disabled": v["disabled"], "max_nodes": v["max_nodes"],
                 "nodes": owned.get(k.split("/", 1)[1], 0)} for k, v, _, _ in self.s.list("user", comm + "/")]

    def change_subnet(self, name: str, subnet: str) -> int:
        """Moves the community to another subnet: every node gets a new address in it (older nodes first, the same hash rule as a fresh
        allocation); MAC addresses, keys, users and routes stay. The nodes learn the new address when they register again (a restart).
        Returns the number of nodes re-addressed."""
        c = self.community(name)
        if c is None:
            raise RegistryError("unknown community", 404)
        try:
            net = ipaddress.ip_network(subnet, strict=True)
        except ValueError:
            raise RegistryError("bad subnet (use a.b.c.d/prefix with the network address, e.g. 10.10.10.0/24)")
        if net.version != 4 or net.prefixlen > 29 or net.prefixlen < 16:
            raise RegistryError("subnet must be IPv4 between /16 and /29")
        with self.s.lock:
            for _, r, _, _ in self.s.list("route", name + "/"):
                if net.overlaps(ipaddress.ip_network(r["cidr"])):
                    raise RegistryError(f"the subnet overlaps the route {r['cidr']}", 409)
            nodes = sorted(self.nodes(name), key=lambda n: (n[1].get("alloc_ts", 0), n[0]))
            if len(nodes) > min(c["max_nodes"], net.num_addresses - 2):
                raise RegistryError("the new subnet is too small for the nodes of the community", 507)
            taken, moved = set(), []
            for nid, v, _, _ in nodes:
                ip = self._alloc_ip(name, net, bytes.fromhex(nid), taken)
                taken.add(ip)
                moved.append((nid, dict(v, ip=ip, alloc_ts=self.s.now_ms())))
            self.s.put("comm", name, dict(c, subnet=str(net)))
            for nid, v in moved:
                self.s.put("node", f"{name}/{nid}", v)
        return len(moved)

    def set_node_ip(self, comm: str, nid_hex: str, ip: str) -> dict:
        """Gives a node a fixed address of the community subnet (for the servers whose other services are configured with it). The address
        must be a host address of the subnet that no other node uses; the node learns it when it registers again (a restart)."""
        c = self.community(comm)
        if c is None:
            raise RegistryError("unknown community", 404)
        try:
            addr = ipaddress.ip_address(ip)
            net = ipaddress.ip_network(c["subnet"])
        except ValueError:
            raise RegistryError("bad address")
        if addr not in net or addr in (net.network_address, net.broadcast_address):
            raise RegistryError(f"{ip} is not a host address of {c['subnet']}")
        with self.s.lock:
            rec = self.s.get("node", f"{comm}/{nid_hex}")
            if not rec:
                raise RegistryError("unknown node", 404)
            for other, v, _, _ in self.nodes(comm):
                if other != nid_hex and v["ip"] == str(addr):
                    raise RegistryError(f"{ip} is used by node {other[:8]} {v.get('name', '')}", 409)
            rec = dict(rec, ip=str(addr), alloc_ts=self.s.now_ms())
            self.s.put("node", f"{comm}/{nid_hex}", rec)
            return rec

    def update_community(self, name: str, mtu: Optional[int] = None, max_nodes: Optional[int] = None):
        c = self.community(name)
        if c is None:
            raise RegistryError("unknown community", 404)
        if mtu is not None:
            if isinstance(mtu, bool) or not isinstance(mtu, int) or not 1000 <= mtu <= 1500:
                raise RegistryError("bad mtu (1000-1500)")
            c["mtu"] = mtu
        if max_nodes is not None:
            if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not 1 <= max_nodes <= 100000:
                raise RegistryError("bad max_nodes (1-100000)")
            c["max_nodes"] = max_nodes
        self.s.put("comm", name, c)

    def delete_community(self, name: str):
        """Removes the community with its accounts, nodes and presence records."""
        if self.community(name) is None:
            raise RegistryError("unknown community", 404)
        with self.s.lock:
            for kind in ("user", "node", "pres", "rel", "dlg", "route"):
                for k, _, _, _ in self.s.list(kind, name + "/"):
                    self.s.delete(kind, k)
            self.s.delete("comm", name)

    def update_user(self, comm: str, user: str, role: Optional[str] = None, max_nodes: Optional[int] = None):
        u = self.s.get("user", f"{comm}/{user}")
        if not u:
            raise RegistryError("unknown user", 404)
        if role is not None:
            if role not in ("user", "admin"):
                raise RegistryError("bad role")
            if role != u["role"]:
                u["role"] = role
                u["tokgen"] += 1             # tokens carry the role they were issued with
        if max_nodes is not None:
            if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not 0 <= max_nodes <= 10000:
                raise RegistryError("bad max_nodes (0-10000)")
            u["max_nodes"] = max_nodes
        self.s.put("user", f"{comm}/{user}", u)

    # ---- login and tokens
    def login(self, comm: str, user: str, password: str) -> Optional[str]:
        u = self.s.get("user", f"{comm}/{user}") if NAME_RE.match(user or "") and NAME_RE.match(comm or "") else None
        if not u:
            dummy_check(password or "")
            return None
        if not check_password(u["hash"], password or "") or u["disabled"]:
            return None
        return make_token(self.secret, comm, user, u["role"], u["tokgen"])

    def authenticate(self, token: str) -> Optional[dict]:
        """-> {'c','u','r'} when the token is genuine and the account is still valid on THIS oneqrelay."""
        d = parse_token(self.secret, token or "")
        if not d:
            return None
        u = self.s.get("user", f"{d['c']}/{d['u']}")
        if not u or u["disabled"] or u["tokgen"] != d["g"]:
            return None
        return {"c": d["c"], "u": d["u"], "r": u["role"]}

    # ---- nodes, IP and MAC allocation
    def nodes(self, comm: str):
        return [(k.split("/", 1)[1], v, ts, o) for k, v, ts, o in self.s.list("node", comm + "/")]

    def _alloc_ip(self, comm: str, net: ipaddress.IPv4Network, nid: bytes, taken: set):
        n = net.num_addresses - 2
        start = int.from_bytes(hashlib.sha256(b"alloc" + nid).digest()[:8], "big") % n
        for i in range(n):
            ip = str(net.network_address + 1 + (start + i) % n)
            if ip not in taken:
                return ip
        raise RegistryError("community address space is full", 507)

    def join_node(self, comm: str, user: str, role: str, nid: bytes, pub_b64: str, name: str = "",
                  offer: Optional[bool] = None, verified: bool = False) -> dict:
        """`verified`: the caller proved possession of the node key (oneqpop). A node id registered with a proof can only be updated
        with a proof (an administrator can delete the node to reset it)."""
        c = self.community(comm)
        if c is None:
            raise RegistryError("unknown community", 404)
        nid_hex = nid.hex()
        key = f"{comm}/{nid_hex}"
        with self.s.lock:
            cur = self.s.get("node", key)
            if cur:
                if cur["owner"] != user and role != "admin":
                    raise RegistryError("node id belongs to another user", 403)
                if cur["pub"] != pub_b64:
                    raise RegistryError("public key mismatch", 409)
                if cur.get("pop") and not verified:
                    raise RegistryError("this node id is protected by a proof of possession of its key", 403)
                changed = False
                if verified and not cur.get("pop"):
                    cur["pop"], changed = True, True
                if name and cur.get("name") != name:
                    cur["name"], changed = name, True
                if offer is not None and bool(cur.get("offer", False)) != bool(offer):
                    cur["offer"], changed = bool(offer), True
                if changed:
                    self.s.put("node", key, cur)
                return cur
            nodes = self.nodes(comm)
            if len(nodes) >= c["max_nodes"]:
                raise RegistryError("community is full", 507)
            u = self.s.get("user", f"{comm}/{user}")
            if sum(1 for _, v, _, _ in nodes if v["owner"] == user) >= (u or {}).get("max_nodes", 5):
                raise RegistryError("node quota exceeded for this user", 403)
            net = ipaddress.ip_network(c["subnet"])
            ip = self._alloc_ip(comm, net, nid, {v["ip"] for _, v, _, _ in nodes})
            macs = {v["mac"] for _, v, _, _ in nodes}
            mac, salt = derive_mac(nid), 0
            while mac in macs:
                salt += 1
                mac = derive_mac(nid, salt)
            rec = {"pub": pub_b64, "owner": user, "name": name[:64], "ip": ip, "mac": mac,
                   "alloc_ts": self.s.now_ms()}
            if verified:
                rec["pop"] = True
            if offer:
                rec["offer"] = True
            self.s.put("node", key, rec)
            return rec

    def delete_node(self, comm: str, nid_hex: str, user: str, role: str):
        key = f"{comm}/{nid_hex}"
        cur = self.s.get("node", key)
        if not cur:
            raise RegistryError("unknown node", 404)
        if cur["owner"] != user and role != "admin":
            raise RegistryError("not your node", 403)
        self.s.delete("node", key)
        self.s.delete("pres", key)
        if self.s.get("dlg", key):
            self.s.delete("dlg", key)
        for rk, rv, _, _ in self.s.list("route", comm + "/"):        # a route through a node that is gone points nowhere
            if rv.get("via") == nid_hex:
                self.s.delete("route", rk)

    def set_presence(self, comm: str, nid_hex: str, endpoints: list, nat: Optional[dict] = None, relays: Optional[list] = None):
        v = {"endpoints": endpoints, "at": self.s.origin}
        if relays:
            v["rl"] = relays                     # delegated relay nodes this node holds a session with (members can reach it through them)
        if nat:
            v["nat"] = nat                       # {"type": ..., "mapped": "ip:port"} as measured by the node against the STUN service
        self.s.put("pres", f"{comm}/{nid_hex}", v, ttl_ms=PRESENCE_TTL_MS)

    def set_relay_at(self, comm: str, nid_hex: str, present: bool):
        key = f"{comm}/{nid_hex}"
        if present:
            self.s.put("rel", key, {"at": self.s.origin}, ttl_ms=PRESENCE_TTL_MS)
        else:
            self.s.delete("rel", key)

    def relay_at(self, comm: str, nid_hex: str) -> Optional[str]:
        r = self.s.get("rel", f"{comm}/{nid_hex}")
        return r["at"] if r else None

    # ---- delegated relay nodes
    def grant_relay(self, comm: str, nid_hex: str, by: str, max_kbps: int = RELAY_DEFAULT_KBPS, days: int = 0, force: bool = False) -> dict:
        """Lets a member node forward datagrams for the other members. It must have offered (relay_offer) and be reachable from the
        outside (open or cone NAT, as measured against the STUN service) unless `force` (administrator who knows better)."""
        if isinstance(max_kbps, bool) or not isinstance(max_kbps, int) or not RELAY_MIN_KBPS <= max_kbps <= RELAY_MAX_KBPS:
            raise RegistryError(f"bad max_kbps ({RELAY_MIN_KBPS}-{RELAY_MAX_KBPS})")
        if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= 3650:
            raise RegistryError("bad days (0 = no expiry, up to 3650)")
        key = f"{comm}/{nid_hex}"
        with self.s.lock:
            n = self.s.get("node", key)
            if not n:
                raise RegistryError("unknown node", 404)
            if not n.get("offer"):
                raise RegistryError("the node has not offered to relay (relay_offer = yes in its configuration)", 409)
            nat = (self.s.get("pres", key) or {}).get("nat") or {}
            if not force and nat.get("type") not in RELAY_NAT_OK:
                raise RegistryError(f"the node is not known to be reachable from outside (NAT: {nat.get('type', 'not measured')}; "
                                    "needs open or cone, or force)", 409)
            rec = {"by": by, "max_kbps": max_kbps, "exp": self.s.now_ms() + days * 86_400_000 if days else 0}
            self.s.put("dlg", key, rec)
            return rec

    def revoke_relay(self, comm: str, nid_hex: str):
        key = f"{comm}/{nid_hex}"
        if not self.s.get("dlg", key):
            raise RegistryError("this node is not a delegated relay", 404)
        self.s.delete("dlg", key)

    def relay_grants(self, comm: str) -> dict:
        """node id -> {"max_kbps", "exp", "by"} of the grants that are in force (not expired)."""
        now = self.s.now_ms()
        return {k.split("/", 1)[1]: v for k, v, _, _ in self.s.list("dlg", comm + "/") if not v.get("exp") or v["exp"] > now}

    # ---- routes through a gateway node
    @staticmethod
    def route_key(comm: str, net, via: Optional[str] = None) -> str:
        base = f"{comm}/{net.network_address}_{net.prefixlen}"
        return base + "/" + via if via else base

    @staticmethod
    def parse_route_key(key: str):
        """'192.168.16.0_24' (as used in URLs and keys) or '192.168.16.0/24' -> an IPv4Network, or a RegistryError."""
        try:
            net = ipaddress.ip_network(key.replace("_", "/"), strict=True)
        except ValueError:
            raise RegistryError("bad network (use a.b.c.d/prefix with the network address, e.g. 192.168.16.0/24)")
        if net.version != 4:
            raise RegistryError("only IPv4 networks")
        return net

    def _route_records(self, comm: str, net=None):
        """[(key, value)] of the route records of the community, or of one network (new and old key shapes)."""
        out = []
        for k, v, _, _ in self.s.list("route", comm + "/" if net is None else self.route_key(comm, net)):
            if net is None or v.get("cidr") == str(net):
                out.append((k, v))
        return out

    def set_route(self, comm: str, cidr: str, via_hex: str, by: str, prio: int = ROUTE_DEFAULT_PRIO) -> dict:
        """Announces `cidr` as reachable through the member node `via_hex` (a gateway). The same network may have several gateways (up to
        ROUTE_MAX_GATEWAYS): this adds one, or changes the priority of one that is already there. Lower `prio` is preferred."""
        c = self.community(comm)
        if c is None:
            raise RegistryError("unknown community", 404)
        net = self.parse_route_key(cidr)
        if isinstance(prio, bool) or not isinstance(prio, int) or not 0 <= prio <= ROUTE_MAX_PRIO:
            raise RegistryError(f"bad priority (0-{ROUTE_MAX_PRIO}, lower is preferred)")
        if net.prefixlen < ROUTE_MIN_PREFIX:
            raise RegistryError(f"the prefix must be /{ROUTE_MIN_PREFIX} or longer (a route for most of the Internet is refused)")
        first, last = net.network_address, net.broadcast_address
        if any(a.is_loopback or a.is_multicast or a.is_link_local or a.is_unspecified or a.is_reserved for a in (first, last)):
            raise RegistryError("loopback, multicast, link-local and reserved networks cannot be routed")
        if net.overlaps(ipaddress.ip_network(c["subnet"])):
            raise RegistryError("the network overlaps the community's own subnet")
        with self.s.lock:
            if not self.s.get("node", f"{comm}/{via_hex}"):
                raise RegistryError("unknown gateway node", 404)
            mine = self._route_records(comm, net)
            if via_hex not in {v["via"] for _, v in mine} and len(mine) >= ROUTE_MAX_GATEWAYS:
                raise RegistryError(f"at most {ROUTE_MAX_GATEWAYS} gateways per network", 409)
            key = self.route_key(comm, net, via_hex)
            if not self.s.get("route", key) and len(self._route_records(comm)) >= MAX_ROUTES_PER_COMM:
                raise RegistryError(f"at most {MAX_ROUTES_PER_COMM} routes per community", 409)
            rec = {"cidr": str(net), "via": via_hex, "by": by, "prio": prio}
            self.s.put("route", key, rec)
            legacy = self.route_key(comm, net)                      # the older record shape (one gateway per network) is superseded
            old = self.s.get("route", legacy)
            if old and old.get("via") == via_hex:
                self.s.delete("route", legacy)
            return rec

    def del_route(self, comm: str, cidr: str, via: Optional[str] = None):
        """Withdraws the route to `cidr`: through every gateway, or only through the node `via`."""
        net = self.parse_route_key(cidr)
        with self.s.lock:
            hit = [k for k, v in self._route_records(comm, net) if via is None or v.get("via") == via]
            if not hit:
                raise RegistryError("no such route", 404)
            for k in hit:
                self.s.delete("route", k)

    def routes(self, comm: str) -> list:
        """Routes of the community whose gateway still exists: [{"cidr", "via", "by", "prio"}], by network, then priority."""
        seen, out = set(), []
        for _, v in self._route_records(comm):
            if (v["cidr"], v["via"]) in seen or not self.s.get("node", f"{comm}/{v['via']}"):
                continue
            seen.add((v["cidr"], v["via"]))
            out.append({"cidr": v["cidr"], "via": v["via"], "by": v.get("by", ""), "prio": v.get("prio", ROUTE_DEFAULT_PRIO)})
        return sorted(out, key=lambda r: (ipaddress.ip_network(r["cidr"]).network_address, r["cidr"], r["prio"], r["via"]))

    def members(self, comm: str) -> list:
        out = []
        grants = self.relay_grants(comm)
        for nid, v, _, _ in self.nodes(comm):
            p = self.s.get("pres", f"{comm}/{nid}")
            g = grants.get(nid) if v.get("offer") else None          # a node that withdrew its offer is not used
            out.append({"id": nid, "pub": v["pub"], "name": v.get("name", ""), "ip": v["ip"], "mac": v["mac"],
                        "owner": v["owner"], "endpoints": (p or {}).get("endpoints", []), "online": p is not None,
                        "nat": (p or {}).get("nat"), "offer": bool(v.get("offer")),
                        "relay_role": {"max_kbps": g["max_kbps"], "exp": g.get("exp", 0)} if g else None,
                        "relays": (p or {}).get("rl", [])})
        return out

    def fix_ip_conflicts(self, comm: str, grace_s: float = 30.0) -> int:
        """Two oneqrelays may hand out the same address concurrently. After replication the record
        with the smaller (alloc_ts, node_id) keeps it; the loser is re-addressed by the oneqrelay that
        wrote it (or by anyone once `grace_s` has passed)."""
        c = self.community(comm)
        if not c:
            return 0
        fixed = 0
        with self.s.lock:
            by_ip = {}
            for nid, v, ts, origin in self.nodes(comm):
                by_ip.setdefault(v["ip"], []).append((v["alloc_ts"], nid, v, ts, origin))
            net = ipaddress.ip_network(c["subnet"])
            for ip, group in by_ip.items():
                if len(group) < 2:
                    continue
                group.sort(key=lambda g: (g[0], g[1]))
                for alloc_ts, nid, v, ts, origin in group[1:]:
                    if origin != self.s.origin and self.s.now_ms() - ts < grace_s * 1000:
                        continue
                    taken = {x["ip"] for _, x, _, _ in self.nodes(comm)}
                    v = dict(v, ip=self._alloc_ip(comm, net, bytes.fromhex(nid), taken), alloc_ts=self.s.now_ms())
                    self.s.put("node", f"{comm}/{nid}", v)
                    fixed += 1
        return fixed
