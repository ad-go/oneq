# Post-quantum VPN: mesh oneqrelay/oneqnode and point-to-point oneqtunel

# Two modes of operation

1. **L2 mesh network with users and passwords (recommended):** `oneqrelay` (federated servers) + `oneqnode` (L2/TAP nodes), IP/MAC allocated automatically. Full description: [ARCHITECTURE.md](ARCHITECTURE.md). Formal wire protocol specification (formats, keys, transcript, threat model, what is not guaranteed): [specifications.html](specifications.html), verified with `spec_check.py`.
2. **Point-to-point (`oneqtunel.py`):** an L3 tunnel between two nodes with manually exchanged keys; see the sections below.

Installing clients (Windows, macOS, Debian, Android), with command examples: [client/README.md](client/README.md#installing-a-client-examples).

## Debian packages (Debian 13, amd64)

Two packages, `oneqrelay` and `oneqnode`, install the application in **`/opt/oneq/relay`** and **`/opt/oneq/node`** (Python libraries included), with commands linked in `/usr/bin`, and configure it from dedicated files:

| File | Role |
|---|---|
| `/etc/oneq/relay.conf` | oneqrelay configuration (INI, section `[relay]`): `id`, `listen`, `db`, `secret_file`, `federation_peers`, `cert`/`key`, `init` |
| `/etc/oneq/node.conf` | oneqnode configuration: `[defaults]` plus one `[NAME]` section per node (`relays`, `community`, `user`, `key_file`, `password_file`, `advertise`, …) |

Command-line options override file settings; a misspelled option stops the service with a clear message. Keys and passwords are not stored in these files, but in separate files (`/etc/oneq/relay.secret`, `/etc/oneq/node-NAME.key`, `node-NAME.password`, mode 0600), referenced by path.

```sh
sudo apt install ./oneq-server_0.0.1_all.deb ./oneqnode_0.0.1_amd64.deb ./oneqrelay_0.0.1_amd64.deb    # server: node + relay (node only: ./oneqnode_0.0.1_amd64.deb); or from the apt repository (repo/README.md)
sudo oneqrelay-admin community-add lan 10.50.0.0/24
sudo oneqrelay-admin user-add lan alice --role admin
sudo oneqnode-init lan --relay https://r1.example.org --community lan --user alice
```

Services start under systemd or supervisord (auto-detected, or `init =` in the config file). Build: `packaging/build-debs.sh`; signed repository: `packaging/make-repo.sh` + `packaging/sign-repo.sh`; tests: `packaging/{smoke,service,repo}-test.sh`.
The signed apt repository is in Gitea, `ad-go/oneq-apt` (0.0.1, trixie/amd64; key `oneq-archive-keyring.gpg`, fingerprint `4C33 A0A0 1EC9 798B 53EE 638D 1F87 9861 4F16 22ED`); `oneq.sources` contains a placeholder URL (`https://apt.example.org/oneq`) until the directory is served by a web server.

## Mesh network: quick start

```sh
# 1. Same federation secret on all oneqrelay instances
oneqrelay.py gen-secret > federation.secret && chmod 600 federation.secret

# 2. On the first oneqrelay: community and users (password from file / $TUNMESH_PASSWORD / prompt, never from arguments)
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret community-add lan 10.50.0.0/24
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret user-add lan alice --role admin --password-file alice.pw
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret list

# 3. Start the oneqrelay instances (TLS 1.3, X25519MLKEM768 only); accounts and nodes replicate between them
oneqrelay.py run --id r1 --db r1.db --secret-file federation.secret --listen 0.0.0.0:8443     --cert fullchain.pem --key privkey.pem --fed-peer https://r2.example.org:8443 --cafile ca.pem
oneqrelay.py run --id r2 --db r2.db --secret-file federation.secret ... --fed-peer https://r1.example.org:8443

# 4. On each node: own key, then join the community (IP and MAC come from oneqrelay)
oneqnode.py genkey --key node.key
oneqnode.py run --key node.key --relay https://r1.example.org:8443 --relay https://r2.example.org:8443     --community lan --user alice --password-file alice.pw --name laptop --advertise 203.0.113.5:51820 --listen 0.0.0.0:51820
```

- Multiple `--relay` = automatic failover. A `oneqnode` stays on the network even when all oneqrelay instances go down.
- Administration (`oneqrelay.py admin`): `community-add`, `community-subnet`, `user-add`, `user-passwd`, `user-disable`, `user-enable`, `user-del`, `node-del`, `relay-grant`, `relay-revoke`, `route-add`, `route-del`, `list`.
  Changing the password or disabling an account immediately revokes all its tokens across the entire federation. `community-subnet COMMUNITY 10.10.10.0/24` moves the community to a different subnet: each node gets a new address (MACs, keys, users and routes remain)
  and picks it up on restart; rejected if the new subnet is too small or overlaps a route.
- Bound to the address of an existing interface: `oneqnode.py run ... --via IFACE`. The interface belongs to the process that created it (not shared); `oneqnode` creates its own TAP.
- Production: `deploy/oneqrelay.service`, `deploy/oneqnode@.service`, `deploy/nginx-oneqrelay.conf`, `deploy/oneqnode.env.example`.
- Mesh tests: `test_mesh_core.py`, `test_oneqrelay.py`, `test_oneqnode.py` (no root), `sudo python3 test_e2e_mesh.py` (real TAPs, 2 oneqrelay + 3 oneqnode in namespaces: direct, relay forced through federation, fallback + failover + recovery, accounts).

---

## Nodes delegated as relays

The federation can **delegate ordinary nodes to relay packets** for other members when they cannot reach each other directly. The node offers itself (`relay_offer = yes` in `node.conf`, `--relay-offer`),
the administrator delegates it (admin page: "Delegate…" button on the node, or `oneqrelay admin relay-grant COMMUNITY NODE [--max-kbps N] [--days D] [--force]`), and nodes that
cannot reach each other directly send their packets (end-to-end encrypted) through it, over UDP, before falling back to the WebSocket relay of `oneqrelay`. Requirements: the node must be
reachable from outside (NAT `open` or `cone`, measured by STUN), and all relay servers in the federation must know the delegations. Revocation: `relay-revoke` or "Withdraw". Details: ARCHITECTURE.md.

## Routes through a gateway node

A private network behind a member (e.g. `192.168.16.0/24`) can be made transparently accessible to other members. The administrator announces it via a **gateway** node:

    oneqrelay admin route-add COMMUNITY 192.168.16.0/24 NODE [--prio 100]      # NODE: id, id prefix (8+ digits) or name; or admin page, "Routes" section
    oneqrelay admin route-del COMMUNITY 192.168.16.0/24 [NODE]                 # one gateway, or all

The same network can have up to 4 gateways (redundancy): the client uses the one with the best priority among those that respond, and switches to the next when it goes silent, without switching back automatically.
The gateway is an ordinary node with `ip_forward` and NAT (`deploy/oneq-gateway`, `deploy/oneq-gateway.service`: only the announced network exits the mesh). Rust clients receive routes with `--accept-routes`
(`accept_routes` in the service configuration, off by default) and accept only private networks outside the mesh. Details: ARCHITECTURE.md, `client/README.md`.

## Relay on Windows and macOS

The Windows and macOS packages (`client/package-desktop.py`) include both the node and the relay (with bundled Python 3.13 / OpenSSL 3.5): `oneqclient relay init`, then
`oneqclient relay install` (Windows service `oneqrelay` / launchd daemon), see `client/README.md`. Android has no relay (node only): the relay is in Python.
`oneqrelay init --dir DIR --name HOST` performs the same setup on any machine without the Debian package.

## oneqrelay admin page

Each oneqrelay can serve an admin page on the same TLS port: `https://<relay>/admin/`. It is disabled until you set
`admin_password_file` in `/etc/oneq/relay.conf` (the operator password, a mode 0600 file owned by the `oneqrelay` user). **A second factor
is mandatory**: TOTP codes (RFC 6238) from any authenticator app (Google/Microsoft Authenticator, Aegis, FreeOTP, 1Password…).
Without `admin_totp_file` the relay refuses to start the page: two-factor authentication is required, from any network.

    sudo -u oneqrelay oneqrelay gen-admin-password --out /etc/oneq/admin.pw      # writes the file (0600) and prints the password once
    sudo -u oneqrelay oneqrelay admin-totp --out /var/lib/oneq/relay/admin.totp --issuer "oneqrelay x" \
         --save-enrolment /tmp/enrol.txt                                       # QR in terminal, otpauth link, secret, 10 recovery codes
    # in relay.conf:  admin_password_file = /etc/oneq/admin.pw
    #                 admin_totp_file     = /var/lib/oneq/relay/admin.totp
    #                 admin_allow         = 203.0.113.0/24, 10.0.0.0/8      # optional: others get 404
    # then: systemctl restart oneqrelay

The TOTP file lives in `/var/lib/oneq/relay`, not in `/etc`: the service rewrites it on every login (last step used, consumed recovery codes),
and systemd mounts `/etc` read-only for it; the relay checks at startup that it can write the file.

The page has three sections:

* **Relay**: effective settings (id, port, TLS-PQ transport, database, federation CA, configuration), version, uptime,
  attached nodes, totals and limits for this version. File settings are changed in `relay.conf` (with a restart).
* **Federation**: peers, age of last synchronization, active relay links and the federation secret fingerprint (the same on
  all relay instances). Peers can be added/removed from the page (stored locally); those from `relay.conf` are only displayed.
  Replication *pulls* data from peers: for a bidirectional link, add the peer on the other relay too.
* **Communities**: create, modify (MTU, maximum number of nodes), cascade delete (requires community name); per community
  users (add, new password, enable/disable, role, node quota, delete) and nodes (address, MAC, owner,
  status, attached relay, remove). Changes go through the replicated registry, so they reach all relay instances.

Authentication: password + code from the app (±30 s window for clock differences). A code cannot be used twice (not even after a restart:
the last accepted step is saved), a wrong code or wrong password give the same message and the same lockout (5 failures → 60 s, then doubling up to 15 min),
the code is consumed only if the password was correct, and if the state cannot be saved the code is rejected. The 10 recovery codes (hashed in the file) work only once.
Security: HMAC-signed operator token (1 h) kept only in page memory (no cookie), lockout after repeated failures,
strict CSP with no external resources, every change is logged with the client address. A community user token
(even with `admin` role) has no access. The password is not displayed and not stored in the page.

## Node key proof of possession

*English version: [POP.md](POP.md).*

`node_id` is the hash of the public key, and public keys are not secret (the member list shows them). Without a proof, anyone with a token (point-to-point mode) or an account
(mesh) could register someone else's key with their own addresses or could claim a `node_id` before its owner. Node keys are KEM keys (X25519 + ML-KEM-768), not signing keys,
so the proof is a **challenge** that only the holder of the private key can open (`oneqpop.py`):

1. The node sends `POST /v1/c/<community>/nodes/<id>/challenge` (point-to-point mode: `POST /v1/nodes/<id>/challenge`) with the public key.
2. The server encapsulates ML-KEM towards the node's key, performs an ephemeral–static X25519 exchange and seals a secret `R = HMAC(server_key, nonce | exp | node_id)`. **Stateless**:
   in a federation, `server_key` is derived from the shared secret, so any relay can verify a challenge made by another.
3. The node opens the challenge and responds with `HMAC(R, "proof" | node_id | nonce | exp)`, sent in `PUT` as `pop` (valid for 60 s and reused until close to expiry).

Rules: a node registered once with a proof **can no longer be updated without a proof** (also protects against downgrade attacks); `--require-pop` (`require_pop = yes`) rejects any
registration without a proof; an administrator can reset a `node_id` by deleting the node. In point-to-point mode, the WebSocket relay slot of a verified node also requires the proof
(`X-Oneq-Pop`). A relay that does not know the challenge responds with 404, and the node falls back to a simple registration (compatibility). The proof does not cover the rest of the request: it protects against those who **do not** have the key, not against an attacker who can read the TLS stream. The Rust and Python clients implement the same protocol. The `oneqrelay` package depends on `cryptography` (ML-KEM).

## Nodes behind NAT

*English version of this section: [NAT.md](NAT.md).*

Any node can reach any other node through the relay (WebSocket, always attached). A direct UDP path is established in addition, if the NATs allow it.

**What `oneqrelay` does.** It starts by default a STUN service (RFC 5389, with `CHANGE-REQUEST` on port as in RFC 5780) on **three UDP ports**
of the listen address: the `listen` port, +1 and +2 (`stun`, `stun_port`, `stun_alt_port`, `stun_change_port` in `relay.conf`; must be
opened in the firewall). It can also test whether a node accepts unsolicited packets: `POST /v1/c/<community>/nodes/<id>/nat-test`
sends a Binding request from a port the node has never contacted (only to the caller's public address;
loopback/link-local/multicast are rejected; one probe per 5 s per node).

**What the node does** (`oneqnode`, Rust client, apps): three STUN transactions on the same UDP socket used for traffic:
1. main port → public address M1 (no response = `blocked`);
2. alternate port → M2; M2 ≠ M1 ⇒ mapping depends on destination ⇒ `symmetric`;
3. main port with change-port ⇒ response comes from the third port, never contacted: if it arrives ⇒ `cone`, otherwise `port-restricted`
   (local address = M1 ⇒ `open`, no NAT).
The result (type, public address, "inbound") appears in the registry, on the admin page and in apps; the public address becomes
a candidate for others (not for `symmetric`: port changes with destination). Measured again every 5 min or when the mapping changes.
`oneqnode nat-check HOST:PORT` shows the result without joining a community.

**Which pairs connect directly**

| | open | cone | port-restricted | symmetric |
|---|---|---|---|---|
| **open** | direct | direct | direct | direct |
| **cone** | direct | direct | direct | direct |
| **port-restricted** | direct | direct | direct | relay |
| **symmetric** | direct | direct | relay | relay |

"Relay" pairs do not wait 10 s: nodes know in advance that a direct path is not possible and go directly to the relay (traffic works the same way).
This is the basic table; four mechanisms change it (sections below): port mapping on the router, port prediction, double NAT and IPv6.

| Situation | Rule |
|---|---|
| symmetric with predictable port step (`delta`) vs port-restricted | direct (the other end probes the predicted ports) |
| symmetric vs symmetric, **both** with `delta` | direct |
| one side with a second NAT (`cgnat`) | immediate relay, unless the other side is `open` |
| both sides have a global IPv6 address | always tries direct (no translation, only a stateful firewall) |
| port mapping on router verified from outside | published as `open` |

**Hole punching synchronization.** Between two filtering NATs, a packet arriving at a NAT *before* that NAT has sent anything "poisons" the connection table (netfilter: the next mapping uses a different port) and retransmitting keeps it alive. Therefore the two nodes only send unsolicited packets in **rounds** aligned to the relay's clock (measured at each registration, error ≤ half the RTT): every 4 s, in the first 3 rounds out of 10 (the ~32 s silence lets failed state expire), in bursts of 4 packets. When a packet from the other end arrives, the "hole" is used immediately (INIT or probe), towards that address and only towards IPs registered by it (a spoofed address does not trigger a 2 KB handshake to a third party). Between an `open`/`cone` node and anyone, continuous attempts as before are maintained.

**Tests** (`test_nat_sim.py`, as root on Linux with real simulated NATs: namespaces + nftables, 15 ms latency on each link):
classification for open, port-restricted (`masquerade`), symmetric (`masquerade random`), cone (static SNAT/DNAT) and blocked UDP;
node pairs: port-restricted ↔ port-restricted (hard case), port-restricted ↔ cone, symmetric ↔ cone, open ↔ symmetric
connect directly, symmetric ↔ port-restricted goes to relay immediately; same cases between **the Rust client** (compiled for Linux with Zig)
and the Python node, in both role orders, plus Rust ↔ Rust. Without latency (0.1 ms) two Linux NATs "poison" each other
(lab artifact: on the internet latency separates packets), which is why the test requires `tc netem`.

**Automatic port mapping on the router (PCP, NAT-PMP, UPnP).** If the NAT is not `open`, the node asks the home router to
forward its UDP port: first PCP (RFC 6887, UDP 5351 on the gateway), then NAT-PMP (RFC 6886), then UPnP IGD (SSDP discovery,
`AddPortMapping` via SOAP; `oneqportmap.py` and `client/core/src/portmap.rs`, same logic). The mapping is renewed at half its lifetime and
deleted on shutdown. The node **does not claim** to be open based on the router's response: it asks the relay to probe the mapping's external address from an
uncontacted port (`nat-test`) and only if the response arrives does it publish `open` (with `via: pcp|natpmp|upnp`); other nodes then try the address directly,
without hole punching. A UPnP response is accepted only from a private/link-local address, with `LOCATION` and the control URL on the same address (a
spoofed response cannot redirect the node to a third party), with bodies limited to 64 KB. Disable: `--no-port-mapping` (`port_mapping = no` in `node.conf`).

**Double NAT (CGNAT, a router behind another router).** A node is considered behind two NATs if the address seen by the relay is in
100.64.0.0/10 (RFC 6598) or if the router reports (NAT-PMP/PCP/UPnP) a different WAN address than the one seen by the relay. A mapping on the first router
would be useless (deleted), the node publishes `cgnat: true`, and the pair goes **immediately to relay**, unless the other side is `open`. If
the router does not respond to any protocol, only the 100.64.0.0/10 case is detectable; a CGNAT with public addresses cannot be recognized this way.

**Port prediction (symmetric NAT).** For a symmetric NAT the node performs a third STUN transaction, towards the "change" port of the relay (announced as
`stun.change_port`): three consecutive mappings with a constant step (`delta`, 1..64, or small positive steps) ⇒ sequential allocation. It publishes `delta` and the most recent
mapping; the other side sends PUNCH also to `port + delta·k`, k = 1..16, in synchronized rounds. This way symmetric ↔ port-restricted and
symmetric ↔ symmetric (both with `delta`) no longer need to go to relay. The method guesses: if the NAT has served other flows between measurement and
punching, the target may be missed (the 16-port window covers part of the range); it does not help with random-port NATs, which stay on relay.

**IPv6.** The node's data socket is dual-stack (`::` with `IPV6_V6ONLY` off; falls back to IPv4 if the system cannot). A global IPv6 address
(2000::/3, chosen by the system for internet, without sending any packet) is published as `[address]:port`, and the IPv6 candidates of others are
tried the same way as IPv4. Two nodes with global IPv6 do not go through NAT rules (no translation, only a stateful firewall) and do not fall back to relay for
NAT reasons. `--no-ipv6` (`ipv6 = no`) disables it.

`oneqnode nat-check` also shows the port allocation step and whether there is a second NAT. An `--advertise` verified by the relay: if it does not respond to
the probe, the node writes a warning.


# Mode 2: point-to-point (oneqtunel)

Educational project, **without an independent cryptographic audit**.

- **Handshake:** X25519 + ML-KEM-768 (ML-KEM secret before X25519 in each KDF), 2 messages:
  `INIT` 2329 B, `RESP` 2225 B, fragmented at the application level (≤ 1200 B/datagram).
- **Data:** ChaCha20-Poly1305, 64-bit counter, 1024-packet anti-replay window. Rekey at 120 s, rejection at 180 s, keepalive at 25 s.
- **Discovery:** HTTPS rendezvous API (`rendezvous_server.py`), TLS 1.3 **only** X25519MLKEM768, no fallback.
- **Relay:** if after ~10 s there is no direct session, datagrams go opaque through a WebSocket (`wss://…/v1/relay`). The tunnel reverts automatically to the direct path (probe every 20 s).
- `LABEL`: `tunsec-pq/v1 …` (the wire constant of the point-to-point mode). Any protocol change gets a new version.

## Requirements

Python linked against **OpenSSL ≥ 3.5** (`python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"`), `/dev/net/tun`, `ip`.

```sh
python3 -m venv /opt/oneq-src/venv && /opt/oneq-src/venv/bin/pip install -r requirements.txt
/opt/oneq-src/venv/bin/python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey"
```

## Keys and public key exchange

```sh
oneqtunel.py genkey --key A.key          # writes A.key (0600) and A.key.pub (1216 B, base64); prints node_id
```

Exchange the **`.pub` files** between the two nodes over a trusted channel. The rendezvous server is not trusted for identity, because the handshake authenticates nodes by their static keys. `node_id = SHA-256(public key)[:16]`. The node with the smaller public key is the initiator.

## Token and server

```sh
python3 -c "import secrets;print(secrets.token_urlsafe(32))" > net.token && chmod 600 net.token   # same on both nodes
python3 rendezvous_server.py hash-token < net.token >> /etc/oneq-p2p/tokens.sha256                   # server only stores the hash
```

Server with direct TLS (self-signed certificate or Let's Encrypt):

```sh
rendezvous_server.py run --listen 0.0.0.0:8443 --cert fullchain.pem --key privkey.pem --tokens-file tokens.sha256
```

In production, recommended behind nginx/Caddy (`deploy/`), with the server on `127.0.0.1:8080 --insecure-http --trust-proxy`.

## Starting a node

```sh
# token from file (0600) or from environment (TUNSEC_TOKEN). Never from the command line.
oneqtunel.py run --key A.key --peer B.key.pub --ifname pq0 --addr 10.99.0.1/24 \
   --listen 0.0.0.0:51820 --advertise 203.0.113.5:51820 \
   --rendezvous https://rv.example.org --token-file net.token [--cafile ca.pem] [--stun host:3478]
```

Requires `CAP_NET_ADMIN` (or a persistent TUN: `ip tuntap add dev pq0 mode tun user oneq-p2p`, then `--no-config`, in which case the node no longer needs privileges).
Without rendezvous (test or fixed IPs): `--peer-endpoint IP:PORT`. Relay: `--force-relay`, `--no-relay`, `--relay-after SEC`.

## Interface binding (`--via`)

`--via IFACE` binds the UDP socket to the address of interface IFACE (e.g. of another existing tunnel). Its address is announced as an additional candidate. The interface is **owned by the process that created it and cannot be shared**: the tunnel creates its **own** TUN interface (`--ifname pq0`), and traffic flows encapsulated through the other interface. The default MTU in this case is **1220** (1380 otherwise). Can be overridden with `--mtu`.

## Post-quantum TLS verification

With an `openssl` ≥ 3.5:

```sh
openssl s_client -connect rv.example.org:443 -tls1_3 -groups X25519MLKEM768 -brief </dev/null   # expected: "Negotiated TLS1.3 group: X25519MLKEM768"
openssl s_client -connect rv.example.org:443 -tls1_3 -groups X25519          -brief </dev/null   # expected to fail (handshake_failure)
```

**Mechanism:** Python 3.13 does not have `SSLContext.set_groups`, so `pqtls.py` sets `OPENSSL_CONF=pq_openssl.cnf` (TLS 1.3, `Groups = X25519MLKEM768`) *before* `import ssl`. The file is loaded only in our processes, not in the rest of the system. The client (`Rendezvous`, `RelayClient`) rejects any server that does not offer this group. On a proxy, the restriction is enforced with `ssl_ecdh_curve X25519MLKEM768` (nginx) or `curves x25519mlkem768` (Caddy).

## Production

`deploy/`: `oneq-p2p@.service` (user `oneq-p2p`, `CAP_NET_ADMIN` only here, key and token via `LoadCredential`), `oneq-p2p-rendezvous.service` (no capabilities), `nginx-rendezvous.conf`, `Caddyfile`, `node.env.example`.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin oneq-p2p;  useradd --system ... oneq-p2p-rv
install -m600 A.key /etc/oneq-p2p/NAME.key;  install -m600 net.token /etc/oneq-p2p/NAME.token
cp deploy/node.env.example /etc/oneq-p2p/NAME.env && chmod 600 /etc/oneq-p2p/NAME.env   # edit ONEQ_P2P_ARGS
systemctl enable --now oneq-p2p@NAME
```

## Tests

```sh
python3 test_oneqtunel.py        # unit + TLS (openssl s_client) + API + relay + fragmentation, no root
python3 test_nginx_proxy.py      # real nginx (OpenSSL ≥ 3.5) in front of the server
sudo python3 test_e2e.py         # 2 real TUNs in namespaces: direct, forced relay, fallback + recovery; no plaintext on the wire
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `handshake failure` towards rendezvous | server/proxy does not offer X25519MLKEM768 (OpenSSL < 3.5) |
| `pqtls must be imported before ssl` | a module imports `ssl` before `pqtls` |
| `cannot import mlkem` | `cryptography` too old (requires ≥ 50.0.2 tested) |
| no session, no relay | wrong token (401), clocks drifted > 180 s (INIT rejected), UDP blocked and `--no-relay` |
| session through relay only | symmetric NAT or firewall; check `--advertise` and UDP ports |
| `private key must not be accessible…` | `chmod 600` on key/token |
| TUN: `Operation not permitted` | missing `CAP_NET_ADMIN` (or persistent TUN with `--no-config`) |
| MTU/loss with `--via` (encapsulation in another tunnel) | use `--mtu 1220` or smaller |

## Known limitations

- **Node key proof of possession** (see section above, [POP.md](POP.md) in English): prevents a token/account holder who does not have the private key from claiming a `node_id`.
  Does not protect against a compromised relay (which can delete a node and allocate its address to another key) or against an account holder who also has the key. Without
  `--require-pop`, a node that does not provide proof is accepted and its slot can be taken.
- One peer per node (point-to-point mode); for multiple peers use the mesh mode.
- Port prediction guesses (see "Nodes behind NAT"); a NAT with random ports, a CGNAT with public addresses and a symmetric NAT without a constant step stay on relay.

## Update check

The relay, the Python node and the clients look once a day on the GitHub Releases of `ad-go/oneq` whether a newer version exists
(`GET https://api.github.com/repos/ad-go/oneq/releases/latest`, HTTPS only, no identifiers, no telemetry; drafts and pre-releases are ignored).
When one exists, the relay admin page shows a one-line banner and the node writes one log line. The package can be downloaded from the admin
page (`oneqnode update-download` on a node) and is verified against the `SHA256SUMS` of the same release; a file that does not match is deleted.
Nothing is ever installed or executed automatically: you install the downloaded package yourself.
Turn the automatic check off with `update_check = no` in `relay.conf` / `node.conf` (the "Check for updates" button and
`oneqnode update-check` keep working). `update_url` overrides the release API address, `update_dir` the download directory of the relay.
