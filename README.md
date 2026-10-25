# Post-quantum VPN: oneqrelay/oneqnode mesh and oneqtunel point-to-point

# Two modes of operation

1. **L2 mesh network with users and passwords (recommended):** `oneqrelay` (federated servers) + `oneqnode` (L2/TAP nodes), IP/MAC assigned automatically. Full description: [ARCHITECTURE.md](ARCHITECTURE.md). Formal specification of the wire protocol (formats, keys, transcript, threat model, what it does not guarantee): [specifications.html](specifications.html), checked with `spec_check.py`.
2. **Point-to-point (`oneqtunel.py`):** an L3 tunnel between two nodes with manually exchanged keys; see the sections below.

Installing the clients (Windows, macOS, Debian, Android), with command examples: [client/README.md](client/README.md#installing-a-client-examples).

## Debian packages (Debian 13, amd64)

Two packages, `oneqrelay` and `oneqnode`, install the application in **`/opt/oneq/relay`** and **`/opt/oneq/node`** (Python libraries included), with the commands linked in `/usr/bin`, and configure it from real files:

| File | Role |
|---|---|
| `/etc/oneq/relay.conf` | oneqrelay configuration (INI, `[relay]` section): `id`, `listen`, `db`, `secret_file`, `federation_peers`, `cert`/`key`, `init` |
| `/etc/oneq/node.conf` | oneqnode configuration: `[defaults]` plus one `[NAME]` section per node (`relays`, `community`, `user`, `key_file`, `password_file`, `advertise`, ...) |

Command-line options override them; a misspelled option stops the service with a clear message. Keys and passwords are not kept in these files, but in separate files (`/etc/oneq/relay.secret`, `/etc/oneq/node-NAME.key`, `node-NAME.password`, mode 0600), referenced by path.

```sh
sudo apt install ./oneq-server_0.0.1_all.deb ./oneqnode_0.0.1_amd64.deb ./oneqrelay_0.0.1_amd64.deb    # server: node + relay (node only: ./oneqnode_0.0.1_amd64.deb); or from a signed apt repository built from these packages
sudo oneqrelay-admin community-add lan 10.0.0.0/24
sudo oneqrelay-admin user-add lan admin --role admin
sudo oneqnode-init lan --relay https://r1.example.org --community lan --user admin
```

Services start under systemd or supervisord (auto-detected, or `init =` in the configuration file). Build: `packaging/build-debs.sh`; signed repository: `packaging/make-repo.sh` + `packaging/sign-repo.sh`; tests: `packaging/{smoke,service,repo}-test.sh`.
The signed apt repository is built from the packages (0.0.1, trixie/amd64, keyring `oneq-archive-keyring.gpg`); `oneq.sources` contains a placeholder URL (`https://apt.example.org/oneq`) until the directory is served by a web server.

## Mesh network: quick start

```sh
# 1. The same federation secret on all oneqrelay instances
oneqrelay.py gen-secret > federation.secret && chmod 600 federation.secret

# 2. On the first oneqrelay: community and users (password from a file / $TUNMESH_PASSWORD / prompt, never from arguments)
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret community-add lan 10.0.0.0/24
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret user-add lan admin --role admin --password-file admin.pw
oneqrelay.py admin --db r1.db --id r1 --secret-file federation.secret list

# 3. Start the oneqrelay instances (TLS 1.3 with X25519MLKEM768 only); accounts and nodes replicate between them
oneqrelay.py run --id r1 --db r1.db --secret-file federation.secret --listen 0.0.0.0:8443     --cert fullchain.pem --key privkey.pem --fed-peer https://r2.example.org:8443 --cafile ca.pem
oneqrelay.py run --id r2 --db r2.db --secret-file federation.secret ... --fed-peer https://r1.example.org:8443

# 4. On each node: own key, then join the community (IP and MAC come from oneqrelay)
oneqnode.py genkey --key node.key
oneqnode.py run --key node.key --relay https://r1.example.org:8443 --relay https://r2.example.org:8443     --community lan --user admin --password-file admin.pw --name laptop --advertise 203.0.113.5:51820 --listen 0.0.0.0:51820
```

- Several `--relay` options = automatic failover. A `oneqnode` stays in the network even when all oneqrelay instances go down.
- Administration (`oneqrelay.py admin`): `community-add`, `community-subnet`, `user-add`, `user-passwd`, `user-disable`, `user-enable`, `user-del`, `node-del`, `relay-grant`, `relay-revoke`, `route-add`, `route-del`, `list`.
  Changing the password or disabling an account immediately revokes all of the account's tokens, across the whole federation. `community-subnet COMMUNITY 10.20.0.0/24` moves the community to another subnet: every node gets a new address (MACs, keys, users and routes are kept)
  and picks it up on restart; it is refused if the new subnet is too small or covers a route.
- Bound to the address of an existing interface: `oneqnode.py run ... --via IFACE`. The interface stays owned by the process that holds it (it is not shared); `oneqnode` creates its own TAP.
- Production: `deploy/oneqrelay.service`, `deploy/oneqnode@.service`, `deploy/nginx-oneqrelay.conf`, `deploy/oneqnode.env.example`.
- Mesh tests: `test_mesh_core.py`, `test_oneqrelay.py`, `test_oneqnode.py` (no root), `sudo python3 test_e2e_mesh.py` (real TAP devices, 2 oneqrelay + 3 oneqnode in namespaces: direct, relay forced through the federation, fallback + failover + return, accounts).

---

## Nodes delegated as relays

The federation can **delegate ordinary nodes to act as relays** for the other members, without giving them any secret. The node offers itself (`relay_offer = yes` in `node.conf`, `--relay-offer`),
the administrator delegates it (admin page: the "Delegate..." button on the node, or `oneqrelay admin relay-grant COMMUNITY NODE [--max-kbps N] [--days D] [--force]`), and nodes that
cannot reach each other directly send their packets (end-to-end encrypted) through it, over UDP, before falling back to the `oneqrelay` WebSocket relay. Conditions: the node must be reachable from
the outside (NAT `open` or `cone`, as measured by STUN), and all the federation's relays must know about the delegations. Revocation: `relay-revoke` or "Withdraw". Details: ARCHITECTURE.md.

## Routes through a gateway node

A private network behind a member (e.g. `192.168.50.0/24`) can be made transparently reachable to the other members. The administrator announces it through a **gateway** node:

    oneqrelay admin route-add COMMUNITY 192.168.50.0/24 NODE [--prio 100]      # NODE: id, id prefix (8+ digits) or name; or the admin page, "Routes" section
    oneqrelay admin route-del COMMUNITY 192.168.50.0/24 [NODE]                 # one gateway, or all

The same network can have up to 4 gateways (redundancy): the client uses the one with the best priority among those that respond, and switches to the next when that one goes silent, without returning on its own.
The gateway is an ordinary node with `ip_forward` and NAT (`deploy/oneq-gateway`, `deploy/oneq-gateway.service`: only the announced network leaves the mesh). Rust clients receive the routes with `--accept-routes`
(`accept_routes` in the service configuration, off by default) and accept only private networks outside the mesh. Details: ARCHITECTURE.md, `client/README.md`.

## Relay on Windows and macOS

The packages for Windows and macOS (`client/package-desktop.py`) contain both the node and the relay (with their own Python 3.13 / OpenSSL 3.5): `oneqclient relay init`, then
`oneqclient relay install` (Windows service `oneqrelay` / launchd daemon), see `client/README.md`. There is no relay on Android (node only): the relay is written in Python.
`oneqrelay init --dir DIR --name HOST` does the same setup on any machine without the Debian package.

## The oneqrelay administration page

Each oneqrelay can serve an administration page on the same TLS port: `https://<relay>/admin/`. It is off until you set
`admin_password_file` in `/etc/oneq/relay.conf` (the operator password, a mode 0600 file owned by the `oneqrelay` user). **A second factor
is mandatory**: TOTP codes (RFC 6238) from any authenticator app (Google/Microsoft Authenticator, Aegis, FreeOTP, 1Password...).
Without `admin_totp_file` the relay refuses to start the page: two-step authentication is mandatory, from any network.

    sudo -u oneqrelay oneqrelay gen-admin-password --out /etc/oneq/admin.pw      # writes the file (0600) and prints the password once
    sudo -u oneqrelay oneqrelay admin-totp --out /var/lib/oneq/relay/admin.totp --issuer "oneqrelay x" \
         --save-enrolment /tmp/enrol.txt                                       # QR in the terminal, otpauth link, secret, 10 recovery codes
    # in relay.conf:  admin_password_file = /etc/oneq/admin.pw
    #                 admin_totp_file     = /var/lib/oneq/relay/admin.totp
    #                 admin_allow         = 203.0.113.0/24, 10.0.0.0/8      # optional: everyone else gets 404
    # then: systemctl restart oneqrelay

The TOTP file lives in `/var/lib/oneq/relay`, not in `/etc`: the service rewrites it on every login (last used step, recovery codes consumed),
and systemd mounts `/etc` read-only for it; the relay checks at startup that it can write it.

The page has three sections:

* **Relay**: the effective settings (id, port, TLS-PQ transport, database, federation CA, configuration), version, uptime,
  attached nodes, totals and the limits in this version. File settings are changed in `relay.conf` (with a restart).
* **Federation**: the peers, the age of the last synchronization, the active relay links and the fingerprint of the federation secret (the same on
  all relays). Peers can be added/removed from the page (they stay saved locally); those from `relay.conf` are only displayed.
  Replication *pulls* data from a peer: for a link in both directions, add the peer on the other relay too.
* **Communities**: create, modify (MTU, maximum number of nodes), cascading delete (requires the community name); per community,
  users (add, new password, enable/disable, role, node quota, delete) and nodes (address, MAC, owner,
  state, the relay they are attached to, remove). Changes go through the replicated registry, so they reach all relays.

Authentication: password + code from the app (a window of +/-30 s for clock drift). A code cannot be used twice (not even after a restart:
the last accepted step is saved), a wrong code or a wrong password gives the same message and the same lockout (5 failures -> 60 s, then doubling up to 15 min),
the code is consumed only if the password was correct, and if the state cannot be saved the code is refused. The 10 recovery codes (hashed in the file) work once each.
Security: an HMAC-signed operator token (1 h) kept only in the page's memory (no cookie), lockout after repeated failures,
strict CSP with no external resources, every change is logged with the client's address. A community user token
(even with the `admin` role) has no access. The password is not displayed and not stored in the page.

## Proof of possession of the node key

*English version: [POP.md](POP.md).*

`node_id` is the hash of the public key, and public keys are not secret (the member list shows them). Without a proof, anyone with a token (point-to-point mode) or an account
(mesh) could register someone else's key with their own addresses or take over the `node_id` before its owner. Node keys are KEM keys (X25519 + ML-KEM-768), not
signature keys, so the proof is a **challenge** that only the holder of the private key can open (`oneqpop.py`):

1. The node requests `POST /v1/c/<community>/nodes/<id>/challenge` (point-to-point mode: `POST /v1/nodes/<id>/challenge`) with the public key.
2. The server encapsulates ML-KEM to the node's key, performs an ephemeral-static X25519 exchange and seals a secret `R = HMAC(server_key, nonce | exp | node_id)`. It is **stateless**:
   in a federation, `server_key` is derived from the shared secret, so any relay verifies a challenge issued by another.
3. The node opens the challenge and answers with `HMAC(R, "proof" | node_id | nonce | exp)`, sent in the `PUT` as `pop` (valid for 60 s and reused until close to expiry).

Rules: a node registered once with a proof **can no longer be updated without a proof** (this also protects against downgrade); `--require-pop` (`require_pop = yes`) refuses any
registration without a proof; an administrator can reset a `node_id` by deleting the node. In point-to-point mode, the WebSocket relay slot of a verified node also requires the proof
(`X-Oneq-Pop`). A relay that does not know the challenge answers 404, and the node falls back to a plain registration (compatibility). The proof does not cover the rest of the request: it defends against whoever does **not** have the key, not against an
attacker who reads the TLS stream. The Rust and Python clients implement the same protocol. The `oneqrelay` package depends on `cryptography` (ML-KEM).

## Nodes behind NAT

*English version of this section: [NAT.md](NAT.md).*

Any node reaches anyone through the relay (WebSocket, always attached). The direct UDP path is obtained in addition, if the NATs allow it.

**What `oneqrelay` does.** It starts a STUN service by default (RFC 5389, with a port `CHANGE-REQUEST` as in RFC 5780) on **three UDP ports**
of the listen address: the `listen` port, +1 and +2 (`stun`, `stun_port`, `stun_alt_port`, `stun_change_port` in `relay.conf`; they must be
open in the firewall). It can also test whether a node accepts unsolicited packets: `POST /v1/c/<community>/nodes/<id>/nat-test`
sends a Binding request from a port the node has never contacted (only to the caller's public address;
loopback/link-local/multicast are refused; one probe per 5 s per node).

**What the node does** (`oneqnode`, the Rust client, the apps): three STUN transactions from the same UDP socket it uses for traffic:
1. main port -> public address M1 (no answer = `blocked`);
2. alternate port -> M2; M2 != M1 => the mapping depends on the destination => `symmetric`;
3. main port with change-port => the answer comes from the third, uncontacted port: if it arrives => `cone`, otherwise `port-restricted`
   (local address = M1 => `open`, no NAT).
The result (type, public address, "inbound") appears in the registry, in the administration page and in the apps; the public address becomes
a candidate for the others (not for `symmetric`: the port changes with the destination). It is measured again every 5 min or when the mapping changes.
`oneqnode nat-check HOST:PORT` shows the result without joining the community.

**Which pairs connect directly**

| | open | cone | port-restricted | symmetric |
|---|---|---|---|---|
| **open** | direct | direct | direct | direct |
| **cone** | direct | direct | direct | direct |
| **port-restricted** | direct | direct | direct | relay |
| **symmetric** | direct | direct | relay | relay |

"Relay" pairs do not wait 10 s: the nodes know in advance that it cannot work and go straight to the relay (traffic works the same).
The table is the baseline; four mechanisms change it (sections below): mapping a port on the router, port prediction, the second NAT and IPv6.

| Situation | Rule |
|---|---|
| symmetric with a predictable port step (`delta`) versus port-restricted | direct (the other end probes the predicted ports) |
| symmetric versus symmetric, **both** with `delta` | direct |
| one side with a second NAT (`cgnat`) | immediate relay, unless the other end is `open` |
| both sides have global IPv6 | always tried directly (there is no translation, only a stateful firewall) |
| router mapping verified from the outside | published as `open` |

**Hole punching synchronization.** Between two filtering NATs, a packet that reaches a NAT *before* that NAT has
sent anything "poisons" the connection table (netfilter: the next mapping moves to another port) and retransmission keeps it alive. That is why
the two nodes send unsolicited packets only in **rounds** aligned to the relay's clock (measured at each registration,
error <= half the RTT): every 4 s, in the first 3 rounds out of 10 (the ~32 s of silence lets the failed state expire), in bursts of 4
packets. When a packet arrives from the other end, the "hole" is used immediately (INIT or probe), towards that address and only towards IPs
registered by it (a spoofed address does not trigger a 2 KB handshake towards a third party). Between an `open`/`cone` node and anyone, the
earlier continuous attempts are kept.

**Tests** (`test_nat_sim.py`, as root on Linux with simulated real NATs: namespaces + nftables, 15 ms latency on each link):
classification for open, port-restricted (`masquerade`), symmetric (`masquerade random`), cone (static SNAT/DNAT) and blocked UDP;
node pairs: port-restricted <-> port-restricted (the hard case), port-restricted <-> cone, symmetric <-> cone, open <-> symmetric
connect directly, symmetric <-> port-restricted goes straight to the relay; the same cases between the **Rust client** (compiled for Linux with Zig)
and the Python node, in both role orders, plus Rust <-> Rust. Without latency (0.1 ms) two Linux NATs "poison" each other
(a lab artifact: on the internet latency separates the packets), which is why the test requires `tc netem`.

**Automatically opening a port on the router (PCP, NAT-PMP, UPnP).** If the NAT is not `open`, the node asks the home router to
forward the node's UDP port: first PCP (RFC 6887, UDP 5351 on the gateway), then NAT-PMP (RFC 6886), then UPnP IGD (SSDP discovery,
`AddPortMapping` over SOAP; `oneqportmap.py` and `client/core/src/portmap.rs`, same logic). The mapping is renewed at half its lifetime and
removed on shutdown. The node **does not claim** to be open based on the router's answer: it asks the relay to probe the mapping's external address from an
uncontacted port (`nat-test`) and only if the answer arrives does it publish `open` (with `via: pcp|natpmp|upnp`); the other nodes then try the address directly,
without hole punching. A UPnP response is accepted only from a private/link-local address, with `LOCATION` and the control URL on the same address (a
spoofed response cannot send the node towards a third party), with bodies limited to 64 KB. To turn it off: `--no-port-mapping` (`port_mapping = no` in `node.conf`).

**The second NAT (CGNAT, one router behind another).** The node considers itself behind two NATs if the address seen by the relay is in
100.64.0.0/10 (RFC 6598) or if the router reports (NAT-PMP/PCP/UPnP) a different WAN address than the one seen by the relay. A mapping on the first router
would be useless (it is removed), the node publishes `cgnat: true`, and the pair goes **immediately through the relay**, unless the other end is `open`. If the
router answers no protocol, only the 100.64.0.0/10 case is visible; a CGNAT with public addresses cannot be recognized this way.

**Port prediction (symmetric NAT).** For a symmetric NAT the node makes a third STUN transaction, to the relay's "change" port (announced as
`stun.change_port`): three consecutive mappings with a constant step (`delta`, 1..64, or small positive steps) => sequential allocation. It publishes `delta` and the newest
mapping; the other end sends PUNCH also to `port + delta*k`, k = 1..16, in the synchronized rounds. Thus symmetric <-> port-restricted and
symmetric <-> symmetric (both with `delta`) no longer necessarily go through the relay. The method guesses: if the NAT served other flows between measurement and
punching, the target may be missed (the 16-port window covers part of that); it does not help with NATs that use random ports, which stay on the relay.

**IPv6.** The node's data socket is dual-stack (`::` with `IPV6_V6ONLY` off; falling back to IPv4 if the system cannot). A global IPv6 address
(2000::/3, chosen by the system for the internet, without sending any packet) is published as `[address]:port`, and the other nodes' IPv6 candidates are
tried the same way as IPv4 ones. Two nodes with global IPv6 skip the NAT rules (there is no translation, only a stateful firewall) and do not fall back to the relay for
NAT reasons. `--no-ipv6` (`ipv6 = no`) turns them off.

`oneqnode nat-check` also shows the port-allocation step and whether a second NAT exists. An `--advertise` address is verified by the relay: if it does not answer the
probe, the node prints a warning.


# Mode 2: point-to-point (oneqtunel)

Educational project, **without an independent cryptographic audit**.

- **Handshake:** X25519 + ML-KEM-768 (the ML-KEM secret before the X25519 one in each KDF), 2 messages:
  `INIT` 2329 B, `RESP` 2225 B, fragmented at the application level (<= 1200 B/datagram).
- **Data:** ChaCha20-Poly1305, 64-bit counter, anti-replay window of 1024. Rekey at 120 s, rejection at 180 s, keepalive at 25 s.
- **Discovery:** HTTPS rendezvous API (`rendezvous_server.py`), TLS 1.3 with X25519MLKEM768 **only**, no fallback.
- **Relay:** if there is no direct session after ~10 s, datagrams go opaquely through a WebSocket (`wss://.../v1/relay`). The tunnel returns to the direct path on its own (probe at 20 s).
- `LABEL`: `tunsec-pq/v1 ...` (the wire constant of point-to-point mode). Any protocol change gets a new version.

## Requirements

Python linked against **OpenSSL >= 3.5** (`python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"`), `/dev/net/tun`, `ip`.

```sh
python3 -m venv /opt/oneq-src/venv && /opt/oneq-src/venv/bin/pip install -r requirements.txt
/opt/oneq-src/venv/bin/python -c "from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey"
```

## Keys and public key exchange

```sh
oneqtunel.py genkey --key A.key          # writes A.key (0600) and A.key.pub (1216 B, base64); prints the node_id
```

Exchange the **`.pub` files** between the two nodes over a trusted channel. The rendezvous server is not trusted for identity, because the handshake authenticates the nodes by their static keys. `node_id = SHA-256(public key)[:16]`. The node with the smaller public key is the initiator.

## Token and server

```sh
python3 -c "import secrets;print(secrets.token_urlsafe(32))" > net.token && chmod 600 net.token   # the same on both nodes
python3 rendezvous_server.py hash-token < net.token >> /etc/oneq-p2p/tokens.sha256                   # the server keeps only the hash
```

Server with direct TLS (own certificate or Let's Encrypt):

```sh
rendezvous_server.py run --listen 0.0.0.0:8443 --cert fullchain.pem --key privkey.pem --tokens-file tokens.sha256
```

In production it is recommended behind nginx/Caddy (`deploy/`), with the server on `127.0.0.1:8080 --insecure-http --trust-proxy`.

## Starting a node

```sh
# token from a file (0600) or from the environment (TUNSEC_TOKEN). Never from the command line.
oneqtunel.py run --key A.key --peer B.key.pub --ifname pq0 --addr 10.99.0.1/24 \
   --listen 0.0.0.0:51820 --advertise 203.0.113.5:51820 \
   --rendezvous https://rv.example.org --token-file net.token [--cafile ca.pem] [--stun host:3478]
```

Requires `CAP_NET_ADMIN` (or a persistent TUN: `ip tuntap add dev pq0 mode tun user oneq-p2p`, then `--no-config`, in which case the node no longer needs privileges).
Without rendezvous (testing or fixed IPs): `--peer-endpoint IP:PORT`. Relay: `--force-relay`, `--no-relay`, `--relay-after SEC`.

## Binding to an interface (`--via`)

`--via IFACE` binds the UDP socket to the address of interface IFACE (for example of another existing tunnel). Its address is announced as an extra candidate. The interface is **held by the process that created it and cannot be shared**: the tunnel creates its **own** TUN interface (`--ifname pq0`), and traffic flows encapsulated through the other interface. The default MTU in this case is **1220** (1380 otherwise). It can be overridden with `--mtu`.

## Verifying post-quantum TLS

With an `openssl` >= 3.5:

```sh
openssl s_client -connect rv.example.org:443 -tls1_3 -groups X25519MLKEM768 -brief </dev/null   # must show: "Negotiated TLS1.3 group: X25519MLKEM768"
openssl s_client -connect rv.example.org:443 -tls1_3 -groups X25519          -brief </dev/null   # must fail (handshake_failure)
```

**The mechanism:** Python 3.13 has no `SSLContext.set_groups`, so `pqtls.py` sets `OPENSSL_CONF=pq_openssl.cnf` (TLS 1.3, `Groups = X25519MLKEM768`) *before* `import ssl`. The file is loaded only in our processes, not in the rest of the system. The client (`Rendezvous`, `RelayClient`) refuses any server that does not offer this group. On a proxy, the restriction is enforced with `ssl_ecdh_curve X25519MLKEM768` (nginx) or `curves x25519mlkem768` (Caddy).

## Production

`deploy/`: `oneq-p2p@.service` (user `oneq-p2p`, `CAP_NET_ADMIN` only here, key and token through `LoadCredential`), `oneq-p2p-rendezvous.service` (no capabilities), `nginx-rendezvous.conf`, `Caddyfile`, `node.env.example`.

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin oneq-p2p;  useradd --system ... oneq-p2p-rv
install -m600 A.key /etc/oneq-p2p/NAME.key;  install -m600 net.token /etc/oneq-p2p/NAME.token
cp deploy/node.env.example /etc/oneq-p2p/NAME.env && chmod 600 /etc/oneq-p2p/NAME.env   # edit ONEQ_P2P_ARGS
systemctl enable --now oneq-p2p@NAME
```

## Tests

```sh
python3 test_oneqtunel.py        # unit + TLS (openssl s_client) + API + relay + fragmentation, no root
python3 test_nginx_proxy.py      # real nginx (OpenSSL >= 3.5) in front of the server
sudo python3 test_e2e.py         # 2 real TUNs in namespaces: direct, forced relay, fallback + return; no plaintext on the wire
```

## Troubleshooting

| Symptom | Probable cause |
|---|---|
| `handshake failure` towards the rendezvous | the server/proxy does not offer X25519MLKEM768 (OpenSSL < 3.5) |
| `pqtls must be imported before ssl` | a module imports `ssl` before `pqtls` |
| `cannot import mlkem` | `cryptography` too old (>= 50.0.2 tested is required) |
| no session, no relay | wrong token (401), clocks skewed by more than 180 s (INIT rejected), UDP blocked and `--no-relay` |
| session only through the relay | symmetric NAT or firewall; check `--advertise` and the UDP ports |
| `private key must not be accessible...` | `chmod 600` on the key/token |
| TUN: `Operation not permitted` | missing `CAP_NET_ADMIN` (or a persistent TUN with `--no-config`) |
| MTU/loss with `--via` (encapsulation in another tunnel) | use `--mtu 1220` or smaller |

## Known limitations

- **Proof of possession of the node key** (see the section above, [POP.md](POP.md) in English): it prevents a token/account holder who does not have the private key from taking over a `node_id`.
  It does not defend against a compromised relay (which can delete a node and assign its address to another key) nor against an account holder who also has the key. Without
  `--require-pop`, a node that gives no proof is accepted and can be taken over.
- A single peer per node (point-to-point mode); for several peers, use mesh mode.
- Port prediction guesses (see "Nodes behind NAT"); a NAT with random ports, a CGNAT with public addresses and a symmetric NAT without a constant step stay on the relay.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 ad-go. Third-party components under `client/third_party` and the bundled
dependencies keep their own licenses. This is an educational project without an independent cryptographic audit; see [SECURITY.md](SECURITY.md).
