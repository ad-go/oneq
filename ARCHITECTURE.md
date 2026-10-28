# Mesh network architecture (oneqrelay + oneqnode)

Educational project, **without an independent cryptographic audit**.

The network is a virtual Ethernet network (L2, TAP) made up of nodes (`oneqnode`), plus rendezvous and relay servers (`oneqrelay`) that federate with each other. It has **users with passwords**, **automatic IP/MAC allocation** and a **post-quantum** key exchange (X25519 + ML-KEM-768).

```
          federation (TLS 1.3, X25519MLKEM768, HMAC with federation secret)
   oneqrelay r1 <=====================================> oneqrelay r2
      ^   ^  login, registration, member list, relay (wss)   ^
      |   +------------------+                               |
   oneqnode A <---- UDP direct, end-to-end session (PQ) ----> oneqnode B ---- oneqnode C
```

## Roles

| Component | Role |
|---|---|
| `oneqrelay` | Registry of communities, accounts, nodes and addresses; WebSocket relay; federation with other oneqrelay instances. Does not see traffic. |
| `oneqnode` | Authenticates, receives IP/MAC, opens sessions with all members, switches Ethernet frames between TAP and sessions. |
| `meshproto.py` | Wire protocol `tunmesh-pq/v2`: handshake, data, indices. |
| `meshdb.py` | Replicated storage (SQLite), accounts, tokens, address allocation. |

The data plane goes directly between nodes (UDP, with hole punching) or, if not possible, through the relay. **If all oneqrelay instances go down, existing sessions continue**: only discovery and new member entry need them.

## Trust model

- **oneqrelay instances are trusted for *membership***: who can join the community and what address they get. They are not trusted for confidentiality: they do not see and cannot decrypt traffic.
- `node_id = SHA-256(public key)[:16]`, and nodes verify this binding themselves for each registry entry. A compromised oneqrelay can **add** members, but cannot replace the key of an existing node (that would change the `node_id`).
- The handshake authenticates both ends by static keys (X25519 + ML-KEM), not by password. **The password is not a cryptographic key**: it opens access to the registry and the relay. That is why it can be changed or revoked without affecting sessions.
- Authentication between oneqrelay instances uses a shared federation secret (HMAC over method, path, body and time, 60 s window), over TLS with certificate verification.

## Accounts and authentication

- Each **community** has a subnet, MTU, node limit and users (`user` or `admin`, per-user node quota).
- Passwords are stored as **scrypt** (N=2^15, per-user salt) and replicated between oneqrelay instances. Minimum 8 characters.
- `POST /v1/login` returns a **signed token** (HMAC with federation secret, 1 h), valid on any oneqrelay. The token contains a `tokgen` counter. On password change, disable or delete, `tokgen` increases (or the account disappears), and all issued tokens become invalid **across the entire federation**, as soon as the change replicates. The role is not read from the token, but from the account.
- Attack protection: rate limit, lockout after 5 failures per address and per account, with doubled time on each lockout (60 s … 15 min), "dummy" password verification for non-existent accounts (same slow response).
- A node belongs to the user who registered it. Another user (non-admin) cannot take over a `node_id` and cannot attach a relay for it.

## Automatic address allocation

- IP: from the community's subnet, chosen deterministically from `SHA-256(node_id)` with linear probing over taken addresses. **Sticky**: the node keeps its address as long as the registration exists.
- MAC: `02:` + 5 bytes from `SHA-256(node_id)` (locally administered, unicast), with salt if collision.
- Two oneqrelay instances can allocate the same address simultaneously (partition or race). After replication, the registration with the smallest `(alloc_ts, node_id)` keeps the address, and the losing one is reallocated by the oneqrelay that wrote it (or by any after 30 s). The node picks up the new address on next renewal.
- A community's subnet can be changed (`oneqrelay admin community-subnet COMMUNITY SUBNET`): each node gets a new address in it (with the same rule, older nodes first), MACs, keys and routes remain, and nodes pick up the address when they register again (on restart). Rejected if the new subnet is too small for nodes or covers a route.

## Replication and federation

- Storage: `(kind, key) -> JSON` records with a **hybrid logical clock**; larger `(ts, origin)` wins (**last writer wins**). Deletions are tombstones. Presence (endpoints, relay attachment) has a 90 s TTL.
- Types: `comm` (community), `user`, `node`, `pres` (endpoints), `rel` (which oneqrelay the node's relay is attached to).
- **Anti-entropy** on a per-peer cursor, over the local change counter `lseq` (not on a version vector): works over multiple hops, in any order, without loss. An `epoch` detects a peer with a wiped database, and the cursor resets. A `poke` after each change triggers immediate synchronization; otherwise, once every 5 s.
- **Relay between oneqrelay instances:** if the destination is attached to another oneqrelay (from `rel`), the frame passes through a WebSocket link between the two (a single hop, no loops).
- **Failover:** `oneqnode` gets a list of oneqrelay instances; on error it switches to the next, refreshes its token and reconnects the relay.

## Data plane (L2)

- Each node maintains sessions with all members (full mesh; small networks). Initiator: the node with the smaller public key.
- **Switching:** unicast to a known MAC goes to a single peer; broadcast, multicast and unknown unicast are sent to all. Registered MACs are static; MACs behind a node (bridge) are learned from received frames and expire after 5 min. A member cannot use another member's MAC (the frame is dropped). No transit: a frame received from a peer is not forwarded to another, so no loops.
- **Paths:** direct (UDP) preferred. Each node stays **attached at all times** to a oneqrelay (WebSocket), so it can always be reached via relay; otherwise a peer sending via relay to a node with a direct session would lose packets. The handshake also goes through the relay for a peer with no direct session after 10 s, and data goes through the relay when the direct path becomes inactive (75 s without packets). On the relay, a probe every 20 s tries the direct path and switches back automatically.

## Wire protocol `tunmesh-pq/v2`

Messages (formal specification: [specifications.html](specifications.html)):

| Message | Format | Role |
|---|---|---|
| INIT `0x21` (2349 B) | `type, idx_i(4), node_id_i(16), E_i, ek_e, ct_sr, AEAD(ts)` | responder looks up the peer's key from the registry by `node_id`, without decryption attempts; the header enters the transcript |
| RESP `0x22` (2233 B) | `type, idx_r(4), idx_i(4), E_r, ct_e, ct_si, AEAD("")` | indices for demultiplexing |
| DATA `0x23` | `type, receiver_idx(4), counter(8), ChaCha20-Poly1305` | one socket serves many sessions; the 13 B header is AAD |

Common parameters: secret order (ML-KEM before X25519), fragmentation at 1200 B (`0x15`), anti-replay window of 1024, rekey at 120 s, rejection at 180 s, keepalive at 25 s. **PUNCH `0x14`** (17 B: type + `node_id`) is sent every 1 s while a node has no session with a peer: opens the NAT and, if the peer is the initiator and believes it has an established session, makes it immediately redo the handshake (limit: once every 5 s per peer, only for sessions older than 3 s); without it, a node that cannot initiate (its key is last) would remain unreachable until session renewal. Ethernet frames are at least 14 B, so 1-byte payloads (`0x00` probe, `0x01` response) cannot be confused with a frame.

## Post-quantum TLS

The client API, the relay and the federation run on TLS 1.3 with **only** X25519MLKEM768, via a dedicated `OPENSSL_CONF` (`pq_openssl.cnf`, set by `pqtls.py` before `import ssl`) or via a reverse proxy with the same restriction (`deploy/nginx-oneqrelay.conf`). Let's Encrypt certificates are classical: only the key exchange is post-quantum.

## Known limitations

- Full mesh (n² sessions): designed for tens of nodes, not thousands.
- No admin approval for members (any valid account with quota can add nodes).
- Replication is "eventually consistent": after a change, a password change or a revocation may take a few seconds to reach another oneqrelay (tokens already verified there remain valid until synchronization).
- SQLite databases are not encrypted; the file contains password hashes.

## Admin page (oneqadmin)

`oneqadmin.py` + `oneqadmin.html` are loaded by `oneqrelay` only if `admin_password_file` exists. Routes `/admin/` (page) and
`/admin/api/*` (JSON) use an operator token separate from community tokens (different HMAC prefix, different format), so an
`admin` account in a community cannot administer the relay. Operations write to the same replicated registry (`meshdb.Registry`:
`users`, `update_community`, `delete_community` in cascade, `update_user`), and peers added from the page are stored in
the local `meta` table (`fed_extra`, not replicated: federation topology remains each operator's decision). The page's rate limiter is separate from the client API's (key per address and ceiling), so they don't affect each other.

## Routes through a gateway node

An administrator can announce a private network (e.g. `192.168.16.0/24`) as accessible through a member, the **gateway**: `oneqrelay admin route-add oneq 192.168.16.0/24 m`, API `PUT /v1/c/<comm>/routes/192.168.16.0_24`
`{"via": "<node id>"}` or the "Routes" section on the admin page. The registry keeps `route` records (`<comm>/<network>_<prefix>` → `{cidr, via, by}`), replicated like all others; the member list (`GET /nodes`) includes them as `routes`.
A route disappears when the gateway node disappears. Rules: IPv4, prefix at least /8, does not overlap the community subnet, not loopback/multicast/link-local, at most 64 per community.

The Rust client with `--accept-routes` (default off) accepts only **private** networks (RFC 1918 and 100.64/10) outside the mesh, regardless of what the relay announces: a relay is trusted for membership, not for routing your traffic.
`l3.rs` sends the IP packet to the gateway's MAC (longest prefix match; the packet stays unchanged, only the frame has a different MAC), and `routes_os.rs` installs the route in the system on the TUN interface (`netsh` / `ip` / `route`) and removes it when it is withdrawn or the node stops. Responses come as normal packets to our mesh address. The gateway is an ordinary node with `ip_forward` and NAT (`deploy/oneq-gateway`): without NAT, hosts in the network don't know how to reply to 10.78.0.0/24.
The script only allows the announced network (`FORWARD ... DROP` for the rest) and corrects the MSS (the mesh MTU is smaller).

**Redundancy.** The same network can be announced through up to 4 gateways (`route-add ... --prio N`, smaller = preferred; one `route` record per network + gateway pair, key `<comm>/<network>_<prefix>/<node id>`).
The client chooses, for each network, the gateway with the best priority **among those that respond** (`l3.rs`: session established and a packet received in the last 45 s; not registry presence, which expires only at 90 s),
stays on it as long as it responds (no automatic fallback to the preferred one, to avoid moving connections that pass through its NAT) and switches to the next when it goes silent; if none responds, it tries the preferred one again.
The system route (`routes_os.rs`) points to the preferred gateway (next hop doesn't matter: the L3 adapter puts the MAC by destination address); status shows the preferred gateway and backups.
Limitations: a gateway alive in the mesh but without access to the network is not detected, no load sharing, on Android networks are added to the VpnService interface (rebuilt when the list changes), Python TAP nodes don't install routes, a Rust client cannot be a gateway.

## Delegated relay nodes (L1)

A community member can be **delegated by an administrator to relay packets for other members** when they cannot reach each other directly
(symmetric NAT, UDP blocked between them). The delegated node receives no secret (neither the federation secret nor passwords) and does not see traffic: it relays already end-to-end encrypted packets.

* **Registry:** record type `dlg` (`<community>/<node id>` → `{by, max_kbps, exp}`), replicated like all others; revocation is a tombstone.
  The node must have offered itself (`relay_offer = yes` → the `offer` field in its registration) and granting requires the NAT test to show it as reachable from outside
  (`open` or `cone`), except with `force`. The member list has `offer`, `relay_role` (kbit/s quota, only if the offer is active and the delegation hasn't expired) and `relays`
  (delegated nodes with which the member has a session, published on each registration). API: `GET/PUT/DELETE /v1/c/<comm>/relays[/<nid>]` (writes only for administrators),
  admin page ("Delegate…" button on a node), `oneqrelay admin relay-grant|relay-revoke`. A relay ignores record types it doesn't know (`dlg`, `route`): update the entire federation before using a new feature.
* **Data plane:** new packet `M_RLY = 0x24`, with the header, keys and counter of the regular session (authenticated by the same AEAD); the payload is an operation between a member and
  the delegated node: `FWD dst(16)|datagram`, `DLV src(16)|datagram`, `NACK dst(16)|reason`. The member's authentication to the delegated node is the hybrid X25519 + ML-KEM session itself between them (the delegated node is in the registry), so there are no tokens to verify. The `src` label in `DLV` is put by the delegated node from the session identity
  (not from the message); the datagram remains protected by the session between the two members, so a fake label produces only a rejected packet. A single hop, no transit.
* **Selection:** the direct path remains preferred. For "relay" a node chooses, for each destination, the delegated node with which **both** have a session (from `relays`) and
  with the lowest RTT (probe every 10 s through the session), otherwise `oneqrelay` (WebSocket). A delegated node is used only while it has a fresh direct path (< 40 s; keepalive 25 s).
  A `NACK` (destination not attached) excludes it for 30 s for that destination. Handshake and data go through the same path.
* **Limits:** token bucket on total (registry quota) and per sender (half), datagrams at most 1600 B, `NACK` at most once per second and pair; a node without entitlement (no delegation in registry) ignores `FWD`, and `DLV`/`NACK` are accepted only from nodes the registry lists as delegated.
* **Implementations:** `oneqnode.py` and the Rust client (`engine.rs`: selection computed on every tick in `Io.rly`, sending functions put the packet in a queue from which the engine sends it after an event). Tests: registry/API/admin, in-memory data plane (Python), Rust engine and Linux NAT lab (`test_nat_sim.py`: symmetric + port-restricted through Python or Rust delegated node, Python or Rust members).

## Admin page second factor (oneqtotp)

`oneqtotp.py` implements TOTP (HMAC-SHA1, 6 digits, 30 s, ±1 window) and `TotpStore`: a mode 600 JSON file with the secret (160 bits, base32), hashes of 10
recovery codes and the last accepted step. `oneqadmin.AdminUI.h_login` verifies the password first and only then consumes the code (in an executor: writing the file
doesn't block the event loop); a single error message for both factors; same lockout keys (`LoginGuard`) as for the password. Tested with
RFC 6238 vectors, with code reuse, recovery codes, lockout and the case where state cannot be saved (code rejected).

## Proof of possession (oneqpop)

`oneqpop.py` (standalone: only `cryptography`) contains the server's stateless challenge (`make_challenge`, `verify`), the node's response (`answer`, `Prover` with cache) and
the server key derived from the federation secret. `oneqrelay.h_challenge` and `h_put_node` (the `pop` field; `meshdb.join_node(..., verified)` keeps `pop: true` in the node's registration,
replicated; without proof, a marked node is not updated), `rendezvous_server` (same scheme, plus `X-Oneq-Pop` on relay attachment), Python client (`oneqnode.Control._pop`,
`oneqtunel.Rendezvous.proof`) and Rust client (`wire.rs::Identity::pop_answer`, `control.rs::pop_proof`). Description: README, "Node key proof of possession"; English: POP.md.

## NAT (oneqnat)

*English version: [NAT.md](NAT.md).*

`oneqnat.py` contains the STUN codec (RFC 5389 + change-port), the server (three UDP sockets in `oneqrelay`), classification, the
`can_punch` rule and the reachability probe; the Rust client has the same logic in `client/core/src/nat.rs` (same constants and same
RFC 5769 test vector). The registry keeps `nat` in the presence record (`{type, mapped, inbound}` plus, when present, `delta` (port allocation
step of a symmetric NAT, ±1..64), `cgnat` (second NAT) and `via` (`pcp|natpmp|upnp`); replicated, with TTL; the relay does not pass through other keys).
`can_punch` accounts for prediction and the second NAT (`oneqnat.py`, `nat.rs::can_punch_ex`); `oneqportmap.py` / `portmap.rs` talk to the router;
`info.stun` also contains `change_port`. The filtering test comes from a port that nodes never send to: otherwise the NAT would let the response through, and an extra unsolicited packet would move the next mapping (see README, "Hole punching synchronization"). Punching rounds are a pattern of the relay clock
(`PUNCH_PERIOD`, `PUNCH_CYCLE`, `PUNCH_ATTEMPTS`, `PUNCH_OFFSETS`), identical in Python and Rust; without a measured clock the node tries continuously.
