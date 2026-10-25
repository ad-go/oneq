# Mesh network architecture (oneqrelay + oneqnode)

Educational project, **without an independent cryptographic audit**.

The network is a virtual Ethernet network (L2, TAP) made of nodes (`oneqnode`), plus rendezvous and relay servers (`oneqrelay`) that federate with each other. It has **users with passwords**, **automatic IP/MAC allocation** and a **post-quantum** key exchange (X25519 + ML-KEM-768).

```
          federation (TLS 1.3, X25519MLKEM768, HMAC with the federation secret)
   oneqrelay r1 <=====================================> oneqrelay r2
      ^   ^  login, registration, member list, relay (wss)       ^
      |   +------------------+                                   |
   oneqnode A <---- direct UDP, end-to-end session (PQ) ----> oneqnode B ---- oneqnode C
```

## Roles

| Component | Role |
|---|---|
| `oneqrelay` | Registry of communities, accounts, nodes and addresses; WebSocket relay; federation with other oneqrelay instances. Cannot see the traffic. |
| `oneqnode` | Authenticates, receives IP/MAC, opens sessions with all members, switches Ethernet frames between the TAP device and the sessions. |
| `meshproto.py` | The `tunmesh-pq/v2` wire protocol: handshake, data, indexes. |
| `meshdb.py` | Replicated storage (SQLite), accounts, tokens, address allocation. |

The data plane goes directly between nodes (UDP, with hole punching) or, if that is not possible, through the relay. **If all oneqrelay instances go down, existing sessions continue**: only discovery and the arrival of new members need them.

## Trust model

- **oneqrelay instances are trusted for *membership***: who may join the community and which address they get. They are not trusted for confidentiality: they cannot see or decrypt the traffic.
- `node_id = SHA-256(public key)[:16]`, and nodes themselves verify this binding for every registry entry. A compromised oneqrelay can **add** members, but cannot replace the key of an existing node (that would change its `node_id`).
- The handshake authenticates both ends through static keys (X25519 + ML-KEM), not through a password. **The password is not an encryption key**: it grants access to the registry and the relay. That is why it can be changed or revoked without touching the sessions.
- Authentication between oneqrelay instances uses a shared federation secret (HMAC over method, path, body and time, 60 s window), over TLS with certificate verification.

## Accounts and authentication

- Each **community** has a subnet, MTU, node limit and users (`user` or `admin`, with a per-user node quota).
- Passwords are stored as **scrypt** (N=2^15, per-user salt) and replicated between oneqrelay instances. Minimum 8 characters.
- `POST /v1/login` returns a **signed token** (HMAC with the federation secret, 1 h), valid on any oneqrelay. The token contains a counter `tokgen`. On password change, deactivation or deletion, `tokgen` increases (or the account disappears), and all issued tokens become invalid **across the whole federation** as soon as the change replicates. The role is not read from the token but from the account.
- Attack protection: rate limit, lockout after 5 failures per address and per account, with the time doubling at each lockout (60 s ... 15 min), and a "fake" password check for nonexistent accounts (the response is just as slow).
- A node belongs to the user who registered it. Another (non-admin) user cannot take over its `node_id` and cannot attach a relay for it.

## Automatic address allocation

- IP: from the community subnet, chosen deterministically from `SHA-256(node_id)` with linear probing over the taken addresses. **Sticky**: the node keeps its address as long as the registration exists.
- MAC: `02:` + 5 bytes from `SHA-256(node_id)` (locally administered, unicast), with a salt on collision.
- Two oneqrelay instances may allocate the same address simultaneously (partition or race). After replication, the record with the lowest `(alloc_ts, node_id)` keeps the address, and the losing one is reallocated by the oneqrelay that wrote it (or by any of them after 30 s). The node picks up the new address at its next renewal.
- A community's subnet can be changed (`oneqrelay admin community-subnet COMMUNITY SUBNET`): each node gets a new address in it (with the same rule, older nodes first), while MACs, keys and routes stay,
  and nodes pick up the address when they register again (on restart). It is refused if the new subnet is too small for the nodes or covers a route.

## Replication and federation

- Storage: records `(kind, key) -> JSON` with a **hybrid logical clock**; the higher `(ts, origin)` wins (**last writer wins**). Deletions are tombstones. Presence (endpoints, relay attachment) has a TTL of 90 s.
- Kinds: `comm` (community), `user`, `node`, `pres` (endpoints), `rel` (which oneqrelay the node's relay is attached to).
- **Anti-entropy** on a per-peer cursor, over the local change counter `lseq` (not on a version vector): it works over multiple hops, in any order, without losses. An `epoch` detects a peer whose database was wiped, and the cursor is reset. A `poke` after each change triggers immediate synchronization; otherwise, once every 5 s.
- **Relaying between oneqrelay instances:** if the destination is attached to another oneqrelay (from `rel`), the frame goes through a WebSocket link between the two (a single hop, no loops).
- **Failover:** `oneqnode` receives a list of oneqrelay instances; on error it moves to the next one, renews its token and reconnects the relay.

## Data plane (L2)

- Each node keeps sessions with all members (full mesh; small networks). Initiator: the node with the lower public key.
- **Switching:** unicast to a known MAC goes to a single peer; broadcast, multicast and unknown unicast are sent to all. Registered MACs are static; MACs behind a node (bridge) are learned from received frames and expire after 5 min. A member cannot use another member's MAC (the frame is dropped). There is no transit: a frame received from one peer is not forwarded to another, so no loops appear.
- **Paths:** direct (UDP) is preferred. Each node stays **attached at all times** to a oneqrelay (WebSocket), so that it can be reached through the relay at any moment; otherwise a peer sending through the relay to a node with which it has a direct session would lose packets. The handshake also goes through the relay for a peer with no direct session after 10 s, and data goes through the relay when the direct path becomes inactive (75 s without packets). On the relay, a probe every 20 s tries the direct path and switches back by itself.

## The `tunmesh-pq/v2` wire protocol

The messages (formal specification: [specifications.html](specifications.html)):

| Message | Format | Role |
|---|---|---|
| INIT `0x21` (2349 B) | `type, idx_i(4), node_id_i(16), E_i, ek_e, ct_sr, AEAD(ts)` | the responder picks the peer's key from the registry by `node_id`, without decryption attempts; the header is part of the transcript |
| RESP `0x22` (2233 B) | `type, idx_r(4), idx_i(4), E_r, ct_e, ct_si, AEAD("")` | indexes for demultiplexing |
| DATA `0x23` | `type, receiver_idx(4), counter(8), ChaCha20-Poly1305` | one socket serves many sessions; the 13 B header is the AAD |

Common parameters: secret ordering (ML-KEM before X25519), fragmentation at 1200 B (`0x15`), anti-replay window of 1024, rekey at 120 s, rejection at 180 s, keepalive at 25 s. **PUNCH `0x14`** (17 B: type + `node_id`) is sent every 1 s while a node has no session with a peer: it opens the NAT and, if the peer is the initiator and believes it has an established session, makes it redo the handshake immediately (limit: once every 5 s per peer, only for sessions older than 3 s); without it, a node that cannot initiate (its key is the last one) would stay unreachable until the session is renewed. Ethernet frames are at least 14 B, so the 1-byte payloads (`0x00` probe, `0x01` reply) cannot be confused with a frame.

## Post-quantum TLS

The client API, the relay and the federation run on TLS 1.3 with **only** X25519MLKEM768, through a dedicated `OPENSSL_CONF` (`pq_openssl.cnf`, set by `pqtls.py` before `import ssl`) or through a reverse proxy with the same restriction (`deploy/nginx-oneqrelay.conf`). Let's Encrypt certificates are classical: only the key exchange is post-quantum.

## Known limitations

- Full mesh (n^2 sessions): designed for tens of nodes, not thousands.
- There is no member approval by an admin (any valid account with a quota can add its own nodes).
- Replication is "eventually consistent": after a change, a password change or a revocation can take a few seconds on another oneqrelay (tokens already verified there stay valid until synchronization).
- The SQLite databases are not encrypted; the file contains the password hashes.

## Administration page (oneqadmin)

`oneqadmin.py` + `oneqadmin.html` are loaded by `oneqrelay` only if `admin_password_file` exists. The `/admin/` (the page) and
`/admin/api/*` (JSON) routes use an operator token separate from the community tokens (different HMAC prefix, different format), so an
`admin` account in a community cannot administer the relay. Operations write to the same replicated registry (`meshdb.Registry`:
`users`, `update_community`, cascading `delete_community`, `update_user`), and peers added from the page are kept in the local
`meta` table (`fed_extra`, not replicated: the federation topology remains each operator's decision). The page's rate limiter
is separate from the client API's (key per address and a cap), so that they do not influence each other.

## Routes through a gateway node

An administrator can announce a private network (e.g. `192.0.2.0/24`) as reachable through a member, the **gateway**: `oneqrelay admin route-add oneq 192.0.2.0/24 m`, the API `PUT /v1/c/<comm>/routes/192.0.2.0_24`
`{"via": "<node id>"}` or the "Routes" section of the administration page. The registry keeps `route` records (`<comm>/<network>_<prefix>` -> `{cidr, via, by}`), replicated like all the others; the member list (`GET /nodes`) includes them as `routes`.
A route disappears together with the gateway node. Rules: IPv4, prefix at least /8, must not overlap the community subnet, no loopback/multicast/link-local, at most 64 per community.

The Rust client with `--accept-routes` (off by default) accepts only **private** networks (RFC 1918 and 100.64/10) outside the mesh, regardless of what the relay announces: a relay is trusted for membership, not for steering your traffic.
`l3.rs` sends the IP packet to the gateway's MAC (longest prefix match; the packet stays unchanged, only the frame has a different MAC), and `routes_os.rs` installs the route in the system on the TUN interface (`netsh` / `ip` / `route`) and removes it when
it is withdrawn or when the node stops. Replies come back as ordinary packets to our address in the mesh. The gateway is an ordinary node with `ip_forward` and NAT (`deploy/oneq-gateway`): without NAT, the hosts in the network do not know how to reply to 10.0.0.0/24.
The script allows only the announced network (`FORWARD ... DROP` for the rest) and fixes the MSS (the mesh MTU is smaller).

**Redundancy.** The same network can be announced through up to 4 gateways (`route-add ... --prio N`, lower = preferred; one `route` record per network + gateway pair, key `<comm>/<network>_<prefix>/<node id>`).
For each network, the client picks the gateway with the best priority **among those that respond** (`l3.rs`: established session and a packet received in the last 45 s; not presence in the registry, which expires only after 90 s),
stays on it as long as it responds (no automatic return to the preferred one, so as not to move the connections that pass through its NAT) and moves to the next when it goes silent; if none responds, it keeps trying the preferred one.
The system route (`routes_os.rs`) points to the preferred gateway (the next hop does not matter: the L3 adapter sets the MAC from the destination address); the status shows the preferred gateway and the standbys.
Limitations: a gateway that is alive in the mesh but has no exit to the network is not detected, there is no load balancing, on Android the networks are added to the VpnService interface (rebuilt when the list changes), Python TAP nodes do not install routes, a Rust client cannot be a gateway.

## Nodes delegated as relays (L1)

A member of a community can be **delegated by an administrator to relay packets for the other members** when they cannot reach each other directly
(symmetric NAT, UDP blocked between them). The delegated node receives no secret (neither the federation secret nor passwords) and does not see the traffic: it relays packets that are already
encrypted end to end.

* **Registry:** the record kind `dlg` (`<community>/<node id>` -> `{by, max_kbps, exp}`), replicated like all the others; revocation is a tombstone.
  The node must have offered itself (`relay_offer = yes` -> the `offer` field in its record) and granting requires the NAT test to show it reachable from outside
  (`open` or `cone`), unless `force` is used. The member list has `offer`, `relay_role` (the quota in kbit/s, only if the offer is in force and the delegation has not expired) and `relays`
  (the delegated nodes with which the member has a session, published at each registration). API: `GET/PUT/DELETE /v1/c/<comm>/relays[/<nid>]` (writes only for administrators),
  the admin page (the "Delegate..." button on a node), `oneqrelay admin relay-grant|relay-revoke`. A relay ignores the record kinds it does not know (`dlg`, `route`): update the whole federation before using a new feature.
* **Data plane:** new packet `M_RLY = 0x24`, with the header, keys and counter of the ordinary session (authenticated by the same AEAD); the content is an operation between a member and
  the delegated node: `FWD dst(16)|datagram`, `DLV src(16)|datagram`, `NACK dst(16)|reason`. The member's authentication toward the delegated node is the very
  hybrid X25519 + ML-KEM session between them (the delegated node is in the registry), so there are no tokens to verify. The `src` label in `DLV` is set by the delegated node from the session identity
  (not from the message); the datagram stays protected by the session between the two members, so a false label only produces a rejected packet. A single hop, no transit.
* **Selection:** the direct path remains preferred. For "relay", a node picks, for each destination, the delegated node with which **both** have a session (from `relays`) and
  with the lowest RTT (probe every 10 s through the session), otherwise `oneqrelay` (WebSocket). A delegated node is used only while it has a fresh direct path (< 40 s; keepalive 25 s).
  A `NACK` (destination not attached) excludes it for 30 s for that destination. The handshake and the data take the same path.
* **Limits:** token bucket on the total (the quota from the registry) and per sender (half), datagrams of at most 1600 B, `NACK` at most once per second and pair; a node
  that is not entitled (no delegation in the registry) ignores `FWD`, and `DLV`/`NACK` are accepted only from the nodes that the registry lists as delegated.
* **Implementations:** `oneqnode.py` and the Rust client (`engine.rs`: the selection is computed at every tick in `Io.rly`, and the send functions put the packet in a queue from which the engine
  sends it after the event). Tests: registry/API/admin, the in-memory data plane (Python), the Rust engine and the Linux NAT lab (`test_nat_sim.py`: symmetric + port-restricted through a
  Python or Rust delegated node, Python or Rust members).

## Second factor of the administration page (oneqtotp)

`oneqtotp.py` implements TOTP (HMAC-SHA1, 6 digits, 30 s, +/-1 window) and `TotpStore`: a mode 600 JSON file with the secret (160 bits, base32), the hashes of 10
recovery codes and the last accepted step. `oneqadmin.AdminUI.h_login` verifies the password first and only then consumes the code (in an executor: writing the file
does not block the event loop); a single error message for both factors; the same lockout keys (`LoginGuard`) as for the password. Tested with the vectors from
RFC 6238, with code reuse, recovery codes, lockout and the case where the state cannot be saved (code refused).

## Proof of possession (oneqpop)

`oneqpop.py` (self-contained: only `cryptography`) contains the server's stateless challenge (`make_challenge`, `verify`), the node's response (`answer`, `Prover` with a cache) and
the server key derived from the federation secret. `oneqrelay.h_challenge` and `h_put_node` (the `pop` field; `meshdb.join_node(..., verified)` keeps `pop: true` in the node record,
which is replicated; without proof, a marked node is not updated), `rendezvous_server` (same scheme, plus `X-Oneq-Pop` when attaching to the relay), the Python client (`oneqnode.Control._pop`,
`oneqtunel.Rendezvous.proof`) and the Rust one (`wire.rs::Identity::pop_answer`, `control.rs::pop_proof`). Description: README, "Proof of possession of the node key"; see also POP.md.

## NAT (oneqnat)

*See also: [NAT.md](NAT.md).*

`oneqnat.py` contains the STUN codec (RFC 5389 + change-port), the server (three UDP sockets in `oneqrelay`), the classification, the
`can_punch` rule and the reachability probe; the Rust client has the same logic in `client/core/src/nat.rs` (the same constants and the same RFC 5769
test vector). The registry keeps `nat` in the presence record (`{type, mapped, inbound}` plus, when present, `delta` (allocation step
of a symmetric NAT, +/-1..64), `cgnat` (the second NAT) and `via` (`pcp|natpmp|upnp`); replicated, with a TTL; the relay does not let other keys through).
`can_punch` takes prediction and the second NAT into account (`oneqnat.py`, `nat.rs::can_punch_ex`); `oneqportmap.py` / `portmap.rs` talk to the router;
`info.stun` also contains `change_port`. The filtering test
comes from a port that the nodes never send from: otherwise the NAT would let the reply through, and an extra unsolicited packet
would shift the next mapping (see README, "Nodes behind NAT"). The punching rounds follow a pattern driven by the relay's clock
(`PUNCH_PERIOD`, `PUNCH_CYCLE`, `PUNCH_ATTEMPTS`, `PUNCH_OFFSETS`), identical in Python and Rust; without a measured clock the node tries
continuously.
