# NAT traversal (English)

English version of the section "Noduri în spatele NAT" of `README.md` and of "NAT (oneqnat)" in `ARCHITECTURE.md` (both in Romanian), including the
four additions: router port mapping, IPv6, port prediction and second-NAT detection.

Any node reaches any other through the relay (WebSocket, always attached). A direct UDP path is obtained in addition when the NATs allow it.

## What `oneqrelay` does

It runs a STUN service by default (RFC 5389, with the port `CHANGE-REQUEST` of RFC 5780) on **three UDP ports** next to its listen address: `listen`, +1 and +2
(`stun`, `stun_port`, `stun_alt_port`, `stun_change_port` in `relay.conf`; open them in the firewall). The registry announces them in `info.stun`
(`port`, `alt_port`, `change_port`). The relay can also test whether a node accepts unsolicited packets: `POST /v1/c/<community>/nodes/<id>/nat-test` sends a
Binding request from a port the node never contacted (only to the caller's own public address; loopback, link-local and multicast are refused; one probe per 5 s per node).

## What the node does (`oneqnode`, the Rust client, the apps)

Three STUN transactions from the same UDP socket that carries the traffic:

1. main port -> public address M1 (no answer = `blocked`);
2. alternate port -> M2; M2 != M1 means the mapping depends on the destination, hence `symmetric`;
3. main port with change-port -> the answer comes from the third, never contacted port: if it arrives, `cone`, otherwise `port-restricted`
   (local address = M1 means `open`, no NAT).

The result (type, public address, "inbound") is shown in the registry, the admin page and the apps; the public address becomes a candidate for the others (not for
`symmetric`: the port changes with the destination). It is measured again every 5 minutes or when the mapping changes. `oneqnode nat-check HOST:PORT` shows the
result without joining a community (it also reports the port step of a symmetric NAT and whether a second NAT exists).

## Which pairs connect directly

Basic table:

| | open | cone | port-restricted | symmetric |
|---|---|---|---|---|
| **open** | direct | direct | direct | direct |
| **cone** | direct | direct | direct | direct |
| **port-restricted** | direct | direct | direct | relay |
| **symmetric** | direct | direct | relay | relay |

"relay" pairs do not wait 10 s: both nodes know in advance that it cannot work and use the relay at once (the traffic works the same). Four mechanisms change the
table (below): the router port mapping, port prediction, a second NAT, and IPv6.

| Situation | Rule |
|---|---|
| symmetric with a predictable port step (`delta`) against port-restricted | direct (the other side probes the predicted ports) |
| symmetric against symmetric, **both** with `delta` | direct |
| a side with a second NAT (`cgnat`) | relay at once, unless the other side is `open` |
| both sides have a global IPv6 address | always tried directly (no translation, only a stateful firewall) |
| a router mapping verified from outside | published as `open` |

## Synchronised hole punching

Between two filtering NATs, a packet that reaches a NAT *before* that NAT has sent anything "poisons" its connection table (netfilter: the next mapping moves to another port),
and retransmission keeps the failed entry alive. So the two nodes send unsolicited packets only in **rounds** aligned to the relay's clock (measured at every registration, error
at most half the RTT): every 4 s, in the first 3 rounds out of 10 (the ~32 s of silence lets the failed state expire), in bursts of 4 packets. When a packet from the other end arrives,
the "hole" is used at once (INIT or probe), towards that address and only towards IPs it registered (a forged address cannot trigger a 2 KB handshake towards a third party).
Between an `open`/`cone` node and anyone, the earlier continuous attempts remain.

## Automatic port mapping on the router (PCP, NAT-PMP, UPnP)

If the NAT is not `open`, the node asks the home router to forward the node's UDP port: PCP first (RFC 6887, UDP 5351 on the gateway), then NAT-PMP (RFC 6886), then UPnP IGD
(SSDP discovery, `AddPortMapping` over SOAP; `oneqportmap.py` and `client/core/src/portmap.rs`, same logic). The mapping is renewed at half its lifetime and deleted when the node stops.
The node **does not claim** to be open because the router said so: it asks the relay to probe the mapping's external address from a never-contacted port (`nat-test`), and only when the
answer arrives does it publish `open` (with `via: pcp|natpmp|upnp`); the other nodes then try the address directly, without hole punching. An UPnP answer is accepted only from a private or
link-local address, with `LOCATION` and the control URL on that same address (a forged answer cannot send the node to a third party), and bodies are limited to 64 KB.
Switch off with `--no-port-mapping` (`port_mapping = no` in `node.conf`).

## Second NAT (CGNAT, a router behind another router)

A node considers itself behind two NATs if the address the relay sees is in 100.64.0.0/10 (RFC 6598) or if the router reports (NAT-PMP/PCP/UPnP) a WAN address different from the
one the relay sees. A mapping on the first router would be useless (it is removed), the node publishes `cgnat: true`, and the pair goes to the relay **at once**, unless the other side is
`open`. If the router answers no protocol, only the 100.64.0.0/10 case is visible; a CGNAT using public addresses cannot be recognised this way.

## Port prediction (symmetric NAT)

For a symmetric NAT the node makes a third STUN transaction, to the relay's "change" port (announced as `stun.change_port`): three consecutive mappings with a constant step
(`delta`, 1..64, or small positive steps) mean sequential allocation. The node publishes `delta` and its newest mapping; the other end also sends PUNCH to `port + delta*k`, k = 1..16, in
the synchronised rounds. So symmetric <-> port-restricted and symmetric <-> symmetric (both with `delta`) no longer have to go through the relay. The method guesses: if the NAT served other
flows between the measurement and the punching, the target may be missed (the 16-port window covers some of that); it does not help against NATs with random ports, which stay on the relay.

## IPv6

The node's data socket is dual-stack (`::` with `IPV6_V6ONLY` off; falls back to IPv4 if the system cannot). A global IPv6 address (2000::/3, the one the OS would use towards the internet, found
without sending a packet) is published as `[address]:port`, and the others' IPv6 candidates are tried like the IPv4 ones. Two nodes with global IPv6 do not go through the NAT rules and do not
fall back to the relay for NAT reasons. `--no-ipv6` (`ipv6 = no`) switches this off.

## Where it lives (architecture)

`oneqnat.py` holds the STUN codec (RFC 5389 + change-port), the server (three UDP sockets in `oneqrelay`), the classification, `can_punch` and the reachability probe; the Rust client has the same
logic in `client/core/src/nat.rs` (same constants, same RFC 5769 test vector). The registry stores `nat` in the presence record (`{type, mapped, inbound}` plus, when present, `delta` (port step of a
symmetric NAT, +-1..64), `cgnat` and `via` (`pcp|natpmp|upnp`); replicated, with a TTL; the relay lets no other keys through). `can_punch` takes prediction and the second NAT into account
(`oneqnat.py`, `nat.rs::can_punch_ex`); `oneqportmap.py` / `portmap.rs` talk to the router. The filtering test comes from a port the nodes never send to: otherwise the NAT would let the answer through, and an
extra unsolicited packet would move the next mapping. The punch rounds are a pattern of the relay's clock (`PUNCH_PERIOD`, `PUNCH_CYCLE`, `PUNCH_ATTEMPTS`, `PUNCH_OFFSETS`), identical in Python and Rust;
without a measured clock the node tries continuously.

## Tests

* `test_nat_sim.py` (as root on Linux; network namespaces + nftables, 15 ms latency per link, needs `tc netem`): classification of open, port-restricted (`masquerade`), symmetric (`masquerade random`),
  cone (static SNAT/DNAT) and blocked UDP; real node pairs: port-restricted <-> port-restricted (the hard case), port-restricted <-> cone, symmetric <-> cone and open <-> symmetric connect directly,
  symmetric <-> port-restricted goes through the relay at once; the same cases between the **Rust client** (cross-compiled for Linux with Zig) and the Python node, in both role orders, plus Rust <-> Rust.
* Unit tests: Python `test_oneqportmap.py`, `test_oneqnat.py`; Rust `nat.rs`, `portmap.rs`, `engine.rs`, `client.rs`: PCP / NAT-PMP / UPnP against simulated gateways on loopback (including hostile answers:
  foreign control URL, foreign LOCATION, non-LAN device, refusals, old routers), prediction and second-NAT rules, punch decisions, a real dual-stack socket, effective NAT.
* `client/core/examples/natcheck.rs` (also built for Android) measures the NAT of whatever network it runs on against a relay (`natcheck HOST:PORT`): type, whether the source port is kept, the public address,
  the port step and a second NAT. `client/tool/router_map_test.py` asks the router for a mapping and checks it with datagrams from another network (`udpsend` example).

## Limits

* A mapping on the router works only if the router speaks PCP, NAT-PMP or UPnP IGD; a CGNAT with public addresses cannot be recognised as a second NAT.
* Port prediction guesses (see above): a NAT with random ports stays on the relay.
* Netfilter cannot reproduce a NAT with sequential allocation, so the lab tests prediction with models.
