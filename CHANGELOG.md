# Changelog

One version number for the whole project (relay, node, packages): components of the same version are compatible with each other.
Compatibility rules are listed per release.

## Unreleased

* **Performance: PQ handshake crypto off the event loop.** The X25519+ML-KEM-768 operations in `init_create`,
  `init_consume`+`resp_create` and `resp_consume` now run in a thread-pool executor instead of blocking the asyncio
  event loop. The handshake retry interval was raised from 2 s to 5 s and the maintenance tick from 250 ms to 500 ms.
  A per-peer `init_pending` flag prevents duplicate concurrent handshake tasks. Together these changes cut CPU usage
  significantly on busy nodes (12+ peers, frequent session re-establishment).
* **Performance telemetry.** The Python node emits structured JSON-line events to the `oneq.perf` logger
  (`crypto_init_create`, `crypto_init_resp`, `crypto_resp_consume` with duration in ms; `session_up` with path and
  round-trip time; `path_change`; `tick_slow`), batched and uploaded every 60 s to the relay. The relay stores them
  in `perf-{community}.jsonl`. New endpoints: `POST /v1/c/{comm}/perf` (authenticated, ingest) and
  `GET /v1/bench` (unauthenticated, serve the bench harness script).
* **`oneq_bench.py`: 48-hour randomised test harness.** A standalone script that self-updates from the relay
  (`GET /v1/bench`), schedules test functions at randomised intervals, and uploads results via `POST /v1/c/{comm}/perf`.
  Built-in tests: relay health (`ping_relay`) and member-list latency (`list_nodes`); stubs for session latency,
  local crypto benchmark and throughput burst (to be filled in).

* **Redundant gateways**: the same network can be announced through up to 4 gateway nodes (`oneqrelay admin route-add COMMUNITY NETWORK NODE --prio N`, lower is preferred, default 100; `route-del COMMUNITY NETWORK [NODE]`;
  `PUT {via, prio}` and `DELETE ...?via=` in the API; the admin page lists one line per gateway with its priority). The record key now carries the gateway (`<comm>/<network>_<prefix>/<node id>`); records of the earlier
  shape are still read and are rewritten when the same gateway is announced again. The client uses the best gateway **that answers** (session up and a packet from it within 45 s, not the registry's 90 s presence), stays on it
  while it answers (no switch back, so connections through its NAT are not moved for nothing) and takes the next one when it goes silent; with nobody answering it keeps trying the preferred one.
  Measured with m (priority 100) and n (200) as gateways, from the Windows client: stopping m moved the traffic to n after 45 s of loss, stopping n later moved it back to m after about 25 s; m coming back did not pull the traffic away from n.
  Not covered: a gateway that is alive in the mesh but has lost its own uplink (nothing detects that), load sharing between gateways, and the older clients (they take the first gateway of the list).
* **A community can move to another subnet**: `oneqrelay admin community-subnet COMMUNITY 10.10.10.0/24` gives every node a new address in it (MAC addresses, keys, users and routes stay; refused when the new subnet is too small
  or swallows a route); the nodes take the new address when they register again (restart them). Done on the test federation: 10.78.0.0/24 -> 10.10.10.0/24, all seven nodes re-addressed with the same last octet, the gateway rules moved with it.
* **Routes through a gateway member** (a private network behind a node, reachable transparently from the other members): an administrator announces `192.168.16.0/24` as reachable through a node
  (`oneqrelay admin route-add COMMUNITY NETWORK NODE` / `route-del`, `PUT|DELETE /v1/c/<comm>/routes/<a.b.c.d_len>`, a "Routes" section on the admin page; record kind `route`, replicated; the member list carries `routes`;
  a route goes away with its gateway node; at most 64 per community, /8 or longer, never the mesh subnet, loopback, multicast or link-local). The Rust client with `--accept-routes` (`accept_routes` in the service
  configuration; off by default) sends packets for such a network to the gateway's MAC address (`l3.rs`, longest prefix wins) and installs the route on its TUN interface (`routes_os.rs`: `netsh`, `ip`, `route`; removed when
  withdrawn and when the node stops). Only private networks (RFC 1918, 100.64/10) outside the mesh are accepted by the client, whatever the relay announces. The gateway is an ordinary node with `ip_forward` and NAT:
  `deploy/oneq-gateway` + `oneq-gateway.service` (NAT only for the announced network, nothing else is forwarded out of the mesh). Tested end to end: PC (Windows service) -> m (gateway) -> 192.168.16.0/24 (ping, TCP 80/443, `tracert`), route withdrawn and restored from the relay (about 6 s), route removed when the service stops.
  Not done: Android (the VpnService must add the route), Python TAP nodes as clients (they ignore routes), a gateway that is a Rust client (it does not forward), failover between two gateways. Relays older than this change ignore the new record kind: update the whole federation first.
* Debian packages rebuilt under the oneq names on Debian 13 (`oneqnode`, `oneqrelay`, `oneq-server`; `oneqrelay` now bundles `cryptography`, both ship `oneqpop.py`, the node also `oneqportmap.py`); the apt repository `ad-go/oneq-apt` carries them, signed with the same archive key (fingerprint unchanged, user id renamed to "oneq apt repository"); the npn packages are gone from it.
* Admin page: the second factor is mandatory from every network. The `admin_no_2fa_from` / `admin_no_2fa` settings were removed (a relay that has them in its configuration refuses to start: delete the lines); the relay does not start the page without `admin_totp_file`. Off by default.
* **Proof of possession of the node key** (`oneqpop.py`, `POP.md`): a node id is a hash of a public key, and public keys are public, so anybody with a token or an account could register somebody
  else's key with endpoints of its own or take the id before its owner. Nodes now answer a stateless KEM challenge (`POST .../challenge`, then `pop` in the registration); a node id registered with a proof
  can no longer be updated without one; `--require-pop` / `require_pop = yes` refuses registrations without a proof (older nodes cannot give one). Point-to-point mode: the same for the rendezvous server,
  and the relay slot of a verified node needs the proof (`X-Oneq-Pop`). Python and Rust clients; relays and nodes without the feature keep working. The `oneqrelay` Debian package now depends on `cryptography`.
  Does not protect against a compromised relay, and does not cover older nodes until `--require-pop` is on.
* **NAT traversal, four additions** (Python node and Rust client alike): automatic port mapping on the home router (PCP, NAT-PMP, UPnP IGD; `oneqportmap.py`, `portmap.rs`; a mapping counts as
  "open" only after the relay reached it from a port never contacted; released at exit; `--no-port-mapping` / `port_mapping = no`); **IPv6** (dual-stack data socket, global IPv6 address published as a
  candidate, v6 pairs never fall back to the relay because of NAT rules; `--no-ipv6` / `ipv6 = no`); **port prediction** for a symmetric NAT with sequential allocation (third STUN transaction to the relay's
  newly announced `stun.change_port`, `delta` in the NAT description, probes of the next 16 ports; makes symmetric <-> port-restricted and symmetric <-> symmetric (both predictable) possible);
  **second NAT** (CGNAT 100.64.0.0/10, or a router WAN address that differs from the one the relay sees): `cgnat` is published and the pair goes to the relay at once unless the other side is "open".
  Registry: the `nat` description may carry `delta`, `cgnat` and `via` (other keys are still dropped); older nodes ignore them. `oneqnode nat-check` reports the port step and the second NAT.
  English version of the NAT documentation: `NAT.md`.
  Not tested on a real router that grants a mapping, a real CGNAT or a sequentially-allocating NAT (see README and client/README); `test_nat_sim.py` (Linux, root) was not re-run.
* **New icons: a rounded square with a white "1q"** instead of the "n" (tray and menu-bar icons in green/orange/grey, Windows and Android app icons, the Android notification icon, the browser extension). The macOS app icon was still the Flutter default and is now ours.
  All of them are generated by `client/tool/make_icons.py`.
* **Separate packages: node only, and node + relay (server), on every platform.** Windows: two real installers (`oneq-node-windows-x64.msi`, `oneq-server-windows-x64.msi`; WiX 5, per machine, PATH and Start menu,
  clean uninstall that keeps the settings) instead of the zip; macOS: `oneq-node-macos-*.tar.gz` and `oneq-server-macos-*.tar.gz`; Debian: `oneqnode` (node only), `oneqrelay` and the new `oneq-server` meta-package
  (installs both). `package-desktop.py` builds them (`windows/build-msi.py`, `packaging/build-debs.sh`).
* **The browser extension alone sets up the connection** (extension): `oneqclient native-host` is a native messaging host (Chrome, Brave, Edge, Chromium, Firefox) that keeps the
  settings and the password, starts `oneqclient proxy` and stops it when the browser exits (`proxy --exit-with-pid`). The extension has the connection form, a settings-file import and
  Connect / Disconnect; `install.ps1` / `install.sh` register the host and can fill in the settings (`native-host install|configure|set-password|uninstall`). Design: `client/browser/NATIVE-HOST.md`.
  Needs the oneq client installed once on the computer.
* `oneqclient proxy` serves its SOCKS5 port and status page **to browsers only** (the owning process of every loopback connection is looked up in the operating system: Windows, Linux, macOS);
  `--allow-process NAME`, `--allow-any-local`. **Behaviour change:** other local programs (curl, scripts) are refused unless allowed.
* Browser extension 0.2.0: Firefox support (event page, `proxy.onRequest`), `build-store.py` for the Chrome Web Store / Edge Add-ons / addons.mozilla.org packages, store texts and privacy policy,
  popup without `innerHTML` (web-ext lint clean), `install.ps1 -NoPassword` + `set-password.ps1`, several relays.
* macOS: per-user installation (`install.sh --user`, relay as a LaunchAgent with `relay ... --user`), tested without administrator rights on a real Intel iMac.
* macOS: the default TUN name `oneq` is not valid on macOS (only `utunN`); the system now picks the next free `utun`. Before this fix the node daemon never came up.
* macOS: the menu-bar icon is `oneqclient menubar` (Rust, same icons as the Windows/macOS app); `install.sh` no longer needs Swift or the Command Line Tools and
  creates `~/Applications/oneq.app` plus a desktop alias.
* `oneqclient relay run` replaces itself with the relay on Unix (no orphaned Python process after SIGTERM).
* A node no longer publishes a loopback "public" address when it measures its NAT against a relay on the same machine.
* `specifications.html`: formal specification of `tunmesh-pq/v2` (formats, key derivation, transcript, threat model, non-guarantees);
  `spec_check.py` checks it against `meshproto.py`.
* `SECURITY.md`, stricter `.gitignore` for secrets, CI workflow (not yet run on GitHub).

## 0.8.0

* Delegated relay nodes (L1): an administrator can delegate members to forward end-to-end encrypted datagrams (`M_RLY = 0x24`).
  **Compatibility: every relay of the federation must be 0.8.0 or newer before delegations are used** (older relays ignore the `dlg` record type).
* The relay (own Python 3.13 / OpenSSL 3.5 bundle) ships in the Windows and macOS packages: `oneqclient relay init|install|run|selftest`.
* Userspace mode `oneqclient proxy` (SOCKS5 + userspace TCP/IP stack, no TUN, no administrator rights) and the Chrome/Brave extension with install packs.
* Android: settings import from a file.

## 0.7.0

* Admin page: mandatory second factor (TOTP for authenticator apps), address allow-list.

## 0.6.0

* NAT traversal in the Rust client.

## 0.5.0

* `oneqrelay` admin page: relay settings, federation peers, communities, users, nodes.

## 0.4.4 and 0.4.3

* 0.4.4: relay-handshake fix.
* 0.4.3: `oneqnode` stays attached to a relay and re-handshakes on PUNCH.

Every component carries the same version, 0.0.1 (relay, node, Debian packages, MSI, Rust crate, Flutter app, browser extension; `oneqclient --version`). The numbers used before (0.8.0 for the project, 0.1.0 for the crate, 1.0.0 for the app, 0.3.0 for the extension) are retired: a machine that has the old packages installed has to replace them explicitly (see the note under Installing a client).
