# oneq clients

`core/` is the client engine in Rust (wire-compatible with the Python `oneqnode`, protocol `tunmesh-pq/v2`);
`app/` is the Flutter UI for Windows, Android and macOS; `core/src/bin/oneqclient.rs` is a command-line client.

The clients are **layer-3** devices (Wintun / utun / Android VpnService are IP-only). `core/src/l3.rs` wraps their IP packets
in Ethernet frames with the MACs from the registry and answers ARP for the own address, so the mesh itself is unchanged.
Only the mesh subnet is routed through the client, plus the networks of the routes the client accepted (see below); other traffic is not touched.

## Platforms

| Platform | What runs | Notes |
|---|---|---|
| Windows (x64) | `oneqclient` as the service `oneq`; the Flutter app configures and watches it (tray icon) | Wintun driver DLL next to the executable |
| macOS (Apple Silicon, Intel) | `oneqclient` as the launchd daemon `ro.example.oneq`; menu-bar icon (`oneqclient menubar`); settings page (`oneqclient ui`) | the TUN node needs root; per-user install without root gives the proxy, the browser extension and the relay |
| Android (arm64, armv7, x86_64) | foreground `VpnService` with a notification (peer count, Disconnect) | the node only; no relay (the relay is Python); routed networks with the "Use routed networks" switch |
| Linux | `oneqclient` command line | root or `CAP_NET_ADMIN` for the TUN device |

## One model on every platform

The node is always a **background service** (Android foreground service, Windows service, macOS launchd daemon); every UI (Flutter app,
`oneqclient ui`, the macOS menu-bar icon) only configures it, starts/stops it and watches it (`status.json` on desktop, the in-process core on Android).
Closing the window or the app never drops the connection. Same settings everywhere (relays, community, user, name, CA, force relay, **Start at boot**, start hidden)
and the same export/import file (`oneq-settings` v1, interchangeable between the Flutter apps and the web UI; secrets - password, node key - only when ticked).
**Start at boot** is off by default: the service is installed but started by hand (`--no-autostart`: Windows start type manual, launchd without `RunAtLoad`, Android without the saved config);
Disconnect stops it and keeps it installed. On Android the optional start at boot / Always-on VPN keeps the config encrypted with a key in the Android Keystore.

| | service | UI |
|---|---|---|
| Windows | `oneqclient service install --relay ... --community ... --user ... --password-file F [--cafile CA]`, then `service start|stop|restart|status|uninstall`; files in `%ProgramData%\oneq` (`client.json`, `client.pass` and `client.key` readable by SYSTEM/Administrators only, `client.log`); reconnects by itself when the relay is unreachable; restarted by the service manager | tray icon (grey = off, orange = connecting, green = connected), menu Open / Settings / Connect / Quit; the close button hides the window to the tray |
| macOS | launchd daemon `ro.example.oneq` (`KeepAlive`, `RunAtLoad`), same `service` commands | menu-bar icon with the same three icons, a status line, "Open oneq..." and "Quit" |
| Android | `VpnService` | notification with a Disconnect button |

`oneqclient ui` is the settings page (also usable on Windows and Linux): status and members, connection form, **Export/Import** (same file format as the Flutter app),
Connect/Start/Disconnect/Remove service. It listens on 127.0.0.1 only, the URL carries a random token, the Host header is checked, and the node runs as the background
service (administrator rights are asked for on Connect: macOS password dialog via osascript, Linux pkexec, Windows: start it elevated).

CLI: `oneqclient up --relay https://r1 --relay https://r2 --community C --user U --password-file F [--cafile CA.pem] [--force-relay]`
(administrator/root; the password only from a file or `ONEQ_PASSWORD`, never on the command line).

## Browser without a driver (`oneqclient proxy` + extension)

`oneqclient proxy` joins the mesh without a TUN device or administrator rights (a userspace TCP/IP stack, smoltcp, on the node's mesh address) and serves a SOCKS5 proxy on
127.0.0.1; the Chrome/Brave/Edge/Firefox extension in `browser/extension` points only the mesh addresses and `*.oneq` names at it and shows the connection in its popup. TCP only.
The proxy serves browsers only. See `browser/README.md`.

## Delegated relay nodes and routes

`--relay-offer` (`relay_offer` in the service configuration) lets the node offer to forward datagrams for the other members; once an administrator delegates it (admin page or
`oneqrelay admin relay-grant`) members that cannot reach each other directly send through it over UDP. `--no-delegates` ignores the delegated nodes of the community.
Implemented in `core/src/engine.rs` (`M_RLY` packets, wire-compatible with `oneqnode.py`).

`--accept-routes` (`accept_routes` in the service configuration; off by default) uses the private networks an administrator routed through a gateway member
(`oneqrelay admin route-add`, see ARCHITECTURE.md): the client sends the packets for such a network to the gateway's MAC address (`core/src/l3.rs`) and installs the route on the TUN interface
(`core/src/routes_os.rs`: `netsh` on Windows, `ip` on Linux, `route` on macOS), removing it again when it is withdrawn or when the node stops. Only networks inside RFC 1918 or 100.64.0.0/10
and outside the mesh subnet are accepted, whatever the relay announces. A network announced through several gateways uses the best one (lowest priority number) that answers - a session
is up and a packet arrived within 45 s - and moves to the next one when it goes silent; it does not switch back to a preferred gateway that returns, so connections through the other
gateway's NAT are not moved without a reason. The status (`status.json`, `routes`) lists each network with its preferred gateway and the backups.
The apps have the switch "Use routed networks" (`accept_routes` in the settings file); the Mac menu-bar page has the same checkbox. On Android the VpnService owns the routes: the core lists the accepted
networks (`route_nets` in the status) and the service adds them to the VPN interface, building it again when the list changes (a short interruption).

## NAT traversal in the clients

Every client measures its NAT with the relay's STUN service (UDP, three ports next to the relay's HTTPS port), publishes the type and its
public UDP address, answers STUN Binding requests on its data socket (the relay's reachability test), and punches in rounds aligned to the
relay's clock - the same rules as `oneqnode.py` (`core/src/nat.rs`, `engine.rs`; constants and the round pattern are identical, see the
README at the top of the repository). The status shows it (`NAT: port-restricted · 203.0.113.5:40000` in the app, `nat_type` in `status.json`).
A relay without the STUN service is used without NAT measurement.

Beyond that the client asks the home router to forward its UDP port (PCP, NAT-PMP, UPnP IGD: `core/src/portmap.rs`; the mapping counts only after the relay's `nat-test` reached it
from a port never contacted; `--no-port-mapping`), recognises a second NAT (address in 100.64.0.0/10, or a router WAN address that differs from the one the relay sees) and then goes to
the relay at once, probes the ports a symmetric NAT with sequential allocation will use next (`delta`), and uses a dual-stack socket with IPv6 candidates (`--no-ipv6`).
Unit tests: `nat.rs` (prediction, second NAT, rules), `portmap.rs` (PCP / NAT-PMP / UPnP against simulated gateways on loopback, including hostile answers), `engine.rs` (punch decisions),
`client.rs` (dual-stack socket, effective NAT); `test_nat_sim.py` runs the Rust client against the Python node behind simulated NATs.
On Android the default gateway may not be readable: PCP and NAT-PMP are then skipped and UPnP is tried.

## Update check

The client looks at GitHub (`api.github.com/repos/ad-go/oneq/releases/latest`) for a newer release, 30-120 s after start and every 24 h, and
shows it: the `update` field of the status snapshot (`null` until checked), a banner in `oneqclient ui`, an `Update available: <version>...`
item in the macOS menu bar, and the Flutter app. Nothing is installed or run automatically; `Download` saves the installer of this platform
(Windows msi, macOS tar.gz, Android apk; none on Linux) to the Downloads folder, verified against the release's `SHA256SUMS`
(a mismatch deletes the file). Only HTTPS to GitHub hosts is contacted (<= 5 redirects, 1 MB / 64 KB / 200 MB caps), with a plain
`User-Agent: oneq/<version>` and no identifiers.

* CLI: `oneqclient update check [--json]`, `oneqclient update download [--dir DIR] [--json]` (a manual check works even when automatic checks are off).
* Disable the automatic check: `--no-update-check` (`up`, `service install`), `"update_check": false` in `client.json`, the setting `update_check` in the
  FFI prepare JSON, or the checkbox *Check for updates automatically* in `oneqclient ui`.
* FFI (`oneq_core`): `oneq_update_check_json(force)` and `oneq_update_download_json(dir)` (blocking, free the result with `oneq_free_string`);
  JNI: `NativeCore.updateCheck(force)` / `NativeCore.updateDownload(dir)`.
* Tests use `ONEQ_UPDATE_URL=http://127.0.0.1:PORT/...` (the only way plain http is accepted).

## Packages: node only, or node and relay (server)

Every platform has two packages, so a machine that only joins a mesh does not carry the relay:

| Platform | node only | node + relay (server) |
|---|---|---|
| Windows (x64) | `oneq-node-windows-x64.msi` | `oneq-server-windows-x64.msi` |
| macOS (Apple Silicon / Intel) | `oneq-node-macos-arm64.tar.gz`, `oneq-node-macos-x64.tar.gz` | `oneq-server-macos-arm64.tar.gz`, `oneq-server-macos-x64.tar.gz` |
| Debian 13 (amd64) | `oneqnode_VERSION_amd64.deb` | `oneq-server_VERSION_all.deb` (installs `oneqnode` and `oneqrelay`; `oneqrelay` alone also exists) |

**Windows installer** (MSI, WiX 5, `windows/oneq.wxs`, `windows/build-msi.py`): per machine, to `%ProgramFiles%\oneq` (`INSTALLFOLDER=...` changes it, `msiexec /i FILE /qn` is silent),
adds `oneqclient` to the system PATH (a separate feature) and a Start menu entry for the app. The two editions share a product code family: installing the server MSI over the node
one (or the other way round) switches edition; a newer version replaces an older one, an older never replaces a newer. Uninstalling removes the files, the PATH entry and the
shortcut, and takes the `oneq` and `oneqrelay` services out of the service manager first; **settings, keys and the relay's data (ProgramData, the user profile) are kept**.
`build-msi.py` needs a `relay` folder in the app directory (it may be empty for the node edition).
**macOS:** `install.sh` installs the relay too when `oneqrelay-bundle-...tar.gz` is next to it (the only difference between the two archives). **Debian:** `packaging/build-debs.sh`
builds the three packages; `oneq-server` has no files of its own and depends on both at the same version. The installers are not code-signed.

### macOS install

* With administrator rights: `./install.sh` installs `oneqclient` root-owned in `/usr/local/libexec/oneq` (it runs as root in the launchd service), signs it ad-hoc, creates
  `~/Applications/oneq.app` (+ an alias on the desktop) and starts the menu-bar icon at login. Then `sudo oneqclient service install` (LaunchDaemon `ro.example.oneq`) and, for a relay,
  `sudo oneqclient relay init` / `relay install` (LaunchDaemon `ro.example.oneqrelay`). The TUN interface name must be `utunN`: any other name means "the next free utun". `uninstall.sh [--purge]` removes everything.
* Without administrator rights: `./install.sh --user` installs for the current user only: `oneqclient` in `~/Library/Application Support/oneq/bin` (link in `~/.local/bin`), the relay bundle
  next to it, no root-owned file, no `sudo`. With it: `oneqclient proxy ...` (the browser, see browser/README.md) and the relay as a **LaunchAgent** of the user:
  `oneqclient relay init --user ...`, `relay install --user` (data in `~/.config/oneq/relay`; it runs while the user is logged in; launchd restarts it). The TUN node needs root: utun cannot be created otherwise.
* The menu-bar icon (`oneqclient menubar`, Rust, `core/src/menubar.rs`) reaches AppKit through the Objective-C runtime with dlopen, so no Swift, Command Line Tools or SDK are needed.
* `macos/cross-build.sh` (on Windows/Linux, with `pip install ziglang`, `cargo install cargo-zigbuild`) builds `oneqclient` for Apple Silicon and Intel without a Mac -> `macos/dist/oneqclient-arm64`,
  `oneqclient-x86_64`. It rewrites `core/Cargo.toml` while it runs: do not run `cargo` or commit at the same time.

## Installing a client: examples

The examples join the community `oneq` through the relays `x.example.com` and `y.example.com` as the user `alice`; replace the relays, community, user and CA file with your own.
The password is never given on the command line: put it alone in a file readable only by you (`PASSFILE` below) and delete the file when it is no longer needed.
`ca.crt` is the CA that signed the relay certificates (leave `--cafile` out when they come from a public CA). `--accept-routes` is optional: it makes the networks the
administrator routed through a gateway member reachable (for example `192.168.16.0/24`). After the first connection check the state with `oneqclient service status`
(on Windows and macOS; the members are in the app or the settings page) and `ping` another member's address.

**Version numbering.** Every component is version 0.0.1 (`oneqclient --version`, the Debian packages, the MSI, the apps, the extension). Packages of the earlier numbering (0.8.0) count as *newer*:
the MSI refuses to replace them (uninstall first: `msiexec /x` on the old MSI, or Settings > Apps) and `apt` refuses the downgrade (`dpkg -i FILE.deb`, or `apt install --allow-downgrades ./FILE.deb`).
Settings and keys are kept in both cases.

### Windows (x64)

```powershell
# elevated PowerShell; the MSI is per machine and silent with /qn (add INSTALLFOLDER="D:\oneq" to change the folder)
msiexec /i oneq-node-windows-x64.msi /qn /l*v install.log

# a new shell picks up the PATH entry; the service runs as SYSTEM
oneqclient service install --relay https://x.example.com:8443 --relay https://y.example.com:8443 `
    --community oneq --user alice --password-file C:\secretslice.pw `
    --cafile C:\secrets\ca.crt --name my-pc --accept-routes
oneqclient service status
```

Without the command line: start "oneq" from the Start menu, open Settings, fill in the connection (or **Import from file...** a settings file exported from another
device), press Connect (the administrator prompt installs the service). Remove: `oneqclient service uninstall`, then `msiexec /x oneq-node-windows-x64.msi /qn`
(settings and the node key stay in `%ProgramData%\oneq`).

### macOS (Apple Silicon and Intel)

```sh
tar xzf oneq-node-macos-arm64.tar.gz        # or oneq-node-macos-x64.tar.gz
cd oneq-macos && ./install.sh    # asks for the administrator password once; --user installs without root (no TUN node)

sudo oneqclient service install --relay https://x.example.com:8443 --relay https://y.example.com:8443     --community oneq --user alice --password-file ~/alice.pw --cafile ~/ca.crt --name my-mac --accept-routes
sudo oneqclient service status              # launchd daemon ro.example.oneq; the log is /Library/Application Support/oneq/client.log
```

The menu-bar icon (green = connected) opens the settings page, where the same connection can be entered or imported from a file. The installers are not code-signed:
if Gatekeeper blocks the first start, open the app with right click > Open. Remove: `./uninstall.sh` (`--purge` also deletes settings and keys).

### Debian 13 (amd64)

```sh
sudo apt install ./oneqnode_0.0.1_amd64.deb         # node only; ./oneq-server_0.0.1_all.deb + ./oneqnode_... + ./oneqrelay_... adds the relay

sudo install -m 600 /dev/null /root/alice.pw && sudoedit /root/alice.pw    # the password, alone in the file
sudo oneqnode-init home --relay https://x.example.com:8443 --relay https://y.example.com:8443     --community oneq --user alice --password-file /root/alice.pw --cafile /root/ca.crt --label my-debian
systemctl status oneqnode@home                      # interface oneq-home, address from the community
ip addr show oneq-home && ping -c2 10.10.10.65
```

`oneqnode-init` writes the section `[home]` in `/etc/oneq/node.conf`, generates the key and stores the password for the service (`/etc/oneq/node-home.key`, `node-home.password`, mode 0600).
Behind a NAT or a firewall add `--advertise PUBLIC_IP:51820` and forward that UDP port. `oneqnode-init home --remove` removes the node. To use the routed networks on a Debian machine
run the Rust client (`oneqclient up ... --accept-routes`, root) instead: the Python node does not install routes.

### Android (arm64)

```sh
adb install -r app-release.apk                # or copy the APK to the phone and open it (allow "install unknown apps" for the file manager)
adb push oneq-settings.json /sdcard/Download/ # a settings file exported from another device (without the password)
```

On the phone: open **oneq** > Settings > **Import from file...** and pick the file (or fill in the form by hand), type the password, switch on **Use routed networks** if you need
the gateway's networks, save, then press Connect and accept the system VPN request once. **Start at boot** keeps the settings, with the password, encrypted with a key in the
Android Keystore, so the VPN can come up without opening the app (also used by "Always-on VPN"). Reinstalling the APK with `adb install -r` can reset the app's settings: import the file again.
The APK in the repository build is signed with the debug key; replace it before distributing.

## Node and relay in the desktop packages

The server packages contain the node (`oneqclient`, the app) **and the relay** (`oneqrelay`: registry, accounts, relay, STUN, admin page).
The relay is the Python program of the repository; it needs a Python linked with OpenSSL >= 3.5 (post-quantum TLS), so the packages bring their own:
python-build-standalone 3.13 (checksum-verified against the release's `SHA256SUMS`), the dependencies as wheels for the platform, and the relay files.
`relay/build-bundle.py --platform windows-x64|macos-arm64|macos-x64` builds the bundle, `package-desktop.py` assembles `dist-packages/` (the two Windows installers through `windows/build-msi.py`).

    oneqclient relay init --name host.example.org [--ip PUBLIC.IP] [--port 8443]   # once (administrator): private CA + certificate, federation secret,
                                                                                  # admin password + authenticator (TOTP), relay.conf in <service dir>/relay
    oneqclient relay install                      # service oneqrelay (Windows) / launchd ro.example.oneqrelay (macOS); on Windows it also opens TCP 8443 + UDP 8443-8445
    oneqclient relay admin community-add team 10.50.0.0/24      # communities and users (or the admin page /admin/, password + authenticator code)
    oneqclient relay admin user-add team alice --password-file F
    oneqclient relay selftest                     # TLS PQ handshake, STUN on the three UDP ports, admin login
    oneqclient relay start|stop|restart|status|uninstall|run

Clients import `<service dir>/relay/ca.crt` (Windows `C:\ProgramData\oneq\relay\ca.crt`, macOS `/Library/Application Support/oneq/relay/ca.crt`); the router must forward
TCP 8443 and UDP 8443-8445 to the machine. The admin page asks for the password and a code from any authenticator app; `admin-enrolment.txt` and `admin-qr.svg`
(in the data directory) hold what to enrol and are to be deleted afterwards. On Android there is no relay.

## Build

    cargo build --release -p oneq-core                       # oneqclient.exe, oneq_core.dll
    # wintun.dll: download wintun-0.14.1.zip from wintun.net, verify the signature, put bin/amd64/wintun.dll in client/vendor/wintun/bin/amd64/
    cd app && flutter build windows --release               # copies oneqclient.exe + wintun.dll next to oneq_app.exe (copy oneq_core.dll from target/release too); the exe asks for administrator rights
    # Android (NDK 28 + cargo-ndk):
    ANDROID_NDK_HOME=... cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o app/android/app/src/main/jniLibs build --release -p oneq-core --lib
    rm app/android/app/src/main/jniLibs/*/libtun_rs-*.so    # useless artefact of the dependency
    cd app && flutter build apk --release                   # signed with the debug key: replace before distributing

After a move or rename of the project directory run `flutter clean` before building the app.

## Known limits

- The node key is stored unencrypted in `%APPDATA%\oneq\client.key` (Android: the app's private directory). The password is never stored.
- The relay must present a certificate valid for the name used (rustls rejects CA certificates used as server certificates), and TLS 1.3 with X25519MLKEM768 is mandatory.
- Wintun is not redistributable without WireGuard LLC's consent, so it is not in the repository.
- No automatic reconnect after the relay accounts or the IP change: disconnect and connect again.
- A Rust client cannot be a gateway for a routed network (it does not forward packets); use `oneqnode` on Linux (`deploy/oneq-gateway`).
