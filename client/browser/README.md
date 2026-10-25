# oneq in the browser (Chrome, Brave, Edge)

The mesh in a browser **without a VPN driver and without administrator rights**: `oneqclient proxy` joins the mesh as an ordinary node, runs a small
userspace TCP/IP stack on its mesh address and offers a SOCKS5 proxy on `127.0.0.1`; the extension in `extension/` sends only the mesh addresses
(and names ending in `.oneq`) through that proxy and shows the state of the connection. Everything else the browser does is left alone.

    browser ──(PAC: mesh only)──▶ SOCKS5 127.0.0.1:1080 ──▶ oneqclient proxy ──(post-quantum mesh, direct UDP or relay)──▶ members
        ▲                                                         │
        └────────── extension popup ◀── GET 127.0.0.1:1081/status ┘

## Set up in the extension (connection manager)

The extension alone sets up and runs the connection: open its Settings, enter the relays, community, user, password (or import the settings file the oneq apps export)
and press "Save and connect"; the popup has Connect / Disconnect. This needs the oneq client on the computer (installed once) and its **native messaging host**
registered for the browser (`oneqclient native-host install`, done by the install packs). The host keeps the settings, starts `oneqclient proxy` and stops it when
the browser exits. Design, messages, files and security: [NATIVE-HOST.md](NATIVE-HOST.md). Without the host the extension still works with a proxy you start yourself (below).

## Install packages

`client/package-desktop.py` builds two packages in `client/dist-packages/`: `oneq-browser-extension-windows.zip` (`install.ps1`, `uninstall.ps1`) and
`oneq-browser-extension-unix.tar.gz` (`install.sh`, `uninstall.sh`), each with the extension and a README.txt. The installer copies the extension to a stable folder, can
register the proxy to start at every logon (Windows: a scheduled task of the current user, no administrator rights; macOS: a LaunchAgent; Linux: a systemd user
service), opens the browser's extensions page and puts the folder on the clipboard. A browser loads an unpacked extension only from its own extensions page, so *Developer
mode -> Load unpacked* stays a manual step.

`install.ps1` copies the extension, registers the native host for Chrome, Brave, Edge, Chromium and Firefox and, with `-Relay` (repeatable, failover list) `-Community` `-User` [`-CaFile` `-Name`],
fills the host's settings; the password comes from `-PasswordFile`, a hidden prompt, or later `set-password.ps1` / the extension's Settings (`-NoPassword` skips the prompt). The extension then connects by itself.
`-StartAtLogon` additionally registers the old logon task (a proxy independent of the browser; `-ProxyArgs --allow-process,NAME` adds a program to the gate).

    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Relay https://relay.example.org:8443 -Community lan -User alice -CaFile ca.pem    # asks for the password once
    ./install.sh --relay https://relay.example.org:8443 --community lan --user alice --cafile ca.pem


## Use

1. Start the proxy (the options of `oneqclient up`; it needs no TUN device and no administrator rights; its node key is separate: `proxy.key`):

       oneqclient proxy --relay https://relay.example.org:8443 --community lan --user alice --password-file pw.txt [--cafile ca.pem]
                       [--socks 127.0.0.1:1080] [--status 127.0.0.1:1081] [--name my-laptop]

2. Install the extension: open `chrome://extensions` (Brave: `brave://extensions`), turn on *Developer mode*, *Load unpacked*, choose `client/browser/extension`
   (or unpack `oneq-browser-extension.zip` of the desktop packages and choose that folder).
3. Open a mesh host by address, `http://10.78.0.189/`, or by member name, `http://name.oneq/` (the name a member shows in the member list; the proxy resolves it).
   The toolbar icon is grey `!` while the proxy is not running, orange while it connects and clean when connected; the popup lists the members and their path
   (direct / relay).

The extension's switch gives the browser's proxy settings back. Settings (proxy and status address, extra networks) are on its options page; both addresses must be on
this computer.

## What it can and cannot do

* TCP to mesh addresses (HTTP, HTTPS, SSH through a SOCKS-aware client, ...). **Not**: UDP, ping/ICMP, IPv6, incoming connections from the mesh to the browser's machine.
* Only programs that use the proxy reach the mesh. The system-wide route (every program) is the TUN client (`oneqclient service ...`, the apps); the two can run side by side
  (they are different nodes of the same user, each counts against the user's node quota).
* The PAC script **replaces** any other proxy the browser was using for the mesh addresses only; other addresses stay `DIRECT`. If another extension or a policy controls the
  proxy settings the popup says so.
* Security: the SOCKS5 port and the status page listen on loopback only (refused for any other address) and have no authentication (Chrome cannot send SOCKS credentials),
  so they are **served to browsers only**: for every accepted connection `oneqclient proxy` asks the operating system which program owns the client end (Windows
  `GetExtendedTcpTable`, Linux `/proc/net/tcp` + `/proc/*/fd`, macOS `lsof`) and closes the connection unless the program is a browser (`chrome`, `chromium`, `brave`, `msedge`,
  `firefox`, `librewolf`, `waterfox`, `vivaldi`, `opera`, `tor browser`; on macOS the "... Helper" processes of those). If the owner cannot be determined the connection is refused.
  `--allow-process NAME` (repeatable, a fragment of the executable name) admits another program, `--allow-any-local` restores the old behaviour for every local program.
  The popup shows the mode. Limit: an executable name is not an identity; a program of the same account that is called `chrome` is served (it could read the node key anyway),
  this keeps out other users' programs and tools that only know the port. The status page also checks the `Host` header and sends no CORS headers (web pages cannot read it).
  The extension asks for the `proxy`, `storage` and `alarms` permissions and for access to `127.0.0.1`; it talks to nothing else.

## Store packages (Chrome Web Store, Edge Add-ons, addons.mozilla.org)

`python client/browser/build-store.py` writes `client/dist-store/` (reproducible, ignored by git): `oneq-mesh-chromium-VERSION.zip` (Chrome, Edge, Brave), `oneq-mesh-firefox-VERSION.zip`
(Firefox: event page, `proxy.onRequest` instead of a PAC script, gecko id `oneq-mesh@1q.ro`, declaration that no data is collected, `<all_urls>` host permission which Firefox needs for
`proxy.onRequest`), `store-listing/` (descriptions, permission justifications, privacy policy, `PUBLISHING.md`) and `SHA256SUMS`. Not published, not signed: that needs the publisher's own store
accounts (see `store/PUBLISHING.md`). A release Firefox installs only signed add-ons, so until AMO signs the file it can be loaded only temporarily (`about:debugging` > Load Temporary Add-on).
`web-ext lint` on the Firefox build: 0 errors, 0 warnings.

## Tests

* `cargo test -p oneq-core --lib` : the userspace stack (TCP between two stacks: 300 kB each way, orderly close, refused connection) and the SOCKS5 server (by address, by
  member name, outside the mesh, unknown name).
* `node --test client/browser/test/pac.test.js` : the PAC script (only mesh addresses and `.oneq`, no name resolution, strict parsing of the proxy address and the subnets).
* `python client/browser/test/chrome_e2e.py BROWSER_EXE URL TITLE [MEMBER]` : the real thing in a headless browser with a throw-away profile: the extension loads, sets the
  PAC script from a running `oneqclient proxy`, a mesh page loads by address and by name, the popup renders, the off switch releases the proxy. To prove the path, run it where
  the mesh addresses are *not* reachable directly (no TUN client running). Brave loads the extension with `--load-extension` in a separate profile, but this script cannot attach to it the same way: check by hand
  over DevTools that the PAC script is set, a mesh address loads through the proxy (the proxy's byte counter rises by the size of the page) and the popup shows the members.

* `python client/browser/test/firefox_e2e.py FIREFOX_EXE ZIP URL TITLE [MEMBER]` : the same in a real Firefox (Marionette, temporary add-on from the Firefox zip): the mesh name
  `http://MEMBER.oneq/` loads through the proxy, the popup shows the connection and "browsers only", the off switch stops it, switching on again restores it.
* `cargo test -p oneq-core --lib` also covers the process gate (`peer.rs`): the browser-name matching, the parsers of the three operating systems' tables, and a test that connects to a
  loopback listener and checks that the operating system names this very program (runs on Windows, Linux and macOS).
* The gated proxy refuses other local programs (`curl`, scripts) on both the SOCKS port and the status page: the owning process of every loopback connection is looked up in the operating system
  (Windows, Linux, macOS); on Linux the `/proc` tables are covered by parser tests only.
