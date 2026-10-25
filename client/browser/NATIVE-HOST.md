# Connection manager of the browser extension (native messaging host)

Goal: the extension is the only thing the user sets up. A browser extension cannot open sockets or listen on a port, so it cannot be the VPN client itself; what it
can do is ask a small program of the oneq client, installed once, to do that work and to keep the settings. That program is `oneqclient native-host`.

```
extension (options form, popup)              oneqclient native-host                   oneqclient proxy
  chrome.runtime.connectNative  ── stdin/stdout, JSON ──▶  settings + password files  ──spawns──▶  SOCKS5 127.0.0.1:1080, status :1081
  PAC / proxy.onRequest ─────────── mesh addresses and *.oneq ──────────────────────────────────────▶  (the mesh)
```

## Parts
1. **Host** (`core/src/nativehost.rs`): the native messaging framing (4-byte little-endian length + JSON), the commands below, the settings and password files, the
   proxy child process. The browser starts it with its own arguments (`chrome-extension://ID/`, or `MANIFEST.json ADDON-ID` for Firefox); `oneqclient` recognises them
   (`nativehost::is_launch`) and runs the host instead of a command.
2. **Lifetime**: the proxy is a child of the host and the host lives as long as the browser's pipe. Closing the pipe (the browser exits) stops the proxy; if the host is
   killed abruptly the proxy ends by itself (`oneqclient proxy --exit-with-pid HOSTPID` polls the host's process). The SOCKS5 port therefore exists only during the browser
   session. (The proxy still serves browsers only, see the main README.)
3. **Registration** (`oneqclient native-host install`): a manifest for Chromium browsers (`allowed_origins`: the extension ids) and one for Firefox
   (`allowed_extensions`: `oneq-mesh@1q.ro`); Windows: `HKCU\Software\<Browser>\NativeMessagingHosts\ro.1q.oneq` for Chrome, Brave, Edge, Chromium and Firefox; macOS and
   Linux: the browsers' `NativeMessagingHosts` directories, only for browsers that are installed. `uninstall` removes them. No administrator rights, nothing outside the
   user's profile.
4. **Stable extension id**: an unpacked extension's id depends on its path, so the development manifest carries a public `key` (id
   `bgmdbjhjoieanbojmbkjpcdmkmofikoo`) and the host manifest names that id. The store builds leave the `key` out (a store assigns its own id): register it with
   `oneqclient native-host install --extension-id STOREID`.
5. **Extension**: the options page has the connection form (relays, community, user, password, device name, CA) and imports the settings file of the oneq apps
   (`oneq-settings`); `background.js` talks to the host, starts the connection when the settings are complete, and the popup has Connect / Disconnect and the setup state.
6. **Installers**: `install.ps1` / `install.sh` copy the extension, register the host and, with `-Relay -Community -User`, fill the host's settings
   (`native-host configure`; the password from `-PasswordFile`, a hidden prompt, or later via `set-password.ps1`).

## Messages
Request `{"id": N, "cmd": ...}`, reply `{"id": N, "ok": true|false, "error": "...", ...state}`; every reply carries the state:
`config` (relays, community, user, name, `ca_set`), `has_password`, `complete`, `running`, `log` (the last lines of the proxy's log).

| cmd | effect |
|---|---|
| `hello` | host name, version, operating system |
| `get` / `status` | the state |
| `set` `{config, password?, clear_password?}` | validates and stores the settings (strict: https relays, no spaces or quotes), stores the password if given (kept if omitted), stops a running proxy |
| `start` | starts `oneqclient proxy` with the stored settings (refused with a message if they are incomplete or there is no password) |
| `stop` | stops it |

## Files (in the user's configuration directory: `%APPDATA%\oneq`, `~/.config/oneq`)
`browser.json` (settings, no password), `browser.pass` (the password; mode 0600 on Unix, the user's profile directory on Windows), `browser-ca.pem`,
`browser-proxy.log` (the proxy's output of the last start), `proxy.key` (the node key of the proxy, shared with a manually started `oneqclient proxy`),
`native-host/*.json` (the registered manifests).

## Security
* The password travels once over the browser-to-host pipe and is written to `browser.pass`. It is never sent back, never put on a command line (the proxy reads
  `--password-file`), never in the log, and the extension does not keep it (the form is emptied; `chrome.storage` holds only the proxy addresses, extra networks and switches).
* Only the extensions in the host manifest can start the host: enforced by the browser (`allowed_origins` / `allowed_extensions`).
* The host does not listen on any port; its only inputs are the browser's pipe and the files above.
* Not covered: a program running as the same user can read `browser.pass` and the node key (as it could for any oneq client); a browser extension of the same browser
  cannot reach the host unless it is listed in the manifest.

## Tests
`cargo test -p oneq-core --lib nativehost` (framing, validation, the password rules, manifests, process liveness); `client/browser/test/native_host_unix_test.py` (macOS and Linux:
the host over stdio, the proxy's lifetime including a killed host, manifest registration in a fake home); `chrome_native_e2e.py` and `firefox_native_e2e.py` (a real
browser: fill the options form, the mesh opens by member name, no secret in storage or on a command line, Disconnect/Connect in the popup, the proxy is gone with the browser).
