# Publishing the extension

`python client/browser/build-store.py` writes `client/dist-store/`:

* `oneq-mesh-chromium-VERSION.zip`: upload to the **Chrome Web Store** developer dashboard and to **Microsoft Edge Add-ons** (partner centre). Brave users install from
  the Chrome Web Store.
* `oneq-mesh-firefox-VERSION.zip`: upload to **addons.mozilla.org** (developer hub, "On this site" for the public listing or "On your own" for a signed file that you
  distribute yourself).
* `store-listing/`: texts for the forms (`listing.md`), the privacy policy to host at a public URL (`PRIVACY.md`).
* `SHA256SUMS`.

The build is reproducible: the same sources give the same zip bytes.

## The native host and the store extension id
The extension needs the oneq client's native messaging host (`oneqclient native-host install`, `NATIVE-HOST.md`). The Chromium host manifest lists the extension ids that may start it. The unpacked and
install-pack builds carry a development `key` (fixed id `bgmdbjhjoieanbojmbkjpcdmkmofikoo`); a store build has no `key` and gets its own id from the store: after the first upload run
`oneqclient native-host install --extension-id STOREID` (the packs: `install.ps1 -ExtensionId STOREID`). Firefox is fixed to `k@1q.ro`.

## What the build does not do
* **It does not sign or upload.** Each store needs the publisher's own account (Chrome Web Store one-time developer fee, Edge partner account, Mozilla account). Nothing in
  this repository holds store credentials, and none should be added.
* **Firefox signing:** a release Firefox only installs signed add-ons. Upload the zip to AMO; for a self-distributed file choose "On your own" and download the signed `.xpi`
  (or use `web-ext sign` with AMO API keys, kept outside git). Until it is signed, test with `about:debugging` > "Load Temporary Add-on", or Firefox Developer Edition / ESR with
  `xpinstall.signatures.required` set to `false`.
* **The Firefox add-on id** is `k@1q.ro` (in `build-store.py`). It is fixed forever by the first submission: change it before that if you want another one.
* **Screenshots** are not produced (see `store/listing.md`).
* **Privacy policy URL:** the stores want a public URL; host `PRIVACY.md` (for example on the project's pages) and fill in its contact line.

## Differences between the two builds
|  | Chromium zip | Firefox zip |
|---|---|---|
| Background | service worker | event page (`background.scripts`) |
| Proxy mechanism | PAC script through `chrome.proxy.settings` | `proxy.onRequest` listener |
| Host permissions | `127.0.0.1`, `localhost` | the same plus `<all_urls>` (required by `proxy.onRequest`) |
| Manifest extras | `minimum_chrome_version` 110 | `browser_specific_settings.gecko` (id, minimum Firefox 140, no data collection) |

## Before every release
1. Bump `version` in `client/browser/extension/manifest.json` (the stores reject a version that is not higher than the published one).
2. `node --test client/browser/test`
3. `python client/browser/test/chrome_e2e.py` (Chromium) and `python client/browser/test/firefox_e2e.py` (Firefox) against a running proxy.
4. `python client/browser/build-store.py`
