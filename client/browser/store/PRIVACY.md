# Privacy policy: oneq mesh (browser extension)

**The extension collects no data and sends nothing to any server.**

* It talks only to a program on your own computer: the status page of `oneqclient proxy` on `127.0.0.1` (by default port 1081), to show the state of the
  connection and to learn which network the mesh uses. It never contacts a remote server, a developer server or an analytics service.
* The connection settings you type in the extension (relays, community, user, password, device name, certificate) are handed to the oneq connection manager, a program of the oneq client on your own computer
  (native messaging), which stores them in files that only your user account can read. The extension itself does not keep the password. Nothing is sent to the developer or to any other server by the extension.
* It changes where the browser sends requests only for the addresses of your oneq mesh (the mesh's private network) and for names ending in `.oneq`: those requests go to the
  SOCKS5 proxy on `127.0.0.1`. Every other request is left alone and goes where it would have gone without the extension.
* It does not read, store or transmit the pages you visit, your history, cookies, form data or passwords. It does not inject scripts into web pages.
* What it stores, in the browser's local extension storage on your computer: the proxy and status addresses, extra networks you typed in the options page, whether the switch is on,
  and the last mesh network it saw. Nothing is synchronised to any account.
* The oneq software itself (the proxy and the mesh) is a separate program under your control; this policy covers the extension only. See the project documentation
  for what the mesh servers you connect to can see (`specifications.html`, section 12).

Contact for privacy questions: `<CONTACT>` (to be filled in by the publisher before submission).
