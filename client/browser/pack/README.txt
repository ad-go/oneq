oneq mesh - browser extension (Brave, Chrome, Edge)
=================================================

What it is: the extension sends the addresses of the oneq mesh (and names ending in .oneq) through `oneqclient proxy`, a SOCKS5 proxy on this
computer that joins the mesh without a VPN driver and without administrator rights. Everything else the browser does is left alone.

Install (Windows)
-----------------
  1. Install the oneq client (oneqclient.exe) if you have not: the desktop package has it.
  2. In PowerShell, in this folder:

       powershell -ExecutionPolicy Bypass -File .\install.ps1 -Relay https://relay.example.org:8443 -Community lan -User alice [-CaFile C:\path\ca.pem] [-Name laptop]

     It copies the extension to %LOCALAPPDATA%
pnrowser\extension (a stable folder: the browser loads it from there), registers the oneq connection manager
     (native messaging host) for Chrome, Brave, Edge and Firefox of this user (no administrator rights), fills in the connection settings and asks for the password
     once (hidden; or pass -PasswordFile FILE, or -NoPassword and type it in the extension's Settings later). The extension then starts and stops the connection itself;
     the proxy lives only as long as the browser. Several -Relay values are a failover list.
     Without -Relay it only installs the extension and the connection manager: enter everything in the extension's Settings.
  3. In the browser (this step cannot be automated; browsers load an unpacked extension only from their extensions page):
       - turn on "Developer mode" (top right)
       - press "Load unpacked", choose %LOCALAPPDATA%
pnrowser\extension
     Firefox: about:debugging > This Firefox > Load Temporary Add-on > the Firefox zip (it stays until Firefox restarts; a permanent install needs the signed add-on).
  4. Open a mesh host: http://10.78.0.189/ or http://name.oneq/ . The toolbar icon opens the popup: Connect / Disconnect and the members.

  Options: -StartAtLogon also runs the proxy at every logon, independent of the browser; -ProxyArgs --allow-process,NAME admits another program (the proxy serves browsers
  only); -ExtensionId ID registers a store-installed Chromium extension.

Install (macOS, Linux)
----------------------
       ./install.sh --relay https://relay.example.org:8443 --community lan --user alice [--cafile ca.pem] [--name laptop]

  (macOS: a LaunchAgent starts the proxy at login; Linux: a systemd user service. The native host is registered for the browsers found; settings can also be typed in
  the extension.) Then step 3 above with the folder it prints.

Remove
------
  Windows:  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 [-Purge]      macOS/Linux: ./uninstall.sh [--purge]
  and remove "oneq mesh" on the browser's extensions page.

Notes
-----
  * TCP only (no ping/UDP), IPv4, only for the browser; the system-wide route is the oneq client with its TUN adapter.
  * The proxy listens on 127.0.0.1 without a password: every program of every user of this computer can use it while it runs.
  * The extension asks for the proxy, storage and alarms permissions and for access to 127.0.0.1; it contacts nothing else.
  * Not in a web store: the browser may remind you at start-up that an unpacked extension is loaded.
