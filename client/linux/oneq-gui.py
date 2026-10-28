#!/usr/bin/env python3
"""oneq GTK3 GUI — identical layout to Flutter Windows/Android client.

Startup detection (in order):
  1. oneqclient running and ui.url reachable  → API mode  (full control via HTTP)
  2. oneqnode@<name>.service active            → Monitor mode (reads config, shows status, no second node)
  3. Nothing detected                          → Standalone (connect via oneqclient)
"""
import gi
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gtk, Gdk, GLib

import configparser
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import urllib.request
import urllib.error

# ── Mode detection ────────────────────────────────────────────────────────────

MODE_API  = "api"   # oneqclient ui.url reachable
MODE_SVC  = "svc"   # oneqnode@<name> systemd service
MODE_NONE = "none"  # nothing — standalone

def _find_ui_url():
    home = pathlib.Path.home()
    for p in [
        home / ".config/oneq/ui.url",
        pathlib.Path("/etc/oneq/ui.url"),
        pathlib.Path("/Library/Application Support/oneq/ui.url"),
        home / "Library/Application Support/oneq/ui.url",
    ]:
        try:
            text = p.read_text().strip()
            if text:
                return text
        except OSError:
            pass
    return None


def _api_call(base_url, method, path, body=None, timeout=5):
    url = base_url.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _detect_mode():
    """Returns (mode, info_dict).

    Priority:
      1. oneqnode.py process running  → MODE_SVC (system-managed Python node)
      2. systemctl oneqnode@* active  → MODE_SVC
      3. oneqclient ui.url reachable  → MODE_API (Rust client with live node)
      4. nothing                      → MODE_NONE
    """
    # 1. oneqnode process (Python node) — check before oneqclient ui
    try:
        out = subprocess.check_output(
            ["pgrep", "-a", "-f", "oneqnode.py"],
            text=True, stderr=subprocess.DEVNULL, timeout=3,
        )
        for line in out.strip().split("\n"):
            if "oneqnode.py" not in line:
                continue
            parts = line.split()
            node = "oneq"
            cfg = "/etc/oneq/node.conf"
            try:
                node = parts[parts.index("--node") + 1]
            except (ValueError, IndexError):
                pass
            try:
                cfg = parts[parts.index("--config") + 1]
            except (ValueError, IndexError):
                pass
            return MODE_SVC, {"node": node, "config": cfg}
    except Exception:
        pass

    # 2. systemctl fallback
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--state=active", "--plain", "--no-legend", "--all"],
            text=True, stderr=subprocess.DEVNULL, timeout=3,
        )
        for line in out.split("\n"):
            if "oneqnode@" in line:
                unit = line.split()[0]
                node = unit.replace("oneqnode@", "").replace(".service", "")
                return MODE_SVC, {"node": node, "config": "/etc/oneq/node.conf"}
    except Exception:
        pass

    # 3. oneqclient ui.url (Rust client with its own node)
    url = _find_ui_url()
    if url:
        try:
            _api_call(url, "GET", "/api/status", timeout=2)
            return MODE_API, {"url": url}
        except Exception:
            pass

    return MODE_NONE, {}


# ── oneqnode config reader ────────────────────────────────────────────────────

def _read_node_conf(cfg_file, node_name):
    """Read settings from oneqnode INI config. Returns dict matching Settings fields."""
    result = {}
    try:
        cp = configparser.ConfigParser()
        cp.read(cfg_file)
        # merge: defaults first, then node-specific
        for section in ["defaults", node_name]:
            if not cp.has_section(section):
                continue
            s = dict(cp[section])
            if "relays" in s:
                result["relays"] = re.sub(r"[,\s]+", "\n", s["relays"]).strip()
            if "community" in s:
                result["community"] = s["community"].strip()
            if "user" in s:
                result["user"] = s["user"].strip()
            if "name" in s:
                result["name"] = s["name"].strip()
            cafile = s.get("cafile", "")
            if cafile:
                try:
                    result["ca"] = pathlib.Path(cafile.strip()).read_text()
                except OSError:
                    pass
            if "force_relay" in s:
                result["force_relay"] = s["force_relay"].lower() in ("yes", "true", "1")
            if "accept_routes" in s:
                result["accept_routes"] = s["accept_routes"].lower() in ("yes", "true", "1")
    except Exception:
        pass
    return result


def _node_status(node_name):
    """Poll status of a oneqnode: IP from interface + log tail from journald."""
    snap = {"state": "offline", "node": node_name}
    iface = f"oneq-{node_name}"
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface],
            text=True, stderr=subprocess.DEVNULL, timeout=2,
        )
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("inet ") and not line.startswith("inet6"):
                parts = line.split()
                ip_prefix = parts[1]
                snap["ip"] = ip_prefix.split("/")[0]
                snap["prefix"] = ip_prefix.split("/")[1]
                snap["state"] = "connected"
                break
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["journalctl", "-u", f"oneqnode@{node_name}", "-n", "40",
             "--no-pager", "--output=short", "--no-hostname"],
            text=True, stderr=subprocess.DEVNULL, timeout=3,
        )
        snap["log"] = [l for l in out.strip().split("\n") if l]
    except Exception:
        pass
    return snap


def _svc_control(node_name, action):
    """start/stop/restart a oneqnode@name service (needs permissions)."""
    subprocess.run(
        ["systemctl", action, f"oneqnode@{node_name}"],
        timeout=10, check=True,
    )


# ── Settings model ────────────────────────────────────────────────────────────

SETTINGS_FILE = pathlib.Path.home() / ".config/oneq/gui-settings.json"


class Settings:
    def __init__(self):
        self.relays = ""
        self.community = ""
        self.user = ""
        self.name = ""
        self.ca = ""
        self.force_relay = False
        self.accept_routes = False
        self.exit_node = ""
        self.start_hidden = False
        self.auto_start = False
        self.update_check = True

    def relay_list(self):
        return [s for s in re.split(r"[\s,]+", self.relays) if s]

    def is_configured(self):
        return bool(self.relay_list() and self.community and self.user)

    def to_api_dict(self):
        return {
            "relays": self.relay_list(),
            "community": self.community,
            "user": self.user,
            "name": self.name,
            "ca_pem": self.ca,
            "force_relay": self.force_relay,
            "accept_routes": self.accept_routes,
            "exit_node": self.exit_node,
            "start_hidden": self.start_hidden,
            "auto_start": self.auto_start,
            "update_check": self.update_check,
        }

    def save_local(self):
        SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(self.to_api_dict(), indent=2))

    @classmethod
    def load_local(cls):
        s = cls()
        try:
            j = json.loads(SETTINGS_FILE.read_text())
            relays = j.get("relays", [])
            s.relays = "\n".join(relays) if isinstance(relays, list) else str(relays)
            s.community = j.get("community", "")
            s.user = j.get("user", "")
            s.name = j.get("name", "")
            s.ca = j.get("ca_pem", "")
            s.force_relay = bool(j.get("force_relay", False))
            s.accept_routes = bool(j.get("accept_routes", False))
            s.exit_node = j.get("exit_node", "")
            s.start_hidden = bool(j.get("start_hidden", False))
            s.auto_start = bool(j.get("auto_start", False))
            s.update_check = j.get("update_check", True) is not False
        except OSError:
            pass
        return s

    @classmethod
    def from_node_conf(cls, cfg_file, node_name):
        s = cls()
        d = _read_node_conf(cfg_file, node_name)
        for k, v in d.items():
            if hasattr(s, k):
                setattr(s, k, v)
        return s

    @classmethod
    def from_json(cls, j):
        s = cls()
        relays = j.get("relays", [])
        if not relays or not all(str(r).startswith("https://") for r in relays):
            raise ValueError('"relays" must be a list of https:// URLs')
        s.relays = "\n".join(relays)
        s.community = j.get("community", "")
        s.user = j.get("user", "")
        s.name = j.get("name", "")
        s.ca = j.get("ca_pem", "")
        s.force_relay = bool(j.get("force_relay", False))
        s.accept_routes = bool(j.get("accept_routes", False))
        s.exit_node = j.get("exit_node", "")
        s.start_hidden = bool(j.get("start_hidden", False))
        s.auto_start = bool(j.get("auto_start", False))
        s.update_check = j.get("update_check", True) is not False
        return s


# ── Export / import ───────────────────────────────────────────────────────────

def _key_file():
    return str(pathlib.Path.home() / ".config/oneq/node.key")


def build_export_json(settings, password="", with_password=False, with_key=False):
    payload = {"format": "oneq-settings", "version": 1, "settings": settings.to_api_dict()}
    if with_password and password:
        payload["password"] = password
    if with_key:
        try:
            payload["node_key"] = pathlib.Path(_key_file()).read_text().strip()
        except OSError:
            pass
    return json.dumps(payload, indent=2)


def import_json(text, settings):
    try:
        j = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Not valid JSON: {e}")
    if j.get("format") != "oneq-settings":
        raise ValueError('Not an oneq settings file (missing "format": "oneq-settings")')
    if "settings" not in j:
        raise ValueError('Missing "settings" key')
    new_s = Settings.from_json(j["settings"])
    for attr in ("relays", "community", "user", "name", "ca",
                 "force_relay", "accept_routes", "exit_node",
                 "start_hidden", "auto_start", "update_check"):
        setattr(settings, attr, getattr(new_s, attr))
    password = j.get("password", "")
    node_key = j.get("node_key", "")
    if node_key:
        pathlib.Path(_key_file()).write_text(node_key)
    return password, ("Imported (with password)" if password else "Imported")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_bytes(b):
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.0f} {unit}"
        b /= 1024
    return f"{b:.1f} GB"


def _thread(fn, *args):
    threading.Thread(target=fn, args=args, daemon=True).start()


def _idle(fn, *args):
    GLib.idle_add(fn, *args)


# ── Settings window ───────────────────────────────────────────────────────────

class SettingsWindow(Gtk.Window):
    def __init__(self, parent, mode, svc_info, settings, password, snap, on_saved):
        super().__init__(title="Settings", transient_for=parent, modal=True)
        self.set_default_size(520, 700)
        self.set_border_width(0)
        self._mode = mode
        self._svc_info = svc_info
        self._settings = settings
        self._password_val = password
        self._snap = snap
        self._on_saved = on_saved
        self._with_password = False
        self._with_key = False
        # In SVC mode fields are read-only (config owned by root)
        self._readonly = (mode == MODE_SVC)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(outer)

        if self._readonly:
            bar = Gtk.InfoBar()
            bar.set_message_type(Gtk.MessageType.INFO)
            bar.get_content_area().pack_start(
                Gtk.Label(label=f"Read-only — node '{svc_info.get('node','')}' is managed by the system service. "
                                "Edit /etc/oneq/node.conf as root to change."),
                True, True, 0)
            outer.pack_start(bar, False, False, 0)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        outer.pack_start(scroll, True, True, 0)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        body.set_border_width(16)
        scroll.add(body)

        # ── Connection ──
        self._section(body, "Connection")
        self._relays   = self._multiline(body, "Relays (https://host:port, one per line)", settings.relays, lines=3)
        self._community = self._entry(body, "Community", settings.community)
        self._user      = self._entry(body, "User", settings.user)
        self._password  = self._entry(body, "Password (not saved)", self._password_val, secret=True)
        self._name      = self._entry(body, "Device name (optional)", settings.name)
        self._ca        = self._multiline(body, "Private CA certificate, PEM (empty = public CAs)", settings.ca, lines=4)

        self._force_relay    = self._switch(body, "Send everything through the relay", settings.force_relay)
        self._accept_routes  = self._switch(
            body,
            "Use routed networks\nReach the private networks the administrator routed through a gateway member.",
            settings.accept_routes,
        )

        self._section_label(body, "Exit node (route internet traffic through)")
        exit_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        exit_hbox.set_margin_bottom(8)
        body.pack_start(exit_hbox, False, False, 0)
        self._exit_combo = Gtk.ComboBoxText()
        self._exit_combo.append("", "None — direct internet")
        if snap:
            for p in snap.get("peers", []):
                if p.get("exit_node"):
                    lbl = p["name"]
                    if p.get("public_ip"):
                        lbl += f"  ({p['public_ip']})"
                    self._exit_combo.append(p["name"], lbl)
        if settings.exit_node:
            known = [p["name"] for p in (snap or {}).get("peers", []) if p.get("exit_node")]
            if settings.exit_node not in known:
                self._exit_combo.append(settings.exit_node, settings.exit_node)
        self._exit_combo.set_active_id(settings.exit_node or "")
        self._exit_combo.set_hexpand(True)
        self._exit_combo.set_sensitive(not self._readonly)
        exit_hbox.pack_start(self._exit_combo, True, True, 0)

        self._start_hidden  = self._switch(body, "Start hidden in the tray", settings.start_hidden)
        self._auto_start    = self._switch(
            body,
            "Start at boot\nThe node runs as a background service, started before anyone logs in.",
            settings.auto_start,
        )
        self._update_check  = self._checkbox(body, "Check for updates automatically", settings.update_check)

        upd_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        upd_hbox.set_margin_bottom(12)
        body.pack_start(upd_hbox, False, False, 0)
        upd_btn = Gtk.Button(label="Check for updates")
        upd_btn.set_sensitive(not self._readonly and mode == MODE_API)
        upd_btn.connect("clicked", self._check_updates)
        self._upd_msg = Gtk.Label(label="")
        self._upd_msg.set_halign(Gtk.Align.START)
        upd_hbox.pack_start(upd_btn, False, False, 0)
        upd_hbox.pack_start(self._upd_msg, False, False, 0)

        if not self._readonly:
            save_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
            save_box.set_margin_bottom(8)
            body.pack_start(save_box, False, False, 0)
            save_btn = Gtk.Button(label="Save")
            save_btn.get_style_context().add_class("suggested-action")
            save_btn.connect("clicked", self._save)
            save_box.pack_start(save_btn, False, False, 0)

        self._sep(body)

        # ── Export / import ──
        self._section(body, "Export and import")
        desc = Gtk.Label(label="Settings are exported as a JSON file. Secrets are left out unless you tick them.")
        desc.set_halign(Gtk.Align.START)
        desc.set_line_wrap(True)
        desc.set_margin_bottom(6)
        body.pack_start(desc, False, False, 0)

        self._chk_password = self._checkbox(body, "Include the password (plain text)", False)
        self._chk_password.connect("toggled", lambda w: setattr(self, "_with_password", w.get_active()))
        self._chk_key = self._checkbox(body, "Include this device's node key (keeps its address; moves the identity)", False)
        self._chk_key.connect("toggled", lambda w: setattr(self, "_with_key", w.get_active()))

        exp_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        exp_hbox.set_margin_bottom(6)
        body.pack_start(exp_hbox, False, False, 0)
        exp_file_btn = Gtk.Button(label="Export to file…")
        exp_file_btn.connect("clicked", self._export_file)
        exp_clip_btn = Gtk.Button(label="Copy to clipboard")
        exp_clip_btn.connect("clicked", self._export_clipboard)
        exp_hbox.pack_start(exp_file_btn, False, False, 0)
        exp_hbox.pack_start(exp_clip_btn, False, False, 0)

        imp_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        imp_hbox.set_margin_bottom(12)
        body.pack_start(imp_hbox, False, False, 0)
        imp_file_btn = Gtk.Button(label="Import from file…")
        imp_file_btn.set_sensitive(not self._readonly)
        imp_file_btn.connect("clicked", self._import_file)
        imp_clip_btn = Gtk.Button(label="Paste from clipboard")
        imp_clip_btn.set_sensitive(not self._readonly)
        imp_clip_btn.connect("clicked", self._import_clipboard)
        imp_hbox.pack_start(imp_file_btn, False, False, 0)
        imp_hbox.pack_start(imp_clip_btn, False, False, 0)

        self._sep(body)

        # ── Background service ──
        self._section(body, "Background service")
        node_label = svc_info.get("node", "") if mode == MODE_SVC else ""
        svc_name = f"oneqnode@{node_label}" if node_label else "oneqclient service"
        self._svc_desc = Gtk.Label(label=f"Service: {svc_name}\nStatus: —")
        self._svc_desc.set_halign(Gtk.Align.START)
        self._svc_desc.set_line_wrap(True)
        self._svc_desc.set_margin_bottom(8)
        body.pack_start(self._svc_desc, False, False, 0)

        svc_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        svc_hbox.set_margin_bottom(12)
        body.pack_start(svc_hbox, False, False, 0)
        self._svc_start     = Gtk.Button(label="Start")
        self._svc_start.connect("clicked", lambda _: self._svc_action("start"))
        self._svc_stop      = Gtk.Button(label="Stop")
        self._svc_stop.connect("clicked", lambda _: self._svc_action("stop"))
        self._svc_restart   = Gtk.Button(label="Restart")
        self._svc_restart.connect("clicked", lambda _: self._svc_action("restart"))
        if mode != MODE_SVC:
            self._svc_uninstall = Gtk.Button(label="Uninstall")
            self._svc_uninstall.connect("clicked", lambda _: self._svc_action("uninstall"))
            svc_hbox.pack_start(self._svc_uninstall, False, False, 0)
        svc_hbox.pack_start(self._svc_start, False, False, 0)
        svc_hbox.pack_start(self._svc_stop, False, False, 0)
        svc_hbox.pack_start(self._svc_restart, False, False, 0)

        self._note_label = Gtk.Label(label="")
        self._note_label.set_halign(Gtk.Align.START)
        self._note_label.set_line_wrap(True)
        self._note_label.set_margin_top(8)
        self._note_label.set_selectable(True)
        body.pack_start(self._note_label, False, False, 0)

        self.show_all()
        self._refresh_service()

    # ── helpers ──────────────────────────────────────────────────────────────

    def _section(self, parent, title):
        lbl = Gtk.Label()
        lbl.set_markup(f"<b>{title}</b>")
        lbl.set_halign(Gtk.Align.START)
        lbl.set_margin_top(8)
        lbl.set_margin_bottom(4)
        parent.pack_start(lbl, False, False, 0)

    def _section_label(self, parent, title):
        lbl = Gtk.Label(label=title)
        lbl.set_halign(Gtk.Align.START)
        lbl.set_margin_top(4)
        parent.pack_start(lbl, False, False, 0)

    def _sep(self, parent):
        sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        sep.set_margin_top(12)
        sep.set_margin_bottom(12)
        parent.pack_start(sep, False, False, 0)

    def _entry(self, parent, label, value, secret=False):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_bottom(8)
        lbl = Gtk.Label(label=label)
        lbl.set_halign(Gtk.Align.START)
        box.pack_start(lbl, False, False, 0)
        entry = Gtk.Entry()
        entry.set_text(value or "")
        entry.set_visibility(not secret)
        entry.set_hexpand(True)
        entry.set_editable(not self._readonly or secret)
        box.pack_start(entry, False, False, 0)
        parent.pack_start(box, False, False, 0)
        return entry

    def _multiline(self, parent, label, value, lines=3):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        box.set_margin_bottom(8)
        lbl = Gtk.Label(label=label)
        lbl.set_halign(Gtk.Align.START)
        box.pack_start(lbl, False, False, 0)
        frame = Gtk.Frame()
        tv = Gtk.TextView()
        tv.get_buffer().set_text(value or "")
        tv.set_wrap_mode(Gtk.WrapMode.WORD)
        tv.set_hexpand(True)
        tv.set_size_request(-1, lines * 24)
        tv.set_editable(not self._readonly)
        frame.add(tv)
        box.pack_start(frame, False, False, 0)
        parent.pack_start(box, False, False, 0)
        return tv

    def _switch(self, parent, label, active):
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        row.set_margin_bottom(4)
        lines = label.split("\n", 1)
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        col.set_hexpand(True)
        title_lbl = Gtk.Label(label=lines[0])
        title_lbl.set_halign(Gtk.Align.START)
        col.pack_start(title_lbl, False, False, 0)
        if len(lines) > 1:
            sub = Gtk.Label(label=lines[1])
            sub.set_halign(Gtk.Align.START)
            sub.set_line_wrap(True)
            sub.get_style_context().add_class("dim-label")
            col.pack_start(sub, False, False, 0)
        sw = Gtk.Switch()
        sw.set_active(active)
        sw.set_valign(Gtk.Align.CENTER)
        sw.set_sensitive(not self._readonly)
        row.pack_start(col, True, True, 0)
        row.pack_start(sw, False, False, 0)
        parent.pack_start(row, False, False, 0)
        return sw

    def _checkbox(self, parent, label, active):
        chk = Gtk.CheckButton(label=label)
        chk.set_active(active)
        chk.set_margin_bottom(4)
        parent.pack_start(chk, False, False, 0)
        return chk

    def _say(self, msg, error=False):
        def _do():
            self._note_label.set_text(msg)
            color = Gdk.RGBA(0.8, 0.1, 0.1, 1) if error else Gdk.RGBA(0.1, 0.5, 0.3, 1)
            self._note_label.override_color(Gtk.StateFlags.NORMAL, color)
        _idle(_do)

    def _read_form(self):
        def _tv(tv):
            buf = tv.get_buffer()
            return buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        self._settings.relays        = _tv(self._relays)
        self._settings.community     = self._community.get_text().strip()
        self._settings.user          = self._user.get_text().strip()
        self._settings.name          = self._name.get_text().strip()
        self._settings.ca            = _tv(self._ca)
        self._password_val           = self._password.get_text()
        self._settings.force_relay   = self._force_relay.get_active()
        self._settings.accept_routes = self._accept_routes.get_active()
        self._settings.exit_node     = self._exit_combo.get_active_id() or ""
        self._settings.start_hidden  = self._start_hidden.get_active()
        self._settings.auto_start    = self._auto_start.get_active()
        self._settings.update_check  = self._update_check.get_active()

    def _fill_form(self):
        s = self._settings
        self._relays.get_buffer().set_text(s.relays)
        self._community.set_text(s.community)
        self._user.set_text(s.user)
        self._name.set_text(s.name)
        self._ca.get_buffer().set_text(s.ca)
        self._password.set_text(self._password_val)
        self._force_relay.set_active(s.force_relay)
        self._accept_routes.set_active(s.accept_routes)
        self._start_hidden.set_active(s.start_hidden)
        self._auto_start.set_active(s.auto_start)
        self._update_check.set_active(s.update_check)

    # ── actions ──────────────────────────────────────────────────────────────

    def _save(self, _=None):
        self._read_form()
        self._settings.save_local()
        def _do():
            if self._mode == MODE_API:
                url = self._svc_info.get("url", "")
                try:
                    _api_call(url, "POST", "/api/settings", self._settings.to_api_dict())
                    self._say("Saved.")
                except Exception as e:
                    self._say(f"Saved locally (service: {e})")
            else:
                self._say("Saved locally.")
        _thread(_do)
        if self._on_saved:
            self._on_saved(self._settings, self._password_val)

    def _check_updates(self, _=None):
        if self._mode != MODE_API:
            return
        self._upd_msg.set_text("Checking…")
        url = self._svc_info.get("url", "")
        def _do():
            try:
                r = _api_call(url, "POST", "/api/update/check")
                msg = r.get("message", "Up to date")
            except Exception as e:
                msg = str(e)
            _idle(self._upd_msg.set_text, msg)
        _thread(_do)

    def _export_text(self):
        self._read_form()
        return build_export_json(self._settings, self._password_val,
                                  with_password=self._with_password, with_key=self._with_key)

    def _confirm_secrets(self):
        if not self._with_password and not self._with_key:
            return True
        parts = []
        if self._with_password:
            parts.append("your password in plain text")
        if self._with_key:
            parts.append("this device's node key")
        dlg = Gtk.MessageDialog(transient_for=self, modal=True,
                                message_type=Gtk.MessageType.WARNING,
                                buttons=Gtk.ButtonsType.NONE,
                                text="The file will contain secrets")
        dlg.format_secondary_text(
            f"The exported file will contain {' and '.join(parts)}. "
            "Anyone who gets the file can use it to join your network.")
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dlg.add_button("Export anyway", Gtk.ResponseType.OK)
        resp = dlg.run()
        dlg.destroy()
        return resp == Gtk.ResponseType.OK

    def _export_file(self, _=None):
        if not self._confirm_secrets():
            return
        text = self._export_text()
        dlg = Gtk.FileChooserDialog(title="Export settings", transient_for=self,
                                     action=Gtk.FileChooserAction.SAVE)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dlg.add_button("Save", Gtk.ResponseType.OK)
        dlg.set_current_name("oneq-settings.json")
        ff = Gtk.FileFilter()
        ff.set_name("oneq settings (*.json)")
        ff.add_pattern("*.json")
        dlg.add_filter(ff)
        if dlg.run() == Gtk.ResponseType.OK:
            path = dlg.get_filename()
            try:
                pathlib.Path(path).write_text(text)
                self._say(f"Exported to {path}")
            except Exception as e:
                self._say(f"Export failed: {e}", error=True)
        dlg.destroy()

    def _export_clipboard(self, _=None):
        if not self._confirm_secrets():
            return
        text = self._export_text()
        clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        clip.set_text(text, -1)
        clip.store()
        self._say("Copied to the clipboard.")

    def _import_text(self, text):
        try:
            pw, msg = import_json(text, self._settings)
            if pw:
                self._password_val = pw
            self._fill_form()
            self._say(msg)
        except Exception as e:
            self._say(f"Import failed: {e}", error=True)

    def _import_file(self, _=None):
        dlg = Gtk.FileChooserDialog(title="Import settings", transient_for=self,
                                     action=Gtk.FileChooserAction.OPEN)
        dlg.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dlg.add_button("Open", Gtk.ResponseType.OK)
        ff = Gtk.FileFilter()
        ff.set_name("oneq settings (*.json)")
        ff.add_pattern("*.json")
        dlg.add_filter(ff)
        if dlg.run() == Gtk.ResponseType.OK:
            path = dlg.get_filename()
            try:
                text = pathlib.Path(path).read_text()
                if len(text) > 1024 * 1024:
                    raise ValueError("File too large")
                self._import_text(text)
            except Exception as e:
                self._say(f"Import failed: {e}", error=True)
        dlg.destroy()

    def _import_clipboard(self, _=None):
        clip = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        text = clip.wait_for_text()
        if text:
            self._import_text(text)
        else:
            self._say("Clipboard is empty.", error=True)

    def _refresh_service(self):
        mode = self._mode
        info = self._svc_info
        def _do():
            if mode == MODE_API:
                try:
                    r = _api_call(info["url"], "GET", "/api/service")
                    state = r.get("state", "unknown")
                    _idle(self._svc_desc.set_text,
                          f"Service: oneqclient\nStatus: running ({state})")
                except Exception:
                    _idle(self._svc_desc.set_text,
                          "Service: oneqclient\nStatus: not running")
            elif mode == MODE_SVC:
                node = info.get("node", "")
                try:
                    out = subprocess.check_output(
                        ["systemctl", "is-active", f"oneqnode@{node}"],
                        text=True, stderr=subprocess.DEVNULL, timeout=3,
                    ).strip()
                    _idle(self._svc_desc.set_text,
                          f"Service: oneqnode@{node}\nStatus: {out}")
                except subprocess.CalledProcessError as e:
                    _idle(self._svc_desc.set_text,
                          f"Service: oneqnode@{node}\nStatus: inactive")
                except Exception as e:
                    _idle(self._svc_desc.set_text,
                          f"Service: oneqnode@{node}\nStatus: {e}")
        _thread(_do)

    def _svc_action(self, what):
        for b in (self._svc_start, self._svc_stop, self._svc_restart):
            b.set_sensitive(False)
        mode = self._mode
        info = self._svc_info
        def _do():
            try:
                if mode == MODE_API:
                    _api_call(info["url"], "POST", f"/api/service/{what}")
                elif mode == MODE_SVC:
                    _svc_control(info.get("node", "oneq"), what)
                else:
                    raise RuntimeError("No service to control")
                self._say(f"Service: {what} done.")
            except Exception as e:
                self._say(f"Service {what} failed: {e}", error=True)
            _idle(self._refresh_service)
            _idle(lambda: [b.set_sensitive(True)
                           for b in (self._svc_start, self._svc_stop, self._svc_restart)])
        _thread(_do)


# ── Main window ───────────────────────────────────────────────────────────────

class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app, mode, svc_info):
        super().__init__(application=app, title="oneq")
        self.set_default_size(520, 680)
        self._mode = mode
        self._svc_info = svc_info
        self._snap = None
        self._active = False
        self._busy = False

        if mode == MODE_SVC:
            # Read settings from oneqnode config (read-only)
            cfg = svc_info.get("config", "/etc/oneq/node.conf")
            node = svc_info.get("node", "oneq")
            self._settings = Settings.from_node_conf(cfg, node)
            # Fall back to gui-settings.json if config unreadable
            if not self._settings.is_configured():
                self._settings = Settings.load_local()
            self._password = ""
        else:
            self._settings = Settings.load_local()
            self._password = ""

        self._build_ui()
        self.show_all()
        self._refresh()
        GLib.timeout_add(2000, self._poll)

    def _build_ui(self):
        hb = Gtk.HeaderBar()
        hb.set_show_close_button(True)
        hb.set_title("oneq")
        self.set_titlebar(hb)

        # status chip
        chip = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self._dot  = Gtk.Label(label="●")
        self._stxt = Gtk.Label(label="offline")
        chip.pack_start(self._dot, False, False, 0)
        chip.pack_start(self._stxt, False, False, 0)
        hb.pack_start(chip)

        # mode badge (SVC mode only)
        if self._mode == MODE_SVC:
            node = self._svc_info.get("node", "")
            badge = Gtk.Label()
            badge.set_markup(f'<span size="small" style="italic">system: oneqnode@{node}</span>')
            hb.pack_start(badge)

        # settings button
        btn = Gtk.Button()
        btn.set_image(Gtk.Image.new_from_icon_name("preferences-system", Gtk.IconSize.BUTTON))
        btn.set_tooltip_text("Settings")
        btn.connect("clicked", self._open_settings)
        hb.pack_end(btn)

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(vbox)

        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroll.set_vexpand(True)
        vbox.pack_start(scroll, True, True, 0)

        self._body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self._body.set_border_width(16)
        scroll.add(self._body)

        self._build_static()

    def _build_static(self):
        body = self._body

        # "Set up" card
        self._setup_card = Gtk.Frame()
        si = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        si.set_border_width(12)
        si.pack_start(Gtk.Image.new_from_icon_name("dialog-information", Gtk.IconSize.BUTTON), False, False, 0)
        col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t = Gtk.Label(); t.set_markup("<b>Set up the connection</b>"); t.set_halign(Gtk.Align.START)
        s = Gtk.Label(label="Open Settings to enter the relay, community and user, or import a settings file.")
        s.set_halign(Gtk.Align.START); s.set_line_wrap(True)
        col.pack_start(t, False, False, 0); col.pack_start(s, False, False, 0)
        si.pack_start(col, True, True, 0)
        ob = Gtk.Button(label="Open Settings →")
        ob.connect("clicked", self._open_settings)
        si.pack_start(ob, False, False, 0)
        self._setup_card.add(si)
        self._setup_card.set_margin_bottom(8)
        body.pack_start(self._setup_card, False, False, 0)

        # configured card
        self._conn_card = Gtk.Frame()
        ci = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ci.set_border_width(12)
        col2 = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self._conn_title = Gtk.Label(label=""); self._conn_title.set_halign(Gtk.Align.START)
        self._conn_sub   = Gtk.Label(label=""); self._conn_sub.set_halign(Gtk.Align.START)
        col2.pack_start(self._conn_title, False, False, 0)
        col2.pack_start(self._conn_sub, False, False, 0)
        ci.pack_start(col2, True, True, 0)
        eb = Gtk.Button()
        eb.set_image(Gtk.Image.new_from_icon_name("document-edit", Gtk.IconSize.BUTTON))
        eb.connect("clicked", self._open_settings)
        ci.pack_start(eb, False, False, 0)
        self._conn_card.add(ci)
        self._conn_card.set_margin_bottom(8)
        self._conn_card.set_no_show_all(True)
        body.pack_start(self._conn_card, False, False, 0)

        # password + connect — hidden in SVC mode
        if self._mode != MODE_SVC:
            pw_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            pw_hbox.set_margin_bottom(8)
            body.pack_start(pw_hbox, False, False, 0)
            self._pw_entry = Gtk.Entry()
            self._pw_entry.set_visibility(False)
            self._pw_entry.set_hexpand(True)
            self._pw_entry.set_placeholder_text("Password")
            self._pw_entry.set_text(self._password)
            self._pw_entry.connect("activate", lambda _: self._toggle())
            self._pw_entry.connect("changed", lambda w: setattr(self, "_password", w.get_text()))
            self._connect_btn = Gtk.Button(label="Connect")
            self._connect_btn.get_style_context().add_class("suggested-action")
            self._connect_btn.connect("clicked", lambda _: self._toggle())
            pw_hbox.pack_start(self._pw_entry, True, True, 0)
            pw_hbox.pack_start(self._connect_btn, False, False, 0)
        else:
            self._pw_entry = None
            self._connect_btn = None

        self._error_lbl = Gtk.Label(label="")
        self._error_lbl.set_halign(Gtk.Align.START)
        self._error_lbl.set_line_wrap(True)
        self._error_lbl.set_no_show_all(True)
        body.pack_start(self._error_lbl, False, False, 0)

        self._dyn = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        body.pack_start(self._dyn, True, True, 0)

    def _rebuild_dyn(self, snap):
        for c in self._dyn.get_children():
            self._dyn.remove(c)
        if not snap:
            self._dyn.show_all()
            return

        ip = snap.get("ip", "")
        pfx = snap.get("prefix", "")
        if ip:
            ip_frame = Gtk.Frame()
            inner = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            inner.set_border_width(12)
            t = Gtk.Label()
            t.set_markup(f"<b>{ip}/{pfx}</b>")
            t.set_halign(Gtk.Align.START)
            inner.pack_start(t, False, False, 0)
            # community / mtu / relay info (API mode only)
            if self._mode == MODE_API:
                relay_ok = snap.get("relay_connected", False)
                parts = [
                    f"{snap.get('community','')} · MTU {snap.get('mtu','')} · relay {'connected' if relay_ok else 'down'}",
                    f"↑ {_fmt_bytes(snap.get('tx_bytes',0))}   ↓ {_fmt_bytes(snap.get('rx_bytes',0))}",
                ]
                if snap.get("nat_type"):
                    parts.append(f"NAT: {snap['nat_type']}" +
                                 (f" · {snap['nat_public']}" if snap.get("nat_public") else ""))
                if snap.get("message"):
                    parts.append(snap["message"])
                sub = Gtk.Label(label="\n".join(parts))
                sub.set_halign(Gtk.Align.START)
                inner.pack_start(sub, False, False, 0)
            ip_frame.add(inner)
            ip_frame.set_margin_bottom(8)
            self._dyn.pack_start(ip_frame, False, False, 0)

        peers = snap.get("peers", [])
        if peers:
            mem_lbl = Gtk.Label()
            mem_lbl.set_markup("<b>Members</b>")
            mem_lbl.set_halign(Gtk.Align.START)
            mem_lbl.set_margin_bottom(4)
            self._dyn.pack_start(mem_lbl, False, False, 0)

            exit_peers = [p for p in peers if p.get("exit_node")]
            if exit_peers:
                ef = Gtk.Frame()
                ec = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
                rb0 = Gtk.RadioButton.new_with_label(None, "No exit node — Direct internet")
                rb0.set_active(not self._settings.exit_node)
                rb0.connect("toggled", lambda w: self._set_exit("") if w.get_active() else None)
                row0 = Gtk.Box(); row0.set_border_width(4)
                row0.pack_start(rb0, True, True, 4)
                ec.pack_start(row0, False, False, 0)
                grp = rb0
                for p in exit_peers:
                    rb = Gtk.RadioButton.new_with_label_from_widget(grp, p["name"])
                    rb.set_active(self._settings.exit_node == p["name"])
                    rb.connect("toggled", lambda w, n=p["name"]: self._set_exit(n) if w.get_active() else None)
                    row = Gtk.Box(); row.set_border_width(4)
                    row.pack_start(rb, False, False, 0)
                    sl = Gtk.Label(label=p.get("ip","") + (f"  ·  {p['public_ip']}" if p.get("public_ip") else ""))
                    sl.get_style_context().add_class("dim-label")
                    row.pack_start(sl, False, False, 0)
                    if not p.get("online", True): row.set_sensitive(False)
                    ec.pack_start(row, False, False, 0)
                ef.add(ec); ef.set_margin_bottom(8)
                self._dyn.pack_start(ef, False, False, 0)

            for p in peers:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                row.set_margin_bottom(2)
                s = p.get("session", False); o = p.get("online", False)
                icon = Gtk.Image.new_from_icon_name(
                    "network-vpn" if s else ("network-idle" if o else "network-offline"),
                    Gtk.IconSize.SMALL_TOOLBAR)
                row.pack_start(icon, False, False, 0)
                nl = Gtk.Label(label=p.get("name","")); nl.set_halign(Gtk.Align.START)
                row.pack_start(nl, False, False, 0)
                il = Gtk.Label(label=p.get("ip","")); il.get_style_context().add_class("dim-label")
                row.pack_start(il, False, False, 0)
                pl = Gtk.Label(label=p.get("path","") if s else ("connecting" if o else "offline"))
                pl.set_halign(Gtk.Align.END); pl.set_hexpand(True)
                row.pack_start(pl, True, True, 0)
                self._dyn.pack_start(row, False, False, 0)

        log = snap.get("log", [])
        if log:
            exp = Gtk.Expander(label="Log"); exp.set_margin_top(8)
            tv = Gtk.TextView(); tv.set_editable(False)
            tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
            tv.get_style_context().add_class("monospace")
            lines = log if isinstance(log[0], str) else []
            tv.get_buffer().set_text("\n".join(reversed(lines[-60:])))
            sc = Gtk.ScrolledWindow(); sc.set_size_request(-1, 150); sc.add(tv)
            exp.add(sc)
            self._dyn.pack_start(exp, False, False, 0)

        self._dyn.show_all()

    def _set_exit(self, name):
        if self._settings.exit_node == name:
            return
        self._settings.exit_node = name
        self._settings.save_local()
        if self._mode == MODE_API:
            url = self._svc_info.get("url", "")
            _thread(lambda: _api_call(url, "POST", "/api/settings", self._settings.to_api_dict()))

    # ── polling ──────────────────────────────────────────────────────────────

    def _poll(self):
        _thread(self._refresh)
        return True

    def _refresh(self):
        if self._mode == MODE_API:
            url = self._svc_info.get("url", "")
            try:
                snap = _api_call(url, "GET", "/api/status")
                _idle(self._apply_api_snap, snap, None)
            except Exception as e:
                _idle(self._apply_api_snap, None, str(e))
        elif self._mode == MODE_SVC:
            node = self._svc_info.get("node", "oneq")
            snap = _node_status(node)
            _idle(self._apply_svc_snap, snap)
        else:
            _idle(self._apply_api_snap, None, None)

    def _apply_api_snap(self, snap, err):
        self._snap = snap
        if snap:
            state = snap.get("state", "")
            active = state in ("connected", "connecting", "up")
            self._active = active
            color = "#27ae60" if state == "connected" else "#f39c12"
            self._dot.set_markup(f'<span color="{color}">●</span>')
            self._stxt.set_text(state or "offline")
            self._error_lbl.set_text(""); self._error_lbl.hide()
            if self._connect_btn:
                self._connect_btn.set_label("Disconnect" if active else "Connect")
            self._rebuild_dyn(snap if active else None)
        else:
            self._active = False
            self._dot.set_markup('<span color="#888888">●</span>')
            self._stxt.set_text("offline")
            if err and "ui.url" not in err:
                self._error_lbl.set_text(err); self._error_lbl.show()
            if self._connect_btn:
                self._connect_btn.set_label("Connect")
            self._rebuild_dyn(None)
        self._update_cards()

    def _apply_svc_snap(self, snap):
        self._snap = snap
        state = snap.get("state", "offline")
        active = state == "connected"
        color = "#27ae60" if active else "#888888"
        self._dot.set_markup(f'<span color="{color}">●</span>')
        node = self._svc_info.get("node", "")
        self._stxt.set_text(f"{state} (oneqnode@{node})" if node else state)
        self._rebuild_dyn(snap if active else None)
        self._update_cards()

    def _update_cards(self):
        if self._settings.is_configured():
            self._setup_card.hide()
            self._conn_card.show()
            self._conn_title.set_markup(f"<b>{self._settings.user} @ {self._settings.community}</b>")
            self._conn_sub.set_text("\n".join(self._settings.relay_list()))
        else:
            self._setup_card.show()
            self._conn_card.hide()
        if self._connect_btn:
            self._connect_btn.set_sensitive(not self._busy)

    # ── connect / disconnect (API / NONE mode only) ───────────────────────────

    def _toggle(self):
        if self._busy or self._mode == MODE_SVC:
            return
        self._busy = True
        if self._connect_btn:
            self._connect_btn.set_sensitive(False)
        if self._active:
            _thread(self._do_disconnect)
        else:
            _thread(self._do_connect)

    def _do_connect(self):
        url = self._svc_info.get("url", "")
        try:
            _api_call(url, "POST", "/api/connect", {"password": self._password})
            _idle(self._refresh)
        except Exception as e:
            _idle(self._error_lbl.set_text, str(e))
            _idle(self._error_lbl.show)
        finally:
            self._busy = False
            if self._connect_btn:
                _idle(self._connect_btn.set_sensitive, True)

    def _do_disconnect(self):
        url = self._svc_info.get("url", "")
        try:
            _api_call(url, "POST", "/api/disconnect")
            _idle(self._refresh)
        except Exception as e:
            _idle(self._error_lbl.set_text, str(e))
            _idle(self._error_lbl.show)
        finally:
            self._busy = False
            if self._connect_btn:
                _idle(self._connect_btn.set_sensitive, True)

    # ── settings ─────────────────────────────────────────────────────────────

    def _open_settings(self, _=None):
        def _on_saved(new_s, new_pw):
            self._settings = new_s
            self._password = new_pw
            if self._pw_entry:
                self._pw_entry.set_text(new_pw)
            _thread(self._refresh)
        SettingsWindow(self, self._mode, self._svc_info,
                       self._settings, self._password, self._snap, _on_saved)


# ── Application ───────────────────────────────────────────────────────────────

class OneqApp(Gtk.Application):
    def __init__(self, mode, svc_info):
        super().__init__(application_id="ro.example.oneq.gui")
        self._mode = mode
        self._svc_info = svc_info

    def do_activate(self):
        MainWindow(self, self._mode, self._svc_info).present()


def main():
    mode, svc_info = _detect_mode()

    if mode == MODE_NONE:
        # No service running and no ui.url — warn the user
        dlg = Gtk.MessageDialog(
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.NONE,
            text="oneqclient is not running",
        )
        dlg.format_secondary_text(
            "No running oneq service was found.\n\n"
            "Start the background service first:\n"
            "  oneqclient service start\n\n"
            "or run the node directly:\n"
            "  oneqclient up …"
        )
        dlg.add_button("Open anyway", Gtk.ResponseType.OK)
        dlg.add_button("Quit", Gtk.ResponseType.CANCEL)
        resp = dlg.run()
        dlg.destroy()
        if resp != Gtk.ResponseType.OK:
            sys.exit(0)

    app = OneqApp(mode, svc_info)
    sys.exit(app.run(sys.argv))


if __name__ == "__main__":
    main()
