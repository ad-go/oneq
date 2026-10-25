"""Configuration files of oneqrelay (/etc/oneq/relay.conf) and oneqnode (/etc/oneq/node.conf).

INI format, one value per line, `#` or `;` comment lines (no inline comments). Lists are separated by commas,
spaces or new lines; booleans are yes/no, true/false, on/off, 1/0. Unknown options are an error, so a typo is
never silently ignored. Command-line options always override the file. Secrets (private key, password, federation
secret) are never stored in these files: they only reference separate files with their own permissions.
"""
import configparser
import os
import re
import socket
import tempfile

TRUE = {"1", "yes", "true", "on"}
FALSE = {"0", "no", "false", "off"}
SECTION_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ConfigError(Exception):
    pass


def _parser():
    return configparser.ConfigParser(interpolation=None, delimiters=("=",), comment_prefixes=("#", ";"),
                                     inline_comment_prefixes=None, default_section="__unused__")


def load(path, sections, allowed):
    """Merge the given sections (later ones win). Returns {option: str}; options use `_` for `-`."""
    cp = _parser()
    try:
        with open(path, encoding="utf-8") as f:
            cp.read_file(f, source=path)
    except OSError as e:
        raise ConfigError(f"cannot read {path}: {e.strerror}")
    except configparser.Error as e:
        raise ConfigError(f"{path}: {str(e).splitlines()[0]}")
    out = {}
    for s in sections:
        if not cp.has_section(s):
            continue
        for k, v in cp.items(s):
            kk = k.replace("-", "_")
            if kk not in allowed:
                raise ConfigError(f"{path}: [{s}] unknown option '{k}' (allowed: {', '.join(sorted(allowed))})")
            out[kk] = v.strip()
    return out


def has_section(path, name):
    cp = _parser()
    try:
        with open(path, encoding="utf-8") as f:
            cp.read_file(f, source=path)
    except (OSError, configparser.Error):
        return False
    return cp.has_section(name)


def to_bool(v, key="value"):
    s = v.strip().lower()
    if s in TRUE:
        return True
    if s in FALSE:
        return False
    raise ConfigError(f"option '{key}': '{v}' is not a boolean (yes/no)")


def to_list(v, key="value"):
    return [x for x in re.split(r"[,\s]+", v.strip()) if x]


def to_float(v, key="value"):
    try:
        return float(v)
    except ValueError:
        raise ConfigError(f"option '{key}': '{v}' is not a number")


def to_str(v, key="value"):
    return v


def fill(args, conf, spec):
    """Set argparse results from the file where the command line left them unset.
    spec: {dest: (option_in_file, converter)}. Empty values in the file count as unset."""
    for dest, (key, conv) in spec.items():
        v = conf.get(key, "")
        if v == "":
            continue
        if getattr(args, dest, None) in (None, [], False, ""):
            setattr(args, dest, conv(v, key))


def default_relay_id():
    h = re.sub(r"[^A-Za-z0-9_.-]", "-", socket.gethostname().split(".")[0])[:48]
    return h or "relay"


# ---------------------------------------------------------------- editing node.conf without losing comments

def _drop_section(text, name):
    lines, out, skipping = text.splitlines(keepends=True), [], False
    for ln in lines:
        s = ln.strip()
        if s.startswith("[") and s.endswith("]"):
            skipping = s[1:-1] == name
            if skipping:
                continue
        if not skipping:
            out.append(ln)
    return "".join(out).rstrip("\n") + ("\n" if out else "")


def _write(path, text):
    st = os.stat(path) if os.path.exists(path) else None
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".conf.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    if st:
        os.chmod(tmp, st.st_mode & 0o7777)
        try:
            os.chown(tmp, st.st_uid, st.st_gid)
        except PermissionError:
            pass
    else:
        os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def set_section(path, name, values, header="# written by oneqnode-init; edit freely"):
    if not SECTION_RE.match(name):
        raise ConfigError(f"bad section name '{name}'")
    text = ""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            text = _drop_section(f.read(), name)
    block = f"\n[{name}]\n{header}\n" + "".join(f"{k} = {v}\n" for k, v in values.items())
    _write(path, text.rstrip("\n") + "\n" + block if text.strip() else block.lstrip("\n"))


def del_section(path, name):
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as f:
        old = f.read()
    new = _drop_section(old, name)
    if new == old:
        return False
    _write(path, new)
    return True
