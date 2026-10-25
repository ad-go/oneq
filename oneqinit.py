"""`oneqrelay init`: first-time setup of a relay that is not installed from the Debian package (Windows, macOS, a plain directory).

Creates, in one directory, everything `oneqrelay run --config DIR/relay.conf` needs: a small private CA and a relay certificate signed by it
(clients trust ca.crt), the federation secret, the operator password and the second factor of the admin page (TOTP), and relay.conf.
Nothing existing is overwritten. The CA key stays in the directory so the certificate can be renewed; the directory is restricted to the
service account (mode 700 on POSIX, an ACL for SYSTEM and Administrators on Windows).
"""
import base64
import datetime
import ipaddress
import os
import secrets
import socket
import subprocess
import sys

import oneqconf
import oneqtotp


def _pem_key(key) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _write(path: str, data, force=False, private=True):
    if os.path.exists(path) and not force:
        raise FileExistsError(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def make_certs(name: str, ips, valid_days: int = 1825):
    """-> (ca_cert_pem, ca_key_pem, relay_cert_pem, relay_key_pem). EC P-256; the relay certificate names the host, the addresses and localhost."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    now = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"oneqrelay CA {name}")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    san = [x509.DNSName(name), x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    for ip in ips:
        san.append(x509.IPAddress(ipaddress.ip_address(ip)))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=valid_days))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    return ca.public_bytes(pem), _pem_key(ca_key), leaf.public_bytes(pem), _pem_key(key)


def restrict(path: str):
    """Only the service account (SYSTEM) and administrators may read the directory."""
    if os.name == "posix":
        os.chmod(path, 0o700)
    else:
        subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"],
                       check=True, stdout=subprocess.DEVNULL)


def init(directory: str, name: str, ips, port: int = 8443, relay_id: str = "", admin: bool = True, out=print) -> dict:
    directory = os.path.abspath(directory)
    conf = os.path.join(directory, "relay.conf")
    if os.path.exists(conf):
        raise SystemExit(f"{conf} exists: this directory is already set up (delete it to start over, or edit relay.conf)")
    os.makedirs(directory, exist_ok=True)
    restrict(directory)
    p = lambda n: os.path.join(directory, n)
    ca_crt, ca_key, crt, key = make_certs(name, ips)
    _write(p("ca.crt"), ca_crt, private=False)
    _write(p("ca.key"), ca_key)
    _write(p("relay.crt"), crt, private=False)
    _write(p("relay.key"), key)
    _write(p("relay.secret"), base64.b64encode(secrets.token_bytes(32)).decode() + "\n")
    lines = ["# Written by `oneqrelay init`. Options: see the sample in the oneq documentation (packaging/oneqrelay/etc/oneq/relay.conf).", "[relay]",
             f"id = {relay_id or oneqconf.default_relay_id()}", f"listen = 0.0.0.0:{port}", "insecure_http = no", "trust_proxy = no",
             f"cert = {p('relay.crt').replace(chr(92), '/')}", f"key = {p('relay.key').replace(chr(92), '/')}",
             f"db = {p('registry.db').replace(chr(92), '/')}", f"secret_file = {p('relay.secret').replace(chr(92), '/')}",
             "stun = yes", ""]
    result = {"dir": directory, "ca": p("ca.crt"), "port": port}
    if admin:
        pw = secrets.token_urlsafe(18)
        _write(p("admin.pw"), pw + "\n")
        secret, codes = oneqtotp.TotpStore.create(p("admin.totp"))
        uri = oneqtotp.otpauth_uri(secret, "operator", f"oneqrelay {name}")
        _write(p("admin-enrolment.txt"),
               f"Admin page: https://{name}:{port}/admin/\nOperator password: {pw}\nAuthenticator link: {uri}\nSecret: {secret}\n"
               "Recovery codes (each works once):\n" + "\n".join("  " + c for c in codes) + "\n")
        lines[-1:] = [f"admin_password_file = {p('admin.pw').replace(chr(92), '/')}", f"admin_totp_file = {p('admin.totp').replace(chr(92), '/')}", ""]
        result["enrolment"] = p("admin-enrolment.txt")
        try:
            import segno
            result["qr"] = p("admin-qr.svg")
            segno.make(uri, error="m").save(result["qr"], scale=6, border=3)
        except ImportError:
            pass
    _write(conf, "\n".join(lines), private=False)
    out(f"relay set up in {directory}")
    out(f"  clients must trust: {p('ca.crt')}  (SHA-256 of the file: see `certutil -hashfile` / `shasum -a 256`)")
    out(f"  start it:           oneqrelay run --config {conf}")
    if admin:
        out(f"  admin page:         https://{name}:{port}/admin/  - password and authenticator enrolment are in {p('admin-enrolment.txt')}"
            + (f" (QR: {result['qr']})" if "qr" in result else ""))
        out("                      scan the code, move the password to a password manager and DELETE those files")
    out(f"  open in the firewall: TCP {port} and UDP {port}-{port + 2}")
    return result


def default_name() -> str:
    return socket.getfqdn() or socket.gethostname()


if __name__ == "__main__":
    sys.exit("use: oneqrelay init")
