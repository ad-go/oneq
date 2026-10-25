"""TLS helpers: post-quantum only (TLS 1.3, group X25519MLKEM768, no fallback).

Python 3.13's ssl module has no SSLContext.set_groups, so the group restriction is
applied through a dedicated OPENSSL_CONF (pq_openssl.cnf) that only our processes load.
This module MUST be imported before `ssl` is first imported anywhere in the process.
"""
import os
import sys

_CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pq_openssl.cnf")

if "ssl" in sys.modules and os.environ.get("OPENSSL_CONF") != _CONF:
    raise RuntimeError("pqtls must be imported before ssl (OPENSSL_CONF is read at first use)")
os.environ["OPENSSL_CONF"] = _CONF

import ssl  # noqa: E402

CONF_PATH = _CONF


def client_context(cafile=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cafile:
        ctx.load_verify_locations(cafile)
    else:
        ctx.load_default_certs()
    return ctx


def server_context(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    return ctx
