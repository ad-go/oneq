# Exposing oneqrelay to the internet

A oneqrelay needs two things from the outside world: **TCP** (HTTPS or HTTP behind a TLS reverse proxy) for login, registry and
the relay WebSocket, and **UDP** for the STUN service that nodes use to learn their public address and NAT type.
This page lists what to forward and how to check it. Addresses below are documentation examples (`203.0.113.0/24`).

## 1. What must be reachable

| Public address | Protocol and public port → port on the relay | Purpose |
|---|---|---|
| 203.0.113.10 (`x.example.org`) | **TCP 443** (or 8443) → relay | login, registry, relay WebSocket |
| 203.0.113.10 | **UDP 8443, 8444, 8445** → same ports | STUN (public address, NAT type, reachability tests) |
| 203.0.113.11 (`y.example.org`) | same | second relay (federation, failover) |

* The public UDP ports must be the **same numbers** as on the relay: nodes derive the STUN ports from the relay's HTTPS port
  (`stun_port` in `relay.conf`), and the relay announces them exactly as it bound them.
* One address serves one relay on these ports. Plain nodes need no open port: they find their public address through STUN.
* A container or VM usually cannot reach its own public address (no hairpin NAT). Nodes on the same private network
  should use the relay's private address, which must then be present in the certificate (SAN), or the host must resolve the
  public name to the private address.

## 2. Two supported layouts

**A. The relay terminates TLS** (`listen = 0.0.0.0:8443`, `cert =`, `key =` in `relay.conf`). TLS 1.3 with the hybrid group
`X25519MLKEM768` (OpenSSL >= 3.5). Forward TCP 8443 and UDP 8443-8445 to the relay.

**B. A reverse proxy terminates TLS** (nginx, HAProxy, ...). The relay listens on plain HTTP inside a private network:

```
[relay]
listen = 0.0.0.0:80
insecure_http = yes
trust_proxy = yes     # the client address is the last X-Forwarded-For entry set by the proxy
stun_port = 8443      # STUN stays on UDP 8443-8445, forwarded directly to the relay
```

The proxy must pass WebSocket upgrades and keep idle connections open (nginx example):

```
location / {
    proxy_pass http://relay:80;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $proxy_connection;   # or "upgrade"
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
}
```

With `trust_proxy = yes` the relay believes `X-Forwarded-For`. Publish the relay's HTTP port **only** to the proxy (a private
Docker network, a Unix socket or a firewall rule), never to the internet; otherwise any client can forge its address and
bypass rate limits and the reachability test.

Layout B means the TLS connection to the relay is no longer post-quantum-only unless the proxy is configured for it
(`ssl_ecdh_curve X25519MLKEM768:...`). The tunnels between nodes stay post-quantum either way: that protection does not depend on the
TLS in front of the registry.

UDP can be forwarded with plain DNAT (the relay then sees the real client address). A UDP proxy in `stream` mode hides it, and the
reachability test and the rate limiting would see the proxy's address.

## 3. Forwarding snippets

nftables on the host that owns the public address (add an `accept` rule in `forward` if its policy is `drop`):

```
table ip oneq_public {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    ip daddr 203.0.113.10 tcp dport 8443 dnat to 192.168.0.10:8443
    ip daddr 203.0.113.10 udp dport 8443-8445 dnat to 192.168.0.10
  }
}
```

Docker / Compose:

```
ports:
  - "203.0.113.10:8443:8443/udp"
  - "203.0.113.10:8444:8444/udp"
  - "203.0.113.10:8445:8445/udp"
```

## 4. How a client joins from the internet

* Relay addresses, both for failover: `https://x.example.org` and `https://y.example.org` (add the port if you use 8443).
* If the certificates come from a private CA, import it once: the apps have a "Private CA certificate" field in Settings (or import a
  settings file containing it); on the command line use `oneqclient up --cafile ca.crt ...` or `oneqnode run --cafile /etc/oneq/ca.crt ...`.
  With a public CA (for example Let's Encrypt in front of the relay) nothing has to be imported.
* Accounts are created with `oneqrelay admin ...` or in the admin page.

## 5. Verification

From a computer **outside** the network (another connection, not the one the servers are on):

```
deploy/check-public.sh x.example.org 8443 deploy/oneq-ca.crt
```

The script checks TCP (the certificate matches the name and validates against the CA), `/v1/health`, and runs `oneqnode nat-check`
(UDP, the three ports). Expected: `NAT type` is the type of the client's NAT, not "blocked". If TCP works but `nat-check`
says `blocked`, the UDP forwarding is missing.

## 6. Operator decisions

* **Admin page** (`/admin/`): enabled only when `admin_password_file` is set. Protections: operator password (at least 12 characters)
  plus a TOTP code (mandatory), lock-out after failures (5 → 60 s, doubling up to 15 min), every code usable once, a 1 h session
  token kept only in the page's memory, strict CSP, every change logged with the client address. `admin_allow = <networks>` in
  `relay.conf` hides it (404) from everyone else; recommended if you administer from known addresses only. Enrol the TOTP
  (`oneqrelay admin-totp --out FILE`), move the password to a password manager and delete the enrolment files. If the phone is lost, use the
  recovery codes or create a new TOTP file on the server and enrol again.
* **Certificates**: keep the private CA key off the servers. Renewal: new key on the relay, signed by the CA, installed as `cert =` and
  `key =`, then restart the service.
