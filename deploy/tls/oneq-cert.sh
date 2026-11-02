#!/bin/sh
# oneq-cert.sh — Let's Encrypt certificate lifecycle via acme.sh
#
# Usage:
#   oneq-cert.sh init  DOMAIN EMAIL   acquire cert (nginx must already be running on port 80)
#   oneq-cert.sh renew               renew if due, reload nginx
#   oneq-cert.sh status              print cert expiry and days remaining
#
# Installs acme.sh to /usr/local/lib/oneq-acme if not present.
# Stores certs in /etc/oneq/tls/live/DOMAIN/ (fullchain.pem, privkey.pem).
# After issuance or renewal nginx is sent a reload signal.
#
# nginx config path for webroot: /var/www/html (must exist and be served by nginx).
# When nginx is not yet serving the webroot, pass --standalone to acme.sh instead
# (port 80 must be free).
#
# Integration with nginx-proxy-acme:
#   When HTTPS is terminated by an external nginx-proxy-acme container, this script
#   is NOT needed when an external container already manages certs — acme-companion manages certs automatically.
#   Use this script only for standalone deployments that handle their own HTTPS.
#
# Cron / systemd timer: see oneq-tls.timer (runs daily).

set -e

ACME_HOME=/usr/local/lib/oneq-acme
CERT_BASE=/etc/oneq/tls/live

_install_acme() {
    if [ ! -x "$ACME_HOME/acme.sh" ]; then
        echo "Installing acme.sh to $ACME_HOME ..."
        mkdir -p "$ACME_HOME"
        curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh \
            -o "$ACME_HOME/acme.sh"
        chmod +x "$ACME_HOME/acme.sh"
    fi
}

_reload_nginx() {
    if command -v nginx >/dev/null 2>&1 && nginx -t -q 2>/dev/null; then
        nginx -s reload
    fi
}

cmd_init() {
    domain="$1"; email="$2"
    [ -z "$domain" ] || [ -z "$email" ] && { echo "Usage: $0 init DOMAIN EMAIL" >&2; exit 1; }
    _install_acme
    mkdir -p "$CERT_BASE/$domain"
    # Register account
    "$ACME_HOME/acme.sh" --register-account -m "$email" --home "$ACME_HOME"
    # Issue cert via webroot (nginx serves /.well-known/acme-challenge/ from /var/www/html)
    "$ACME_HOME/acme.sh" --issue -d "$domain" --webroot /var/www/html \
        --home "$ACME_HOME" \
        --cert-file  "$CERT_BASE/$domain/cert.pem" \
        --key-file   "$CERT_BASE/$domain/privkey.pem" \
        --ca-file    "$CERT_BASE/$domain/chain.pem" \
        --fullchain-file "$CERT_BASE/$domain/fullchain.pem" \
        --reloadcmd "_reload_nginx"
    echo "Certificate issued: $CERT_BASE/$domain/fullchain.pem"
    echo "Update nginx ssl_certificate and ssl_certificate_key, then reload nginx."
}

cmd_renew() {
    _install_acme
    # --cron: renew all certs that are due (within 30 days of expiry)
    "$ACME_HOME/acme.sh" --cron --home "$ACME_HOME" && _reload_nginx
}

cmd_status() {
    for certdir in "$CERT_BASE"/*/; do
        domain=$(basename "$certdir")
        cert="$certdir/fullchain.pem"
        [ -f "$cert" ] || continue
        expiry=$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2)
        days=$(( ( $(date -d "$expiry" +%s 2>/dev/null || date -jf "%b %d %T %Y %Z" "$expiry" +%s) - $(date +%s) ) / 86400 ))
        echo "$domain: expires $expiry ($days days)"
    done
}

case "$1" in
    init)   cmd_init "$2" "$3" ;;
    renew)  cmd_renew ;;
    status) cmd_status ;;
    *)      echo "Usage: $0 {init DOMAIN EMAIL | renew | status}" >&2; exit 1 ;;
esac
