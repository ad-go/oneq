#!/bin/bash
# Smoke test of the INSTALLED packages (oneqrelay + oneqnode) that needs neither systemd nor supervisord.
# Run as root where both were installed with apt. The relay is started by hand as the oneqrelay user on a separate
# database and the node runs in a throw-away network namespace. Everything it creates is removed on exit.
set -euo pipefail
PW='smoke-test-pw-123'
T=$(mktemp -d /tmp/npkg.XXXXXX)
NS=npkgt
DB=/var/lib/oneq/relay/smoke.db        # separate database: the real registry is not touched
ADMPW=/var/lib/oneq/relay/smoke.adminpw
TOTPF=/var/lib/oneq/relay/smoke.totp
pids=()
cleanup() {
    for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    ip netns del $NS 2>/dev/null || true
    ip link del vsmoke0 2>/dev/null || true
    rm -rf "$T"
    rm -f $DB* $ADMPW $TOTPF /var/lib/oneq/relay/smoke.enrol
    oneqnode config-del --file /etc/oneq/node.conf smk 2>/dev/null || true
    rm -f /etc/oneq/node-smk.* 2>/dev/null || true
}
trap cleanup EXIT
# grep that reads its whole input: `cmd | grep -q` makes cmd die with SIGPIPE, which pipefail turns into a failure
gq() { grep -c "$@" >/dev/null; }
ok() { echo "  ok: $*"; }
fail() { echo "  FAIL: $*" >&2; exit 1; }

adm() { TUNMESH_PASSWORD=$PW runuser -u oneqrelay -- /opt/oneq/relay/bin/oneqrelay admin --db $DB --id smoke \
            --secret-file /etc/oneq/relay.secret "$@"; }

echo "[1] admin CLI (as the oneqrelay user, explicit paths)"
adm community-add lan 10.50.0.0/24
adm user-add lan alice --role admin
adm list | gq "user alice" && ok "community and user created" || fail "user missing"
[ "$(stat -c %U $DB)" = oneqrelay ] && ok "database owned by oneqrelay" || fail "database owner"

echo "[2] relay started as the oneqrelay user with command-line options (override the configuration file)"
runuser -u oneqrelay -- /opt/oneq/relay/bin/oneqrelay gen-admin-password --out $ADMPW > $T/adminpw.out
[ "$(stat -c '%a %U' $ADMPW)" = "600 oneqrelay" ] && ok "gen-admin-password: file mode 600, owner oneqrelay" || fail "admin password file perms"
runuser -u oneqrelay -- /opt/oneq/relay/bin/oneqrelay admin-totp --out $TOTPF --save-enrolment /var/lib/oneq/relay/smoke.enrol > $T/totp.out
[ "$(stat -c '%a %U' $TOTPF)" = "600 oneqrelay" ] && ok "admin-totp: second-factor file mode 600, owner oneqrelay" || fail "totp file perms"
gq "otpauth://totp/" /var/lib/oneq/relay/smoke.enrol && ok "admin-totp: enrolment link written" || fail "no enrolment link"
if runuser -u oneqrelay -- /opt/oneq/relay/bin/oneqrelay run --config /etc/oneq/relay.conf --db $DB --id smoke2 --listen 127.0.0.1:18079 \
        --admin-password-file $ADMPW > $T/refuse.log 2>&1; then fail "the admin page started without a second factor"; else
    gq "second factor" $T/refuse.log && ok "the admin page refuses to start without a second factor" || fail "refusal message: $(cat $T/refuse.log)"; fi
runuser -u oneqrelay -- /opt/oneq/relay/bin/oneqrelay run --config /etc/oneq/relay.conf --db $DB --id smoke \
    --listen 0.0.0.0:18080 --admin-password-file $ADMPW --admin-totp-file $TOTPF > $T/relay.log 2>&1 &
pids+=($!)
for _ in $(seq 50); do curl -fs http://127.0.0.1:18080/v1/health >/dev/null 2>&1 && break; sleep 0.2; done
curl -fs http://127.0.0.1:18080/v1/health | gq '"origin": "smoke"' && ok "command line overrides relay.conf (id smoke, port 18080)" || fail "override failed"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/v1/login -d '{"community":"lan","user":"alice","password":"wrong"}')
[ "$code" = 401 ] && ok "wrong password refused (401)" || fail "wrong password gave $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/v1/login -d "{\"community\":\"lan\",\"user\":\"alice\",\"password\":\"$PW\"}")
[ "$code" = 200 ] && ok "correct password accepted (200)" || fail "correct password gave $code"

echo "[2b] admin page (installed files: oneqadmin.py + oneqadmin.html)"
curl -fs http://127.0.0.1:18080/admin/ | gq 'oneqrelay admin' && ok "admin page served" || fail "admin page missing"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/admin/api/overview)
[ "$code" = 401 ] && ok "admin API refuses anonymous requests (401)" || fail "admin API gave $code without a token"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/admin/api/login -d '{"password":"wrong-wrong-wrong"}')
[ "$code" = 401 ] && ok "wrong operator password refused (401)" || fail "admin login gave $code"
code=$(python3 -c "import sys,json;sys.path.insert(0,'/opt/oneq/relay');import oneqtotp;print(oneqtotp.totp_now(json.load(open('$TOTPF'))['secret']))")
curl -fs http://127.0.0.1:18080/admin/api/info | gq '"two_factor": true' && ok "login form is told to ask for the authenticator code" || fail "info"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/admin/api/login -d "{\"password\":\"$(cat $T/adminpw.out)\"}")
[ "$code" = 401 ] && ok "password alone is refused (401)" || fail "password alone gave $code"
code=$(python3 -c "import sys,json;sys.path.insert(0,'/opt/oneq/relay');import oneqtotp;print(oneqtotp.totp_now(json.load(open('$TOTPF'))['secret']))")
tok=$(curl -s -X POST http://127.0.0.1:18080/admin/api/login -d "{\"password\":\"$(cat $T/adminpw.out)\",\"code\":\"$code\"}" | sed -n 's/.*"token": "\([^"]*\)".*/\1/p')
code2=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18080/admin/api/login -d "{\"password\":\"$(cat $T/adminpw.out)\",\"code\":\"$code\"}")
[ "$code2" = 401 ] && ok "the same authenticator code is refused a second time" || fail "code reuse gave $code2"
[ -n "$tok" ] && ok "operator login gives a token" || fail "no admin token"
curl -fs -H "Authorization: Bearer $tok" http://127.0.0.1:18080/admin/api/overview | gq '"name": "lan"' && ok "overview lists the community" || fail "overview"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $tok" http://127.0.0.1:18080/admin/api/c/lan/users -d '{"user":"zed","password":"zed-password-1"}')
[ "$code" = 200 ] && ok "user created through the admin API" || fail "user add gave $code"
adm list | gq "user zed" && ok "the user is in the registry (CLI sees it)" || fail "user zed missing in the registry"

echo "[2c] NAT discovery: STUN service of the relay and oneqnode nat-check (loopback: no NAT)"
oneqnode nat-check 127.0.0.1:18080 --json > $T/nat.json && gq '"type": "open"' $T/nat.json && ok "nat-check against the installed relay: open" || fail "nat-check: $(cat $T/nat.json)"
curl -fs -H "Authorization: Bearer $tok" http://127.0.0.1:18080/admin/api/overview | gq '"change_port"' && ok "admin overview shows the STUN service" || fail "overview has no stun"

echo "[3] oneqnode in a network namespace gets an address from the relay"
oneqnode genkey --key $T/node.key | sed 's/^/  /'
printf '%s\n' "$PW" > $T/node.pw; chmod 600 $T/node.pw
ip netns add $NS
ip link add vsmoke0 type veth peer name vsmoke1
ip link set vsmoke1 netns $NS
ip addr add 10.99.9.1/24 dev vsmoke0; ip link set vsmoke0 up
nsenter --net=/run/netns/$NS ip addr add 10.99.9.2/24 dev vsmoke1
nsenter --net=/run/netns/$NS ip link set vsmoke1 up
nsenter --net=/run/netns/$NS ip link set lo up
nsenter --net=/run/netns/$NS /opt/oneq/node/bin/oneqnode run --key $T/node.key --password-file $T/node.pw \
    --relay http://10.99.9.1:18080 --community lan --user alice --ifname npkg0 --name smoke \
    --listen 0.0.0.0:51820 --advertise 10.99.9.2:51820 > $T/node.log 2>&1 &
pids+=($!)
addr=""
for _ in $(seq 60); do
    addr=$(nsenter --net=/run/netns/$NS ip -4 -br addr show npkg0 2>/dev/null | grep -o '10\.50\.0\.[0-9]*/24' || true)
    [ -n "$addr" ] && break; sleep 0.5
done
[ -n "$addr" ] || { cat $T/node.log; fail "node did not get an address"; }
ok "node got $addr automatically"
mac=$(nsenter --net=/run/netns/$NS ip -br link show npkg0 | grep -o '02:[0-9a-f:]*')
ok "node MAC $mac"
adm list | gq "$mac" && ok "relay registry lists the node with that MAC" || fail "node not in registry"
ip link del vsmoke0 2>/dev/null || true

echo "[4] oneqnode-init writes the [NAME] section and protected files (no start)"
printf '%s\n' "$PW" > $T/init.pw; chmod 600 $T/init.pw
oneqnode-init smk --relay https://r1.example.org --relay https://r2.example.org --community lan --user alice \
    --password-file $T/init.pw --advertise 203.0.113.5:51820 --no-start | sed 's/^/  /'
for f in key password; do [ "$(stat -c '%a %U' /etc/oneq/node-smk.$f)" = "600 oneqnode" ] && ok "node-smk.$f mode 600 oneqnode" || fail "node-smk.$f perms"; done
gq '^\[smk\]' /etc/oneq/node.conf && gq '^relays = https://r1.example.org https://r2.example.org' /etc/oneq/node.conf \
    && gq '^advertise = 203.0.113.5:51820' /etc/oneq/node.conf && ok "[smk] section in node.conf" || fail "node.conf content"
gq 'smoke-test-pw' /etc/oneq/node.conf && fail "password found in node.conf" || ok "no secret in node.conf"
! oneqnode-init 'bad name!' --relay https://r --community c --user u 2>/dev/null && ok "bad NAME refused" || fail "bad NAME accepted"
! oneqnode-init x --relay 'https://r;rm -rf /' --community c --user u --password-file $T/init.pw 2>/dev/null && ok "malicious relay URL refused" || fail "bad URL accepted"
oneqnode-init smk --remove | sed 's/^/  /'
gq '^\[smk\]' /etc/oneq/node.conf && fail "section left" || ok "--remove deleted the section"

echo "[5] systemd units"
if command -v systemd-analyze >/dev/null; then
    for u in oneqrelay.service 'oneqnode@.service'; do
        out=$(systemd-analyze verify "/usr/lib/systemd/system/$u" 2>&1 || true)
        if [ -z "$out" ]; then ok "$u verifies"; else echo "$out" | sed 's/^/    /'; fail "$u does not verify"; fi
    done
fi
echo "ALL OK"
