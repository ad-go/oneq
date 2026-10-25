#!/bin/bash
# Real service test of the INSTALLED packages. Run as root after `apt install oneqrelay oneqnode`:
#   packaging/service-test.sh systemd      the relay and two nodes run as systemd services
#   packaging/service-test.sh supervisor   the same under supervisord (the relay must have been (re)installed with
#                                          `init = supervisor` in /etc/oneq/relay.conf)
# It checks that the files are where they should be, that the services really start from /etc/oneq/*.conf, run
# unprivileged, form a mesh, restart after a crash, pick up edits of the configuration files, refuse a
# misspelled option, and clean up. Uses its own community (svcNNNN, 10.77.0.0/24).
set -euo pipefail
MODE=${1:?usage: service-test.sh systemd|supervisor}
PW='service-test-pw-123'
COMM="svc$RANDOM"     # a fresh community per run: the registry keeps the nodes of earlier runs
T=$(mktemp -d /tmp/nsvc.XXXXXX)
RC=/etc/oneq/relay.conf
NC=/etc/oneq/node.conf
# grep that reads its whole input: `cmd | grep -q` makes cmd die with SIGPIPE, which pipefail turns into a failure
gq() { grep -c "$@" >/dev/null; }
ok() { echo "  ok: $*"; }
fail() { echo "  FAIL: $*" >&2; exit 1; }
cleanup() {
    cp "$T/relay.conf.orig" "$RC" 2>/dev/null || true
    for n in t1 t2; do oneqnode-init $n --remove >/dev/null 2>&1 || true; done
    rm -rf "$T"
}
trap cleanup EXIT
cp "$RC" "$T/relay.conf.orig"

adm() { TUNMESH_PASSWORD=$PW oneqrelay-admin "$@"; }
status() {   # status SYSTEMD-UNIT SUPERVISOR-PROGRAM
    if [ "$MODE" = systemd ]; then systemctl is-active "$1" 2>&1 || true; else supervisorctl status "$2" 2>&1 | awk '{print $2}'; fi
}
want_running() { [ "$MODE" = systemd ] && echo active || echo RUNNING; }
logs() {     # logs NAME -> text of the node's log
    if [ "$MODE" = systemd ]; then journalctl --no-pager -q -u "oneqnode@$1.service" 2>/dev/null
    else cat "/var/log/oneq/node-$1.log" 2>/dev/null; fi
}
relay_logs() {
    if [ "$MODE" = systemd ]; then journalctl --no-pager -q -u oneqrelay.service --since "-2min" 2>/dev/null
    else cat /var/log/oneq/relay.log 2>/dev/null; fi
}
restart_relay() { if [ "$MODE" = systemd ]; then systemctl restart oneqrelay || true; else supervisorctl restart oneqrelay >/dev/null 2>&1 || true; fi; }
restart_node() { if [ "$MODE" = systemd ]; then systemctl restart "oneqnode@$1"; else supervisorctl restart "oneqnode-$1" >/dev/null; fi; }
caps() { grep '^CapEff' /proc/$1/status | awk '{print $2}'; }
wait_health() { for _ in $(seq 60); do curl -fs "http://127.0.0.1:$1/v1/health" >/dev/null 2>&1 && return 0; sleep 0.5; done; return 1; }

echo "[0] installed layout"
[ -x /opt/oneq/relay/bin/oneqrelay ] && [ -x /opt/oneq/node/bin/oneqnode ] && ok "applications are in /opt/oneq/relay and /opt/oneq/node" || fail "missing /opt/oneq binaries"
for c in oneqrelay oneqrelay-admin oneqnode oneqnode-init; do
    [ "$(readlink /usr/bin/$c)" = "/opt/oneq/$([ "${c#oneqrelay}" != "$c" ] && echo relay || echo node)/bin/$c" ] || fail "/usr/bin/$c is not a link into /opt/oneq"
done
ok "commands in /usr/bin link into /opt/oneq"
[ -f $RC ] && [ -f $NC ] && ok "configuration files $RC and $NC exist" || fail "missing configuration files"
[ "$(stat -c '%U:%a' /etc/oneq/relay.secret)" = oneqrelay:600 ] && ok "relay.secret owned by oneqrelay, mode 600" || fail "relay.secret perms"
[ ! -e /usr/lib/oneqrelay ] && [ ! -e /usr/lib/oneqnode ] && [ ! -e /etc/oneqrelay ] && [ ! -e /etc/oneqnode ] && ok "no leftovers of the old layout" || fail "old layout present"

echo "[1] relay started by the package under $MODE, from $RC"
wait_health 8080 && ok "health answers on 127.0.0.1:8080 (the listen address of relay.conf)" || fail "relay does not answer"
[ "$(status oneqrelay oneqrelay)" = "$(want_running)" ] && ok "manager reports the relay $(want_running)" || fail "manager state: $(status oneqrelay oneqrelay)"
rpid=$(pgrep -f 'oneqrelay.py run' | head -1)
tr '\0' ' ' < /proc/$rpid/cmdline | gq -- '--config /etc/oneq/relay.conf' && ok "started with --config /etc/oneq/relay.conf" || fail "cmdline: $(tr '\0' ' ' < /proc/$rpid/cmdline)"
[ "$(ps -o user= -p "$rpid")" = oneqrelay ] && ok "relay runs as user oneqrelay" || fail "relay runs as $(ps -o user= -p "$rpid")"
[ "$(caps "$rpid")" = 0000000000000000 ] && ok "relay has no capabilities" || fail "relay capabilities: $(caps "$rpid")"

echo "[2] community, user, two nodes"
adm community-add $COMM 10.77.0.0/24
adm user-add $COMM u1 --role admin
printf '%s\n' "$PW" > "$T/pw"; chmod 600 "$T/pw"
for i in 1 2; do
    oneqnode-init "t$i" --init "$MODE" --relay http://127.0.0.1:8080 --community $COMM --user u1 --label "node$i" \
        --password-file "$T/pw" --listen "0.0.0.0:5182$i" --advertise "127.0.0.1:5182$i" | sed 's/^/    /'
done
gq '^\[t1\]' $NC && gq '^\[t2\]' $NC && ok "sections [t1] and [t2] written to node.conf" || fail "node.conf sections"
gqF "$PW" $NC && fail "node.conf contains the password" || ok "node.conf holds no secret, only the paths of the key and password files"
[ "$(stat -c '%U:%G %a' $NC)" = "root:oneqnode 640" ] && ok "node.conf root:oneqnode 640" || fail "node.conf perms $(stat -c '%U:%G %a' $NC)"
for i in 1 2; do
    [ "$(stat -c '%U:%a' /etc/oneq/node-t$i.key)" = oneqnode:600 ] && ok "t$i key owned by oneqnode, mode 600" || fail "t$i key perms"
    [ "$(stat -c '%U:%a' /etc/oneq/node-t$i.password)" = oneqnode:600 ] && ok "t$i password owned by oneqnode, mode 600" || fail "t$i password perms"
done

echo "[3] nodes get addresses and open a session with each other"
for i in 1 2; do
    a=""
    for _ in $(seq 60); do a=$(ip -4 -br addr show "oneq-t$i" 2>/dev/null | grep -o '10\.77\.0\.[0-9]*/24' || true); [ -n "$a" ] && break; sleep 0.5; done
    [ -n "$a" ] && ok "oneq-t$i has $a" || { logs "t$i" | tail -15; fail "oneq-t$i got no address"; }
done
for i in 1 2; do
    for _ in $(seq 60); do logs "t$i" | gq 'session with' && break; sleep 0.5; done
    logs "t$i" | gq 'session with' && ok "t$i established a session" || { logs "t$i" | tail -15; fail "t$i has no session"; }
done
if [ "$MODE" = systemd ]; then [ "$(status oneqnode@t1 x)" = active ] && ok "oneqnode@t1 active"
else [ "$(status x oneqnode-t1)" = RUNNING ] && ok "oneqnode-t1 RUNNING"; fi
npid=$(pgrep -f 'oneqnode.py run.*--node t1' | head -1)
[ "$(ps -o user= -p "$npid")" = oneqnode ] && ok "node runs as user oneqnode" || fail "node runs as $(ps -o user= -p "$npid")"
[ "$(caps "$npid")" = 0000000000001000 ] && ok "node has exactly CAP_NET_ADMIN" || fail "node capabilities: $(caps "$npid")"

echo "[4] the configuration files really drive the applications"
adm list | gq 'node1' && ok "label from [t1] reaches the registry (node1)" || fail "label not registered"
sed -i '/^\[t1\]/,/^\[/ s/^label = .*/label = renamed-by-edit/' $NC
restart_node t1
for _ in $(seq 40); do adm list | gq 'renamed-by-edit' && break; sleep 0.5; done
adm list | gq 'renamed-by-edit' && ok "editing node.conf + restart changes the node (label renamed-by-edit)" || fail "edit of node.conf not picked up"
sed -i 's/^listen = 127.0.0.1:8080/listen = 127.0.0.1:8081/' $RC
restart_relay
wait_health 8081 && ok "editing relay.conf + restart moves the relay to 127.0.0.1:8081" || { relay_logs | tail -5; fail "relay.conf edit not picked up"; }
! curl -fs -m 2 http://127.0.0.1:8080/v1/health >/dev/null 2>&1 && ok "nothing listens on the old port any more" || fail "old port still answers"
cp "$T/relay.conf.orig" $RC
sed -i 's/^listen = 127.0.0.1:8080/lisen = 127.0.0.1:8080/' $RC       # a typo in an option name
restart_relay
sleep 3
relay_logs | gq "unknown option 'lisen'" && ok "a misspelled option stops the relay with a clear message" || { relay_logs | tail -5; fail "no clear error for the typo"; }
cp "$T/relay.conf.orig" $RC
restart_relay
wait_health 8080 && ok "restored relay.conf: relay is back on 8080" || fail "relay did not come back"
rpid=$(pgrep -f 'oneqrelay.py run' | head -1)

echo "[5] automatic restart after a crash"
kill -9 "$rpid"
sleep 1
wait_health 8080 && ok "relay is back after kill -9" || fail "relay did not come back"
new=$(pgrep -f 'oneqrelay.py run' | head -1)
[ "$new" != "$rpid" ] && ok "new relay process ($new)" || fail "same pid?"
npid=$(pgrep -f 'oneqnode.py run.*--node t1' | head -1)
kill -9 "$npid"
for _ in $(seq 60); do
    n2=$(pgrep -f 'oneqnode.py run.*--node t1' | head -1 || true)
    [ -n "$n2" ] && [ "$n2" != "$npid" ] && break; sleep 0.5
done
[ -n "${n2:-}" ] && [ "$n2" != "$npid" ] && ok "node t1 restarted ($n2)" || fail "node did not restart"

echo "[6] removal"
for i in 1 2; do oneqnode-init "t$i" --remove >/dev/null; done
sleep 2
! ip link show oneq-t1 >/dev/null 2>&1 && ! ip link show oneq-t2 >/dev/null 2>&1 && ok "interfaces gone" || fail "interfaces still there"
ls /etc/oneq/node-t1.* /etc/oneq/node-t2.* >/dev/null 2>&1 && fail "key/password files left" || ok "keys and passwords removed"
gqE '^\[t[12]\]' $NC && fail "sections left in node.conf" || ok "sections removed from node.conf"
if [ "$MODE" = supervisor ]; then ls /etc/supervisor/conf.d/oneqnode-t*.conf >/dev/null 2>&1 && fail "supervisor programs left" || ok "supervisor programs removed"; fi
echo "ALL OK ($MODE)"
