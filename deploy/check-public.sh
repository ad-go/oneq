#!/bin/bash
# Checks a relay from the outside: TCP/TLS (certificate matches the name and the private CA), /v1/health, and the UDP STUN service
# (oneqnode nat-check). Usage: deploy/check-public.sh HOST PORT CA.pem      e.g.  deploy/check-public.sh x.1q.ro 8443 deploy/oneq-ca.crt
set -u
HOST=${1:?host}; PORT=${2:-8443}; CA=${3:?CA certificate (PEM)}
HERE=$(cd "$(dirname "$0")/.." && pwd)
bad=0
ok()   { echo "  ok: $*"; }
fail() { echo "  FAIL: $*"; bad=1; }

echo "[1] TCP $HOST:$PORT"
timeout 6 bash -c "exec 3<>/dev/tcp/$HOST/$PORT" 2>/dev/null && ok "port open" || { fail "no TCP connection (redirection missing or firewall)"; exit 1; }

echo "[2] TLS and health"
out=$(curl -s -m 10 --cacert "$CA" "https://$HOST:$PORT/v1/health" 2>&1)
case "$out" in
  *'"status": "ok"'*) ok "certificate valid for $HOST (private CA), health: $out" ;;
  *) fail "https://$HOST:$PORT/v1/health -> $out" ;;
esac
echo "$out" | grep -q '"stun"' && ok "the relay advertises its STUN ports" || fail "no STUN service advertised (relay older than 0.6 or stun = no)"

echo "[3] UDP (STUN on $PORT, $((PORT+1)), $((PORT+2)))"
if command -v oneqnode >/dev/null 2>&1; then NN=(oneqnode)
elif [ -f "$HERE/oneqnode.py" ]; then NN=(python3 "$HERE/oneqnode.py")
else NN=(); fi
if [ ${#NN[@]} -eq 0 ]; then
    echo "  (skipped: oneqnode not installed; run:  oneqnode nat-check $HOST:$PORT)"
else
    res=$("${NN[@]}" nat-check "$HOST:$PORT" --json 2>&1 | tail -1)
    case "$res" in
      *'"type": "blocked"'*) fail "STUN gets no answer: UDP $PORT-$((PORT+2)) is not forwarded or is filtered ($res)" ;;
      *'"type"'*) ok "STUN answers: $res" ;;
      *) fail "nat-check: $res" ;;
    esac
fi
[ $bad -eq 0 ] && echo "ALL OK" || { echo "SOME CHECKS FAILED"; exit 1; }
