#!/bin/bash
# Tests a signed repository with the real apt, in a sandbox that does not touch the system's apt configuration
# (own sources, own lists and cache); only the installation itself uses the system's dpkg database.
#   sudo packaging/repo-test.sh REPO_DIR [--keep]       REPO_DIR = the signed repository (make-repo + sign-repo)
# Positive: apt update verifies the signature, apt install oneqrelay oneqnode works by name.
# Negative: a modified index, an unsigned repository and a repository signed by another key must all be refused.
set -uo pipefail
REPO=$(cd "${1:?usage: repo-test.sh REPO_DIR [--keep]}" && pwd)
KEEP=${2:-}
T=$(mktemp -d /tmp/aptsb.XXXXXX)
chmod 755 "$T"
fails=0
ok() { echo "  ok: $*"; }
bad() { echo "  FAIL: $*" >&2; fails=$((fails + 1)); }
pids=()
cleanup() {
    for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    [ "$KEEP" = --keep ] || apt-get purge -y oneqrelay oneqnode >/dev/null 2>&1 || true
    rm -rf "$T"
}
trap cleanup EXIT

serve() {   # serve DIR PORT
    (cd "$1" && exec python3 -m http.server "$2" --bind 127.0.0.1 >/dev/null 2>&1) &
    pids+=($!)
    for _ in $(seq 30); do curl -fs -o /dev/null "http://127.0.0.1:$2/" 2>/dev/null && return; sleep 0.2; done
}
apt_in() {  # apt_in NAME -> prints the apt-get options for the sandbox NAME (sources in $T/NAME/sources.d)
    echo "-o Dir::Etc::sourcelist=/dev/null -o Dir::Etc::sourceparts=$T/$1/sources.d -o Dir::State::lists=$T/$1/lists -o Dir::Cache=$T/$1/cache"
}
sandbox() { # sandbox NAME PORT KEYRING
    mkdir -p "$T/$1/sources.d" "$T/$1/lists/partial" "$T/$1/cache/archives/partial"
    chmod -R 777 "$T/$1"
    cat > "$T/$1/sources.d/oneq.sources" <<EOF
Types: deb
URIs: http://127.0.0.1:$2/
Suites: trixie
Components: main
Architectures: amd64
Signed-By: $3
EOF
}

cp "$REPO/oneq-archive-keyring.gpg" "$T/good.gpg"; chmod 644 "$T/good.gpg"
VER=$(awk '/^Version:/ {print $2; exit}' "$REPO/dists/trixie/main/binary-amd64/Packages")

echo "[1] signed repository: update, policy, install by name"
serve "$REPO" 8099
sandbox good 8099 "$T/good.gpg"
out=$(apt-get $(apt_in good) update 2>&1); rc=$?
[ $rc -eq 0 ] && echo "$out" | grep -q 'InRelease' && ok "apt update verified InRelease (rc=0)" || { echo "$out" | tail -5; bad "update failed"; }
echo "$out" | grep -qiE 'warning|not signed|NO_PUBKEY' && { echo "$out" | grep -iE 'warning|not signed|NO_PUBKEY'; bad "apt warnings"; }
pol=$(apt-cache $(apt_in good) policy oneqrelay oneqnode 2>&1)
echo "$pol" | grep -q "Candidate: $VER" && ok "candidate version $VER for both: $(echo "$pol" | grep -c "Candidate: $VER") packages" || { echo "$pol"; bad "policy"; }
sim=$(apt-get $(apt_in good) install -s oneqrelay oneqnode 2>&1)
echo "$sim" | grep -q 'newly installed' && ok "simulation: $(echo "$sim" | grep 'newly installed')" || { echo "$sim" | tail -5; bad "simulation"; }
apt-get $(apt_in good) install -y oneqrelay oneqnode > "$T/install.log" 2>&1 \
    && ok "apt install oneqrelay oneqnode (from the repository)" || { tail -8 "$T/install.log"; bad "install"; }
dpkg -l oneqrelay oneqnode 2>/dev/null | grep -c '^ii' | grep -q 2 && ok "both packages installed (dpkg status ii)" || bad "dpkg status"
grep -q 'Get:.*oneqrelay' "$T/install.log" && ok "packages were downloaded through the repository" || bad "not downloaded from the repository"

echo "[2] negative: modified Packages index (signature of Release still valid)"
cp -a "$REPO" "$T/tampered"
python3 - "$T/tampered/dists/trixie/main/binary-amd64/Packages" <<'EOF'
import sys
p = sys.argv[1]; s = open(p).read()
open(p, "w").write(s.replace("Package: oneqrelay", "Package: oneqrelay\nDepends: evil", 1))
EOF
rm -f "$T/tampered/dists/trixie/main/binary-amd64/Packages.gz" "$T/tampered/dists/trixie/main/binary-amd64/Packages.xz"
serve "$T/tampered" 8098
sandbox tampered 8098 "$T/good.gpg"
out=$(apt-get $(apt_in tampered) update 2>&1); rc=$?
{ [ $rc -ne 0 ] || echo "$out" | grep -qiE 'Hash Sum mismatch|Some index files failed'; } && ok "tampered index refused: $(echo "$out" | grep -iE 'mismatch|failed|Err' | head -1)" || { echo "$out" | tail -4; bad "tampered index ACCEPTED"; }
apt-cache $(apt_in tampered) policy oneqrelay 2>&1 | grep -q "Candidate: $VER" && bad "package visible from the tampered repository" || ok "no package available from the tampered repository"

echo "[3] negative: unsigned repository"
cp -a "$REPO" "$T/unsigned"; rm -f "$T/unsigned/dists/trixie/InRelease" "$T/unsigned/dists/trixie/Release.gpg"
serve "$T/unsigned" 8097
sandbox unsigned 8097 "$T/good.gpg"
out=$(apt-get $(apt_in unsigned) update 2>&1); rc=$?
{ [ $rc -ne 0 ] || echo "$out" | grep -qiE 'not signed|no longer has a Release|Err|E:'; } && ok "unsigned repository refused: $(echo "$out" | grep -iE 'not signed|Err|E:' | head -1)" || { echo "$out" | tail -4; bad "unsigned repository ACCEPTED"; }

echo "[4] negative: signed by another key"
GH=$T/otherkey; mkdir -m 700 "$GH"
gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "someone else <x@example.org>" ed25519 sign 1d >/dev/null 2>&1
gpg --homedir "$GH" --export > "$T/other.gpg"; chmod 644 "$T/other.gpg"
sandbox other 8099 "$T/other.gpg"      # the real repository, but only the wrong key is trusted
out=$(apt-get $(apt_in other) update 2>&1); rc=$?
{ [ $rc -ne 0 ] || echo "$out" | grep -qiE 'NO_PUBKEY|not signed|could not be verified|signature'; } && ok "wrong key refused: $(echo "$out" | grep -iE 'NO_PUBKEY|not signed|verified|signature' | head -1)" || { echo "$out" | tail -4; bad "wrong key ACCEPTED"; }

[ $fails -eq 0 ] && echo "ALL OK" || { echo "$fails check(s) FAILED" >&2; exit 1; }
