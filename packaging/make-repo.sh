#!/bin/bash
# Phase 1 of the apt repository: lay out the packages and generate the (unsigned) indexes.
# Needs apt-ftparchive (package apt-utils), so run it on Debian. Phase 2 is sign-repo.sh, on the machine that holds
# the signing key.
#   packaging/make-repo.sh DEB_DIR OUT_DIR [SUITE]        (REPO_URL=https://apt.example.org/oneq for the docs)
set -euo pipefail
DEBS=${1:?usage: make-repo.sh DEB_DIR OUT_DIR [SUITE]}
OUT=${2:?}
SUITE=${3:-trixie}
URL=${REPO_URL:-https://apt.example.org/oneq}

rm -rf "$OUT"
mkdir -p "$OUT/pool/main" "$OUT/dists/$SUITE/main/binary-amd64"
for f in "$DEBS"/*.deb; do
    pkg=$(dpkg-deb -f "$f" Package)
    mkdir -p "$OUT/pool/main/${pkg:0:1}/$pkg"
    cp "$f" "$OUT/pool/main/${pkg:0:1}/$pkg/"
done
cd "$OUT"
P=dists/$SUITE/main/binary-amd64/Packages
apt-ftparchive packages pool > "$P"
gzip -9nk "$P"
xz -9k "$P"
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=oneq \
    -o APT::FTPArchive::Release::Label=oneq \
    -o APT::FTPArchive::Release::Suite="$SUITE" \
    -o APT::FTPArchive::Release::Codename="$SUITE" \
    -o APT::FTPArchive::Release::Architectures=amd64 \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Description="oneq post-quantum mesh packages (oneqrelay, oneqnode)" \
    release "dists/$SUITE" > "dists/$SUITE/Release.new"
mv "dists/$SUITE/Release.new" "dists/$SUITE/Release"

cat > oneq.sources <<EOF
# /etc/apt/sources.list.d/oneq.sources
Types: deb
URIs: $URL
Suites: $SUITE
Components: main
Architectures: amd64
Signed-By: /usr/share/keyrings/oneq-archive-keyring.gpg
EOF

cat > README.md <<EOF
# oneq apt repository (Debian 13 "$SUITE", amd64)

Packages: \`oneqrelay\` (federated registry and relay) and \`oneqnode\` (layer-2 mesh node).
The repository is a plain directory: serve it with any static web server (nginx, Apache, \`python3 -m http.server\`).

## Use it

    sudo install -d -m 0755 /usr/share/keyrings
    curl -fsSL $URL/oneq-archive-keyring.gpg | sudo tee /usr/share/keyrings/oneq-archive-keyring.gpg >/dev/null
    curl -fsSL $URL/oneq.sources | sudo tee /etc/apt/sources.list.d/oneq.sources >/dev/null
    sudo apt update
    sudo apt install oneqrelay      # on the relay servers
    sudo apt install oneqnode       # on the nodes

The key is dedicated to this repository and only trusted for it (\`Signed-By\`). Check its fingerprint with
\`gpg --show-keys /usr/share/keyrings/oneq-archive-keyring.gpg\` before trusting it.

## Publish a new version

    packaging/build-debs.sh                       # on Debian 13: dist/*.deb
    packaging/make-repo.sh dist repo $SUITE        # lay out + index (on Debian)
    GNUPGHOME=... packaging/sign-repo.sh repo KEYID $SUITE   # sign (where the secret key is)
    rsync -a --delete repo/ server:/srv/apt/oneq/

Layout: \`pool/main/<initial>/<package>/*.deb\`, \`dists/$SUITE/{InRelease,Release,Release.gpg}\`,
\`dists/$SUITE/main/binary-amd64/Packages{,.gz,.xz}\`.
EOF
echo "repository laid out in $OUT (unsigned)"
