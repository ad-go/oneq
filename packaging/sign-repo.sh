#!/bin/bash
# Phase 2 of the apt repository: sign the Release file and export the public key. Run where the secret key lives.
#   GNUPGHOME=/path/to/keyring packaging/sign-repo.sh REPO_DIR KEYID [SUITE]
# A key with a passphrase: put the passphrase in a file and set GPG_PASSPHRASE_FILE=that-file.
set -euo pipefail
REPO=${1:?usage: sign-repo.sh REPO_DIR KEYID [SUITE]}
KEY=${2:?}
SUITE=${3:-trixie}
PASS=(--pinentry-mode loopback --passphrase "")
[ -z "${GPG_PASSPHRASE_FILE:-}" ] || PASS=(--pinentry-mode loopback --passphrase-file "$GPG_PASSPHRASE_FILE")

cd "$REPO/dists/$SUITE"
[ -f Release ] || { echo "no Release in $REPO/dists/$SUITE: run make-repo.sh first" >&2; exit 1; }
rm -f InRelease Release.gpg
gpg --batch --yes "${PASS[@]}" -u "$KEY" --clearsign -o InRelease Release
gpg --batch --yes "${PASS[@]}" -u "$KEY" --armor --detach-sign -o Release.gpg Release
cd "$OLDPWD"
gpg --export "$KEY" > "$REPO/oneq-archive-keyring.gpg"
gpg --export --armor "$KEY" > "$REPO/oneq-archive-keyring.asc"
gpg --batch --verify "$REPO/dists/$SUITE/Release.gpg" "$REPO/dists/$SUITE/Release" 2>&1 | sed 's/^/  /'
gpg --show-keys --with-fingerprint "$REPO/oneq-archive-keyring.gpg" | sed 's/^/  /'
echo "signed: $REPO/dists/$SUITE/{InRelease,Release.gpg}"
