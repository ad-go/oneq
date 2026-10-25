#!/bin/bash
# Build oneqnode_VERSION_amd64.deb (node only), oneqrelay_VERSION_amd64.deb (relay only) and oneq-server_VERSION_all.deb (installs both).
# Run on Debian 13 (trixie) amd64: the bundled wheels are cp313/manylinux x86_64 and the packages depend on
# python3 (= 3.13) and libssl3t64 (>= 3.5). Needs dpkg-deb, python3.13 and network access to PyPI.
#   VERSION=0.2.0 PIP=/opt/oneq-src/venv/bin/pip ./packaging/build-debs.sh      -> dist/*.deb
set -euo pipefail

VERSION=${VERSION:-0.0.1}
SRC=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$SRC/dist}
PIP=${PIP:-pip3}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
[ "$(dpkg --print-architecture)" = amd64 ] || { echo "build on amd64" >&2; exit 1; }
python3 -c 'import sys,ssl; assert sys.version_info[:2]==(3,13), sys.version; print("python", sys.version.split()[0], ssl.OPENSSL_VERSION)'

# name | short name (directory under /opt/oneq) | pip requirements | python sources...
build() {
    local name=$1 short=$2 reqs=$3; shift 3
    local root=$WORK/$name lib
    cp -a "$SRC/packaging/$name" "$root"
    lib=$root/opt/oneq/$short
    mkdir -p "$lib/site-packages"
    for f in "$@"; do cp "$SRC/$f" "$lib/"; done
    # dependencies: exact versions, wheels only (no build at install time)
    printf '%s\n' $reqs > "$WORK/$name.req"
    $PIP install --quiet --only-binary=:all: --no-compile --target "$lib/site-packages" -r "$WORK/$name.req"
    rm -rf "$lib/site-packages/bin" "$lib/site-packages/pip"*
    find "$lib" -name __pycache__ -type d -prune -exec rm -rf {} +
    local bundled
    bundled=$(cd "$lib/site-packages" && for d in *.dist-info; do n=${d%.dist-info}; echo " * ${n%-*} ${n##*-}"; done | sort)

    # docs
    local doc=$root/usr/share/doc/$name
    mkdir -p "$doc"
    sed -e "s/@PKG@/$name/g" -e "s/@SHORT@/$short/g" -e "/@BUNDLED@/{r /dev/stdin
d}" "$SRC/packaging/common/copyright.in" > "$doc/copyright" <<< "$bundled"
    {
        echo "$name ($VERSION) unstable; urgency=medium"
        echo
        echo "  * The application is installed in /opt/oneq/$short; commands are linked into /usr/bin."
        echo "  * Real configuration files read by the application: /etc/oneq/relay.conf and /etc/oneq/node.conf"
        echo "    (INI; command-line options override them; unknown options are an error)."
        echo "  * Secrets stay out of the configuration files: only the paths of their files are stored."
        echo "  * Fix: a restarted node that never initiates (its key sorts last) was unreachable for ~100 s; its PUNCH"
        echo "    now carries the node id and makes the initiators re-handshake at once (measured on real hosts)."
        echo "  * Fix: nodes stay attached to a relay at all times; before, a peer sending through the relay to a node"
        echo "    it had a direct session with lost every packet (the node was never attached). Found on real hosts."
        echo "  * Fix: a member that joins later is discovered by the others within seconds (member list refreshed"
        echo "    every 5 s, and at once when a hole-punch arrives from an unknown address); before, up to 20 s."
        echo
        echo " -- oneq <k@1q.ro>  $(date -R -u -d '2026-10-18 12:00:00')"
    } | gzip -9n > "$doc/changelog.gz"
    if [ "$name" = oneqrelay ]; then
        mkdir -p "$doc/examples"
        cp "$SRC/deploy/nginx-oneqrelay.conf" "$doc/examples/"
    fi
    if [ "$name" = oneqnode ]; then
        # a node can be the gateway of a private network (see "Rute printr-un nod gateway" in ARCHITECTURE.md)
        mkdir -p "$doc/examples"
        cp "$SRC/deploy/oneq-gateway" "$SRC/deploy/oneq-gateway.service" "$doc/examples/"
    fi

    # byte-compile with the target interpreter; checked-hash keeps the pyc valid whatever the mtimes are
    python3 -m compileall -q --invalidation-mode checked-hash "$lib" >/dev/null

    # normalize text files and permissions
    find "$root" -type f \( -name '*.py' -o -name '*.service' -o -name '*.conf' -o -name '*.conf.in' -o -name 'README*' \
        -o -path '*/opt/oneq/*/bin/*' -o -path '*/DEBIAN/*' \) ! -path '*/site-packages/*' -exec sed -i 's/\r$//' {} +
    sed -i "s/@VERSION@/$VERSION/" "$root/DEBIAN/control"
    find "$root" -type d -exec chmod 0755 {} +
    find "$root" -type f -exec chmod go-w,a+r {} +
    chmod 0755 "$lib"/bin/* "$root"/DEBIAN/postinst "$root"/DEBIAN/prerm "$root"/DEBIAN/postrm
    mkdir -p "$root/usr/bin"
    for c in "$lib"/bin/*; do
        [ "$(basename "$c")" = run ] || ln -s "/opt/oneq/$short/bin/$(basename "$c")" "$root/usr/bin/$(basename "$c")"
    done
    ( cd "$root" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z | xargs -0 md5sum > DEBIAN/md5sums )
    local size
    size=$(du -sk --exclude=DEBIAN "$root" | cut -f1)
    sed -i "s/@SIZE@/$size/" "$root/DEBIAN/control"
    dpkg-deb --root-owner-group -Zxz -b "$root" "$OUT/${name}_${VERSION}_amd64.deb" >/dev/null
    echo "built $OUT/${name}_${VERSION}_amd64.deb ($(du -h "$OUT/${name}_${VERSION}_amd64.deb" | cut -f1))"
}

# oneq-server: no files of its own, it installs oneqnode and oneqrelay together (same version)
build_meta() {
    local name=$1 root=$WORK/$1
    cp -a "$SRC/packaging/$name" "$root"
    local doc=$root/usr/share/doc/$name
    mkdir -p "$doc"
    {
        echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
        echo "Upstream-Name: oneq"
        echo "Upstream-Contact: oneq <k@1q.ro>"
        echo
        echo "Files: *"
        echo "Copyright: 2026 oneq <k@1q.ro>"
        echo "License: unspecified"
        echo " No license has been chosen for this software yet: all rights are reserved by the"
        echo " copyright holder. Choose and add a license before redistributing the packages."
    } > "$doc/copyright"
    {
        echo "$name ($VERSION) unstable; urgency=medium"
        echo
        echo "  * Meta-package: depends on oneqnode and oneqrelay of the same version."
        echo
        echo " -- oneq <k@1q.ro>  $(date -R -u -d '2026-10-18 12:00:00')"
    } | gzip -9n > "$doc/changelog.gz"
    sed -i 's/\r$//' "$root/DEBIAN/control"
    sed -i "s/@VERSION@/$VERSION/g" "$root/DEBIAN/control"
    find "$root" -type d -exec chmod 0755 {} +
    find "$root" -type f -exec chmod go-w,a+r {} +
    ( cd "$root" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' | sort -z | xargs -0 md5sum > DEBIAN/md5sums )
    local size
    size=$(du -sk --exclude=DEBIAN "$root" | cut -f1)
    sed -i "s/@SIZE@/$size/" "$root/DEBIAN/control"
    dpkg-deb --root-owner-group -Zxz -b "$root" "$OUT/${name}_${VERSION}_all.deb" >/dev/null
    echo "built $OUT/${name}_${VERSION}_all.deb ($(du -h "$OUT/${name}_${VERSION}_all.deb" | cut -f1))"
}

build oneqrelay relay "aiohttp==3.14.5 segno==1.6.1 cryptography==50.0.2" oneqrelay.py oneqadmin.py oneqadmin.html oneqtotp.py oneqinit.py oneqnat.py oneqpop.py meshdb.py rendezvous_server.py pqtls.py oneqconf.py pq_openssl.cnf
build oneqnode node "aiohttp==3.14.5 cryptography==50.0.2" oneqnode.py oneqnat.py oneqportmap.py oneqpop.py meshproto.py oneqtunel.py pqtls.py oneqconf.py pq_openssl.cnf
build_meta oneq-server
