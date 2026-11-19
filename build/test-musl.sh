#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Run `odin test` on one package inside the musl build container, with a
# static link, like build/musl.sh does for builds.
#
#   build/test-musl.sh <package-dir> [extra odin flags...]
#
#   build/test-musl.sh proto/ossl                         # OpenSSL (default)
#   NOIR_CRYPTO=awslc build/test-musl.sh proto/ossl       # AWS-LC
#   build/test-musl.sh proto/ossl -define:ODIN_TEST_NAMES=ossl.pinning_ed25519
#
# <package-dir> is a path inside the repo, tried relative to the current
# directory first, then to the repo root. The repo is mounted read-only and the
# container has no network. The test binary is built and run inside the
# container and thrown away.
#
# Environment:
#   NOIR_CRYPTO=openssl|awslc   which static libssl/libcrypto to link and which
#                               backend to compile (default: openssl). Unlike
#                               build/musl.sh it also passes -define:NOIR_CRYPTO=...
#   NOIR_MUSL_MOUNT=DIR[:DIR]   host folders mounted read-only at the same path
#                               (as in build/musl.sh)
#   PODMAN=podman               container tool
#
# The flags are the ones the Makefile uses (-vet -strict-style). The exit code is
# that of the test run.
set -euo pipefail

if [[ $# -lt 1 || $1 == -h || $1 == --help ]]; then
	sed -n '5,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
fi

pkg=$1
shift

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/.." && pwd -P)
PODMAN=${PODMAN:-podman}

if [[ -d $pkg ]]; then
	pkg_abs=$(cd "$pkg" && pwd -P)
elif [[ -d $repo/$pkg ]]; then
	pkg_abs=$(cd "$repo/$pkg" && pwd -P)
else
	echo "test-musl.sh: package directory '$pkg' not found (tried the current directory and $repo)" >&2
	exit 2
fi
case "$pkg_abs" in
"$repo") pkg_rel=. ;;
"$repo"/*) pkg_rel=${pkg_abs#"$repo"/} ;;
*)
	echo "test-musl.sh: $pkg_abs is outside the repo ($repo)" >&2
	exit 2
	;;
esac

crypto=${NOIR_CRYPTO:-openssl}
ldpaths="-L/usr/local/lib"
case "$crypto" in
openssl) ;;
awslc) ldpaths="-L/opt/aws-lc/lib $ldpaths" ;;
*)
	echo "test-musl.sh: NOIR_CRYPTO must be openssl or awslc" >&2
	exit 2
	;;
esac

mounts=()
if [[ -n ${NOIR_MUSL_MOUNT:-} ]]; then
	IFS=: read -r -a dirs <<<"$NOIR_MUSL_MOUNT"
	for d in "${dirs[@]}"; do
		if [[ $d != /* || ! -d $d ]]; then
			echo "test-musl.sh: NOIR_MUSL_MOUNT: '$d' is not an absolute path of a folder" >&2
			exit 2
		fi
		mounts+=(-v "$d:$d:ro")
	done
fi

image=$("$here/image.sh")

echo "test-musl.sh: testing $pkg_rel (crypto: $crypto)" >&2
exec "$PODMAN" run --rm \
	--pull=never \
	--network=none \
	-v "$repo":/src:ro \
	"${mounts[@]}" \
	-w /tmp \
	"$image" \
	odin test "/src/$pkg_rel" \
	-collection:noir=/src \
	-vet -strict-style \
	-out:/tmp/noir_test \
	-define:NOIR_CRYPTO="$crypto" \
	-extra-linker-flags:"-static $ldpaths -Wl,--strip-debug" \
	$("$here/microarch.sh") \
	"$@"
