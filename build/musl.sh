#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Build one Odin package as a static musl binary, in a rootless podman
# container (image: see build/Containerfile.alpine).
#
#   build/musl.sh <package-dir> <output-name> [extra odin flags...]
#
#   build/musl.sh proto/ossl_demo ossl_demo
#   build/musl.sh cmd/dcoktest dcoktest -vet -strict-style
#
# <package-dir> is a path inside the repo, tried relative to the current
# directory first, then to the repo root. The binary is written to
# <repo>/out/musl/<output-name>. The repo is mounted read-only.
#
# Environment:
#   NOIR_CRYPTO=openssl|awslc   which crypto backend to compile and link
#                               (default: openssl)
#   NOIR_STATIC_PIE=1           link with -static-pie (ASLR) and not -static
#   NOIR_MUSL_MOUNT=DIR[:DIR]   host folders mounted read-only in the container
#                               at the same path, for an extra library that the
#                               flags name (for example -collection:x=DIR)
#   PODMAN=podman               container tool
#
# The Alpine static libraries carry debug info (20 MB instead of 6.6 MB for a
# small program). The link drops it (-Wl,--strip-debug) unless you pass Odin's
# -debug. Symbol names are kept.
#
# Do not pass -extra-linker-flags: this script sets it already (static, library
# paths), and Odin keeps only the last such flag.
set -euo pipefail

if [[ $# -lt 2 || $1 == -h || $1 == --help ]]; then
	sed -n '5,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
fi

pkg=$1
name=$2
shift 2

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/.." && pwd -P)
PODMAN=${PODMAN:-podman}

if [[ $name == */* || $name == . || $name == .. || -z $name ]]; then
	echo "musl.sh: output name must be a plain file name, got '$name'" >&2
	exit 2
fi

# Find the package directory and convert it to a path relative to the repo root.
if [[ -d $pkg ]]; then
	pkg_abs=$(cd "$pkg" && pwd -P)
elif [[ -d $repo/$pkg ]]; then
	pkg_abs=$(cd "$repo/$pkg" && pwd -P)
else
	echo "musl.sh: package directory '$pkg' not found (tried the current directory and $repo)" >&2
	exit 2
fi
case "$pkg_abs" in
"$repo") pkg_rel=. ;;
"$repo"/*) pkg_rel=${pkg_abs#"$repo"/} ;;
*)
	echo "musl.sh: $pkg_abs is outside the repo ($repo)" >&2
	exit 2
	;;
esac

# Libraries: nng is in /usr/local/lib, AWS-LC in /opt/aws-lc/lib. The OpenSSL
# static libs are in /usr/lib, where the linker finds them by default. A -L path
# that comes first wins, so awslc puts its path in front.
ldpaths="-L/usr/local/lib"
case "${NOIR_CRYPTO:-openssl}" in
openssl) ;;
awslc) ldpaths="-L/opt/aws-lc/lib $ldpaths" ;;
*)
	echo "musl.sh: NOIR_CRYPTO must be openssl or awslc" >&2
	exit 2
	;;
esac

static=-static
[[ ${NOIR_STATIC_PIE:-} == 1 ]] && static=-static-pie

strip=-Wl,--strip-debug
for arg in "$@"; do
	[[ $arg == -debug ]] && strip=
done

mounts=()
if [[ -n ${NOIR_MUSL_MOUNT:-} ]]; then
	IFS=: read -r -a dirs <<<"$NOIR_MUSL_MOUNT"
	for d in "${dirs[@]}"; do
		if [[ $d != /* || ! -d $d ]]; then
			echo "musl.sh: NOIR_MUSL_MOUNT: '$d' is not an absolute path of a folder" >&2
			exit 2
		fi
		mounts+=(-v "$d:$d:ro")
	done
fi

image=$("$here/image.sh")

mkdir -p "$repo/out/musl"

echo "musl.sh: building $pkg_rel -> out/musl/$name (crypto: ${NOIR_CRYPTO:-openssl})" >&2
"$PODMAN" run --rm \
	--pull=never \
	--network=none \
	-v "$repo":/src:ro \
	-v "$repo/out/musl":/out:rw \
	"${mounts[@]}" \
	-w /out \
	"$image" \
	odin build "/src/$pkg_rel" \
	-collection:noir=/src \
	-o:speed \
	-out:"/out/$name" \
	-extra-linker-flags:"$static $ldpaths $strip" \
	-define:NOIR_CRYPTO="${NOIR_CRYPTO:-openssl}" \
	"$@"

bin="$repo/out/musl/$name"
echo "musl.sh: built $bin ($(stat -c %s "$bin") bytes)" >&2
sha256sum "$bin"
