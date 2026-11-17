#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Builds nng 1.x as a static library for macOS, into out/macos/nng.
#
# The control bus (bus/nng) needs the nng 1 API. Homebrew has only nng 2.x, a
# different API (bus/nng/README.md lists the changes), so the 1.x source is built
# here as a static library: the programs need no nng at run time. bus/nng links
# out/macos/nng/lib/libnng.a by its path, so a Homebrew nng cannot take its place.
#
# Usage: build/macos-nng.sh [PREFIX]       (default: out/macos/nng)
#
# Environment:
#   NNG_VERSION  the release to build (default 1.11)
#   MACOSX_DEPLOYMENT_TARGET  the oldest macOS the library runs on (default 14.0)
#   NNG_SRC      a folder with the source, instead of the download
# Needs cmake (brew install cmake), a C compiler, and curl for the download. Does
# nothing if <PREFIX>/lib/libnng.a exists for the same deployment target.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
prefix=${1:-$root/out/macos/nng}
version=${NNG_VERSION:-1.11}
min=${MACOSX_DEPLOYMENT_TARGET:-14.0}

# The library records its target in a stamp file; a different target builds again.
stamp=$prefix/lib/.deployment-target
if [ -f "$prefix/lib/libnng.a" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$min" ]; then
	echo "macos-nng.sh: $prefix/lib/libnng.a exists"
	exit 0
fi
if ! command -v cmake >/dev/null 2>&1; then
	echo "macos-nng.sh: cmake not found (brew install cmake)" >&2
	exit 1
fi

work=$root/out/macos/nng-build
mkdir -p "$work"
src=${NNG_SRC:-}
if [ -z "$src" ]; then
	src=$work/nng-$version
	if [ ! -d "$src" ]; then
		echo "macos-nng.sh: downloading nng $version"
		curl -fsSL "https://github.com/nanomsg/nng/archive/refs/tags/v$version.tar.gz" -o "$work/nng-$version.tar.gz"
		tar -xzf "$work/nng-$version.tar.gz" -C "$work"
	fi
fi

rm -rf "$work/build"
cmake -S "$src" -B "$work/build" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_OSX_DEPLOYMENT_TARGET="$min" \
	-DCMAKE_INSTALL_PREFIX="$prefix" \
	-DBUILD_SHARED_LIBS=OFF \
	-DNNG_TESTS=OFF \
	-DNNG_TOOLS=OFF \
	-DNNG_ENABLE_NNGCAT=OFF \
	-DCMAKE_POSITION_INDEPENDENT_CODE=ON \
	-DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null
cmake --build "$work/build" --parallel >/dev/null
cmake --install "$work/build" >/dev/null
echo "$min" >"$stamp"
echo "macos-nng.sh: $prefix/lib/libnng.a (macOS $min)"
