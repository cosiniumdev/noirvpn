#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Builds the OpenSSL 3.5 LTS DLLs from source with the MSYS2 UCRT64 compiler,
# into out/windows/openssl.
#
# MSYS2 has OpenSSL 4.x only. The programs need the 3.x DLLs
# (libcrypto-3-x64.dll, libssl-3-x64.dll), so the pinned 3.5 release is built
# here. build/windows-openssl.sh runs this script when OPENSSL_BIN is not set.
#
# Usage: build/windows-openssl-src.sh [PREFIX]   (default: out/windows/openssl)
#
# Needs the MSYS2 UCRT64 shell with:
#   pacman -S --needed make perl mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-nasm
# Does nothing if PREFIX has the DLLs of the same version.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
prefix=${1:-$root/out/windows/openssl}
version=3.5.9
sha256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

stamp=$prefix/bin/.version
if [ -f "$prefix/bin/libssl-3-x64.dll" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$version" ]; then
	echo "windows-openssl-src.sh: OpenSSL $version in $prefix"
	exit 0
fi
case "${MSYSTEM:-}" in
UCRT64 | MINGW64 | CLANG64) ;;
*)
	echo "windows-openssl-src.sh: run in the MSYS2 UCRT64 shell" >&2
	exit 1
	;;
esac
for tool in gcc nasm perl make; do
	if ! command -v $tool >/dev/null 2>&1; then
		echo "windows-openssl-src.sh: $tool not found (see the Needs line of this script)" >&2
		exit 1
	fi
done

work=$root/out/windows/openssl-build
tarball=$work/openssl-$version.tar.gz
mkdir -p "$work"
if [ ! -f "$tarball" ]; then
	echo "windows-openssl-src.sh: downloading OpenSSL $version"
	curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-$version/openssl-$version.tar.gz" \
		-o "$tarball.part"
	mv "$tarball.part" "$tarball"
fi
if ! echo "$sha256  $tarball" | sha256sum -c - >/dev/null; then
	echo "windows-openssl-src.sh: $tarball has the wrong SHA-256" >&2
	rm -f "$tarball"
	exit 1
fi

rm -rf "$work/openssl-$version"
tar -xzf "$tarball" -C "$work"
cd "$work/openssl-$version"
log=$work/build.log
echo "windows-openssl-src.sh: building OpenSSL $version (some minutes, log in $log)"
if ! { ./Configure mingw64 shared no-tests no-docs --prefix="$prefix" --libdir=lib &&
	make -j"$(nproc)" && make install_sw; } >"$log" 2>&1; then
	tail -n 40 "$log" >&2
	echo "windows-openssl-src.sh: the build failed, see $log" >&2
	exit 1
fi
echo "$version" >"$stamp"
rm -rf "$work/openssl-$version"
echo "windows-openssl-src.sh: OpenSSL $version in $prefix"
