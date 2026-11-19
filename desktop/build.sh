#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Builds the desktop client into desktop/bin/noirvpn-desktop.
# - Collection noir is the repo root (imports bus, proto/config).
# - About shows the daemon version (VERSION_NUMBER of cmd/noirvpn/cli.odin) and
#   the local build date.
# Windows (MSYS2, MinGW or Git Bash): output is noirvpn-desktop.exe. SDL3.dll
#   and the OpenSSL DLLs go next to it; build/windows-openssl.sh creates the
#   import libraries in out/windows/lib. Icon: res/noirvpn.rc (res/noirvpn.ico,
#   from res/noirvpn-icon.png).
# macOS: nng 1.x is linked statically (build/macos-nng.sh builds it in
#   out/macos/nng); SDL3 and OpenSSL come from Homebrew (brew install sdl3 openssl).
# The CPU level is the level of build/microarch.sh (amd64: x86-64-v3).
# Usage: desktop/build.sh [extra odin build options]
# Set ODIN to the compiler when odin is not on the PATH.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
odin=${ODIN:-odin}
out="$here/bin/noirvpn-desktop"
windows=false
case "$(uname -s)" in
MINGW* | MSYS* | CYGWIN*)
	windows=true
	out="$out.exe"
	;;
esac
mkdir -p "$here/bin"
if [ "$(uname -s)" = Darwin ]; then
	"$here/../build/macos-nng.sh"
	brew_lib=$( (brew --prefix 2>/dev/null || echo /opt/homebrew) | tail -n 1)/lib
	set -- -extra-linker-flags:"-L$brew_lib" "$@"
fi
if $windows; then
	lib="$here/../out/windows/lib"
	"$here/../build/windows-openssl.sh" "$lib"
	set -- -extra-linker-flags:"/LIBPATH:$(cygpath -w "$lib")" -resource:"$(cygpath -w "$here/res/noirvpn.rc")" "$@"
fi
version=$(sed -n 's/^VERSION_NUMBER :: "\(.*\)"$/\1/p' "$here/../cmd/noirvpn/cli.odin")
"$odin" build "$here" -collection:noir="$here/.." -vet -strict-style -define:BUILD_DATE="$(date +%Y-%m-%d)" -define:VERSION_NUMBER="$version" $("$here/../build/microarch.sh") -out:"$out" "$@"
if $windows; then
	cp -f "$lib"/*.dll "$here/bin/"
	dll="$("$odin" root)/vendor/sdl3/SDL3.dll"
	if [ ! -f "$dll" ]; then
		echo "build.sh: $dll not found; put SDL3.dll next to $out" >&2
		exit 1
	fi
	cp -f "$dll" "$here/bin/"
fi
