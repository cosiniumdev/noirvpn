#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Creates the MSVC import libraries crypto.lib and ssl.lib for the MinGW-w64
# OpenSSL DLLs (libcrypto-3-x64.dll, libssl-3-x64.dll), and copies the DLLs
# next to them. The Odin linker cannot read the MinGW .dll.a files, so the
# libraries are generated from the DLL exports with dumpbin and lib of Visual Studio.
#
# Usage: build/windows-openssl.sh [OUT]       (default: out/windows/lib)
# Then:  odin build ... -extra-linker-flags:/LIBPATH:<OUT as a Windows path>
#        and copy OUT/*.dll next to the program.
#
# Environment:
#   OPENSSL_BIN  the folder of the two DLLs (default: out/windows/openssl/bin,
#                built by build/windows-openssl-src.sh)
#   VSTOOLS      the folder of dumpbin.exe and lib.exe (default: an MSVC
#                Hostx64/x64 folder of Visual Studio 2022 or later)
# Runs in an MSYS2 or Git Bash shell. Does nothing if the libraries are newer
# than the DLLs.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/out/windows/lib}
bin=${OPENSSL_BIN:-}
if [ -z "$bin" ]; then
	"$root/build/windows-openssl-src.sh"
	bin=$root/out/windows/openssl/bin
fi

tools=${VSTOOLS:-}
if [ -z "$tools" ]; then
	# <version>/<edition>: 2022/BuildTools, 18/Enterprise (Visual Studio 2026), ...
	for d in "/c/Program Files/Microsoft Visual Studio"/*/*/VC/Tools/MSVC/*/bin/Hostx64/x64; do
		[ -x "$d/lib.exe" ] && tools=$d
	done
fi
if [ -z "$tools" ] || [ ! -x "$tools/lib.exe" ] || [ ! -x "$tools/dumpbin.exe" ]; then
	echo "windows-openssl.sh: dumpbin.exe and lib.exe not found; set VSTOOLS" >&2
	exit 1
fi

# The arguments of the MSVC tools start with a slash: MSYS must not turn
# them into paths.
export MSYS2_ARG_CONV_EXCL='*' MSYS_NO_PATHCONV=1

mkdir -p "$out"
for pair in crypto:libcrypto-3-x64 ssl:libssl-3-x64; do
	lib=${pair%%:*}
	dll=${pair#*:}
	src="$bin/$dll.dll"
	if [ ! -f "$src" ]; then
		echo "windows-openssl.sh: $src not found (OPENSSL_BIN must hold OpenSSL 3.x)" >&2
		exit 1
	fi
	cp -f "$src" "$out/"
	if [ -f "$out/$lib.lib" ] && [ "$out/$lib.lib" -nt "$src" ]; then
		continue
	fi
	{
		echo "LIBRARY $dll.dll"
		echo "EXPORTS"
		# The export table: "ordinal hint RVA name" rows.
		"$tools/dumpbin.exe" -nologo -exports "$(cygpath -w "$src")" |
			awk '/ordinal +hint +RVA +name/ { on = 1; next }
				on && /^ *Summary/ { exit }
				on && NF >= 4 && $1 ~ /^[0-9]+$/ { print "    " $4 }'
	} | tr -d '\r' >"$out/$lib.def"
	# lib.exe writes into the current folder when /OUT has a path, on some
	# versions: run it in the output folder with plain names.
	(cd "$out" && "$tools/lib.exe" -nologo -def:"$lib.def" -machine:x64 -out:"$lib.lib" >/dev/null)
	rm -f "$out/$lib.exp" "$out/$lib.def"
	echo "windows-openssl.sh: $out/$lib.lib"
done
