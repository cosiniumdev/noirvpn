#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Builds the programs for this system and puts them, with their libraries and
# licence texts, into dist/<os>-<arch>/ in the repo root. Installers and packages
# (MSI, deb, apk) start from that directory.
#
#   build/dist.sh [--static]
#
#   --static   Linux only: build noirvpn, noirvpnctl and noirvpn-hook as static
#              musl binaries in the container (build/musl.sh). Default: build
#              with the libraries of this system.
#
# The target is the system the script runs on: linux-amd64, linux-arm64,
# darwin-arm64, darwin-amd64 or windows-amd64 (an MSYS2, MinGW or Git Bash
# shell). A program with no port to the target is skipped with a note.
#
# Layout:
#   linux-<arch>/     bin/noirvpn, bin/noirvpnctl, bin/noirvpn-hook,
#                     bin/noirvpn-desktop, bin/noirvpn-service (launcher script),
#                     share/noirvpn/service.conf, share/applications/noirvpn.desktop,
#                     share/icons/hicolor/*/apps/noirvpn.png, share/doc/noirvpn/,
#                     share/licenses/noirvpn/, MANIFEST
#   darwin-<arch>/    bin/noirvpn, bin/noirvpnctl, bin/noirvpn-desktop, share/doc/noirvpn/,
#                     share/licenses/noirvpn/, MANIFEST. The programs link
#                     OpenSSL and SDL3 from Homebrew (dynamic libraries) and
#                     nng 1.x statically (build/macos-nng.sh).
#   windows-<arch>/   noirvpn.exe, noirvpnctl.exe, noirvpn-desktop.exe,
#                     libcrypto-3-x64.dll, libssl-3-x64.dll, SDL3.dll,
#                     wintun.dll (with WINTUN_DLL), LICENSE.txt, NOTICE.txt,
#                     THIRD-PARTY-NOTICES.txt, licenses\, MANIFEST.txt
#                     (flat, for the MSI)
#
# share/licenses/noirvpn/ has LICENSE, NOTICE, THIRD-PARTY-NOTICES.md and the
# texts of packaging/licenses that this build needs. On Windows the first three
# are in the top folder (as .txt) and the texts in licenses\.
#
# MANIFEST lists the version, commit, build date and SHA-256 of each file.
#
# Environment:
#   ODIN=odin   the compiler, when odin is not on the PATH
#   WINTUN_DLL  Windows: path of wintun.dll (amd64) to copy; without it the tree
#               has no wintun.dll and the daemon cannot create a tunnel
#   WINTUN_LICENSE  Windows: the wintun licence text; default: LICENSE.txt of the
#               wintun zip (WINTUN_DLL is bin/amd64/wintun.dll in it), else
#               packaging/licenses/wintun-LICENSE.txt
#   NOIR_CRYPTO=awslc  with --static: musl.sh links AWS-LC; its licence is added
set -euo pipefail

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
	sed -n '5,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
fi
static=false
for a in "$@"; do
	case $a in
	--static) static=true ;;
	*)
		echo "dist.sh: unknown argument '$a'" >&2
		exit 2
		;;
	esac
done

# sha256sum is not on macOS; shasum -a 256 prints the same lines.
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$@"; }
else
	sha256() { shasum -a 256 "$@"; }
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
odin=${ODIN:-odin}
export ODIN=$odin

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
MINGW* | MSYS* | CYGWIN*) os=windows ;;
*)
	echo "dist.sh: $(uname -s) is not a target yet" >&2
	exit 1
	;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*)
	echo "dist.sh: $(uname -m) is not a target yet" >&2
	exit 1
	;;
esac
if $static && [[ $os != linux ]]; then
	echo "dist.sh: --static is for Linux only" >&2
	exit 2
fi

target=$os-$arch
out=$repo/dist/$target
version=$(sed -n 's/^VERSION_NUMBER :: "\(.*\)"$/\1/p' "$repo/cmd/noirvpn/cli.odin")
commit=$(git -C "$repo" describe --always --dirty 2>/dev/null || echo unknown)
date=$(date -u +%Y-%m-%d)

rm -rf "$out"
mkdir -p "$out"

# The daemon, the control tool and the hook runner. Windows has no hook runner,
# and the daemon links the OpenSSL DLLs through the import libraries of
# build/windows-openssl.sh.
cli=(noirvpn noirvpnctl noirvpn-hook)
if [[ $os == darwin ]]; then
	# nng 1.x is built here as a static library (Homebrew has only nng 2.x).
	"$repo/build/macos-nng.sh"
	brew_lib=$( (brew --prefix 2>/dev/null || echo /opt/homebrew) | tail -n 1)/lib
	mkdir -p "$out/bin"
	for name in noirvpn noirvpnctl; do
		echo "== $name"
		"$odin" build "$repo/cmd/$name" -collection:noir="$repo" -vet -strict-style -o:speed \
			-extra-linker-flags:"-L$brew_lib" -out:"$out/bin/$name"
	done
	echo "== noirvpn-hook: skipped, not on macOS"
elif [[ $os == linux ]]; then
	mkdir -p "$out/bin"
	for name in "${cli[@]}"; do
		echo "== $name"
		if $static; then
			"$repo/build/musl.sh" "cmd/$name" "$name" -vet -strict-style
			cp "$repo/out/musl/$name" "$out/bin/$name"
		else
			"$odin" build "$repo/cmd/$name" -collection:noir="$repo" -vet -strict-style -o:speed \
				-out:"$out/bin/$name"
		fi
	done
else
	lib=$repo/out/windows/lib
	"$repo/build/windows-openssl.sh" "$lib"
	for name in noirvpn noirvpnctl; do
		echo "== $name"
		"$odin" build "$repo/cmd/$name" -collection:noir="$repo" -vet -strict-style -o:speed \
			-extra-linker-flags:"/LIBPATH:$(cygpath -w "$lib")" -out:"$out/$name.exe"
	done
	echo "== noirvpn-hook: skipped, not on Windows"
	cp "$lib"/libcrypto-3-x64.dll "$lib"/libssl-3-x64.dll "$out/"
	if [[ -n ${WINTUN_DLL:-} ]]; then
		# The wintun licence allows it only next to a program that uses its API,
		# with its notices: the licence goes with the DLL.
		# The text of the zip is used when it is there; else the copy in
		# packaging/licenses (wintun 0.14.1).
		wintun_lic=${WINTUN_LICENSE:-$(dirname "$WINTUN_DLL")/../../LICENSE.txt}
		if [[ ! -f $wintun_lic ]]; then
			echo "== wintun licence: $wintun_lic not found, using packaging/licenses/wintun-LICENSE.txt"
			wintun_lic=$repo/packaging/licenses/wintun-LICENSE.txt
		elif ! cmp -s "$wintun_lic" "$repo/packaging/licenses/wintun-LICENSE.txt"; then
			echo "== wintun licence: $wintun_lic differs from packaging/licenses/wintun-LICENSE.txt; update the copy there"
		fi
		cp "$WINTUN_DLL" "$out/wintun.dll"
	else
		echo "== wintun.dll: skipped, set WINTUN_DLL"
	fi
fi

# The desktop client. On Windows desktop/build.sh also copies SDL3.dll, and
# the program gets no console window.
echo "== noirvpn-desktop"
if [[ $os == darwin ]]; then
	# The nng and Homebrew flags are set by desktop/build.sh.
	"$repo/desktop/build.sh" -o:speed
	cp "$repo/desktop/bin/noirvpn-desktop" "$out/bin/"
elif [[ $os == windows ]]; then
	"$repo/desktop/build.sh" -o:speed -subsystem:windows
	cp "$repo/desktop/bin/noirvpn-desktop.exe" "$repo/desktop/bin/SDL3.dll" "$out/"
else
	"$repo/desktop/build.sh" -o:speed
	cp "$repo/desktop/bin/noirvpn-desktop" "$out/bin/"
	# The launcher of the service and its default base config.
	cp "$repo/packaging/linux/noirvpn-service" "$out/bin/"
	mkdir -p "$out/share/noirvpn"
	cp "$repo/packaging/linux/service.conf" "$out/share/noirvpn/"
	# The desktop entry and the icons.
	mkdir -p "$out/share/applications"
	cp "$repo/packaging/linux/noirvpn.desktop" "$out/share/applications/"
	for d in "$repo"/packaging/linux/icons/*x*; do
		mkdir -p "$out/share/icons/hicolor/$(basename "$d")/apps"
		cp "$d/noirvpn.png" "$out/share/icons/hicolor/$(basename "$d")/apps/"
	done
fi

# Documents and licence texts: LICENSE, NOTICE, THIRD-PARTY-NOTICES and the
# texts in packaging/licenses of the components in this build (see
# THIRD-PARTY-NOTICES.md, "What each build contains").
if [[ $os == windows ]]; then
	lic=$out/licenses
	mkdir -p "$lic"
	cp "$repo/LICENSE" "$out/LICENSE.txt"
	cp "$repo/NOTICE" "$out/NOTICE.txt"
	cp "$repo/THIRD-PARTY-NOTICES.md" "$out/THIRD-PARTY-NOTICES.txt"
else
	lic=$out/share/licenses/noirvpn
	doc=$out/share/doc/noirvpn
	mkdir -p "$doc"
	cp "$repo/README.md" "$repo/USAGE.md" "$doc/"
	cp "$repo/docs/"*.md "$doc/"
	mkdir -p "$lic"
	cp "$repo/LICENSE" "$repo/NOTICE" "$repo/THIRD-PARTY-NOTICES.md" "$lic/"
fi
# In every build: the Odin libraries, microui and stb (inside the programs),
# SDL3 and OpenSSL (shipped on Windows, linked from the system elsewhere).
texts=(Odin-LICENSE.txt Odin-compiler-rt-LICENSE.txt Odin-core-NOTICES.txt
	microui-LICENSE.txt stb-LICENSE.txt SDL3-LICENSE.txt OpenSSL-LICENSE.txt)
# nng: static on macOS and in a static Linux build, a system library on Linux.
[[ $os != windows ]] && texts+=(nng-LICENSE.txt)
# A static Linux build has musl and libgcc inside, and AWS-LC when musl.sh
# links it (NOIR_CRYPTO=awslc).
if $static; then
	texts+=(musl-LICENSE.txt libgcc-GPL-3.0.txt libgcc-RUNTIME-EXCEPTION.txt)
	[[ ${NOIR_CRYPTO:-openssl} == awslc ]] && texts+=(AWS-LC-LICENSE.txt)
fi
for t in "${texts[@]}"; do
	cp "$repo/packaging/licenses/$t" "$lic/"
done
if [[ $os == windows && -n ${WINTUN_DLL:-} ]]; then
	cp "$wintun_lic" "$lic/wintun-LICENSE.txt"
fi
# The fonts are inside noirvpn-desktop.
cp "$repo/desktop/ui/fonts/GOOGLESANSFLEX-OFL.txt" "$lic/GoogleSansFlex-OFL.txt"
cp "$repo/desktop/ui/fonts/DEJAVU-LICENSE.txt" "$lic/DejaVu-LICENSE.txt"

# MANIFEST: what was built, and the hash of each file.
manifest=$out/MANIFEST
[[ $os == windows ]] && manifest=$out/MANIFEST.txt
{
	echo "noirvpn $version"
	echo "target  $target"
	echo "commit  $commit"
	echo "date    $date"
	if [[ $os == linux ]]; then
		$static && echo "build   static (musl)" || echo "build   system libraries"
	elif [[ $os == darwin ]]; then
		echo "build   nng static, OpenSSL and SDL3 from Homebrew (dynamic)"
	fi
	echo
	(cd "$out" && find . -type f ! -name "$(basename "$manifest")" | sed 's|^\./||' | LC_ALL=C sort |
		while read -r f; do sha256 "$f"; done)
} >"$manifest"

echo "== dist/$target"
(cd "$out" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
