#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Builds the Windows installer from dist/windows-amd64/ (build/dist.sh first,
# with WINTUN_DLL set) into dist/noirvpn-<version>-windows-amd64.msi.
#
#   build/msi.sh
#
# Run it on Windows in an MSYS2, MinGW or Git Bash shell. It needs WiX Toolset
# 5.0.2 and its Util extension of the same version:
#
#   dotnet tool install --global wix --version 5.0.2
#   wix extension add --global WixToolset.Util.wixext/5.0.2
#
# The WiX source is build/msi/noirvpn.wxs. The MSI is not signed.
#
# Environment:
#   WIX=wix        the WiX program, if wix is not on the PATH (default: wix,
#                  then %USERPROFILE%\.dotnet\tools\wix.exe)
#   MSI_VERSION    the product version x.y.z; default: VERSION_NUMBER of
#                  cmd/noirvpn without a suffix such as -dev
#   MSI_INSTANCE   the service instance (default desktop), for tests on a
#                  computer that has the service noirvpn-desktop already
set -euo pipefail

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
	sed -n '5,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
fi
if [[ $# -gt 0 ]]; then
	echo "msi.sh: unknown argument '$1'" >&2
	exit 2
fi

WIX_VERSION=5.0.2

case "$(uname -s)" in
MINGW* | MSYS* | CYGWIN*) ;;
*)
	echo "msi.sh: run this on Windows (an MSYS2, MinGW or Git Bash shell)" >&2
	exit 1
	;;
esac

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
dist=$repo/dist/windows-amd64
work=$repo/out/msi

wix=${WIX:-}
if [[ -z $wix ]]; then
	if command -v wix >/dev/null 2>&1; then
		wix=wix
	elif [[ -n ${USERPROFILE:-} && -x "$(cygpath -u "$USERPROFILE")/.dotnet/tools/wix.exe" ]]; then
		wix="$(cygpath -u "$USERPROFILE")/.dotnet/tools/wix.exe"
	else
		echo "msi.sh: wix not found; install it: dotnet tool install --global wix --version $WIX_VERSION" >&2
		exit 1
	fi
fi
have=$("$wix" --version | tr -d '\r')
if [[ ${have%%+*} != "$WIX_VERSION" ]]; then
	echo "msi.sh: wix $have found, $WIX_VERSION needed:" >&2
	echo "  dotnet tool update --global wix --version $WIX_VERSION" >&2
	exit 1
fi
if ! "$wix" extension list --global | tr -d '\r' | grep -qx "WixToolset.Util.wixext $WIX_VERSION"; then
	echo "msi.sh: the WiX extension WixToolset.Util.wixext $WIX_VERSION is not installed:" >&2
	echo "  $wix extension add --global WixToolset.Util.wixext/$WIX_VERSION" >&2
	exit 1
fi

version=${MSI_VERSION:-$(sed -n 's/^VERSION_NUMBER :: "\(.*\)"$/\1/p' "$repo/cmd/noirvpn/cli.odin")}
version=${version%%[-+]*}
if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "msi.sh: the version '$version' is not x.y.z" >&2
	exit 1
fi
instance=${MSI_INSTANCE:-desktop}
if [[ ! $instance =~ ^[A-Za-z0-9._-]{1,40}$ ]]; then
	echo "msi.sh: the instance name '$instance' is not valid" >&2
	exit 1
fi

# The MSI has a fixed list of files; the tree must have exactly these.
files=(
	LICENSE.txt
	MANIFEST.txt
	NOTICE.txt
	SDL3.dll
	THIRD-PARTY-NOTICES.txt
	libcrypto-3-x64.dll
	libssl-3-x64.dll
	licenses/DejaVu-LICENSE.txt
	licenses/GoogleSansFlex-OFL.txt
	licenses/Odin-LICENSE.txt
	licenses/Odin-compiler-rt-LICENSE.txt
	licenses/Odin-core-NOTICES.txt
	licenses/OpenSSL-LICENSE.txt
	licenses/SDL3-LICENSE.txt
	licenses/microui-LICENSE.txt
	licenses/stb-LICENSE.txt
	licenses/wintun-LICENSE.txt
	noirvpn-desktop.exe
	noirvpn.exe
	noirvpnctl.exe
	wintun.dll
)
if [[ ! -d $dist ]]; then
	echo "msi.sh: $dist does not exist; run WINTUN_DLL=... build/dist.sh first" >&2
	exit 1
fi
want=$(printf '%s\n' "${files[@]}" | LC_ALL=C sort)
got=$(cd "$dist" && find . -type f | sed 's|^\./||' | LC_ALL=C sort)
if [[ $want != "$got" ]]; then
	echo "msi.sh: the files in $dist are not the files of the MSI:" >&2
	diff <(echo "$want") <(echo "$got") | sed -n 's/^</  missing:/p; s/^>/  not in the MSI:/p' >&2
	exit 1
fi

# The default config is the one that `noirvpn service install` writes.
rm -rf "$work"
mkdir -p "$work"
awk '/^SVC_DEFAULT_CONFIG :: `/ { f = 1; sub(/^SVC_DEFAULT_CONFIG :: `/, ""); print; next }
	f && /^`$/ { exit }
	f { print }' "$repo/cmd/noirvpn/winsvc_windows.odin" >"$work/$instance.conf"
if ! grep -q '^client-service$' "$work/$instance.conf"; then
	echo "msi.sh: cannot read SVC_DEFAULT_CONFIG from cmd/noirvpn/winsvc_windows.odin" >&2
	exit 1
fi

msi=$repo/dist/noirvpn-$version-windows-amd64.msi
echo "== wix $have: $(basename "$msi") (version $version, service noirvpn-$instance)"
"$wix" build -arch x64 \
	-d Version="$version" -d Instance="$instance" \
	-d Dist="$(cygpath -w "$dist")" -d Data="$(cygpath -w "$work")" \
	-d Res="$(cygpath -w "$repo/desktop/res")" \
	-intermediatefolder "$(cygpath -w "$work/obj")" -pdb "$(cygpath -w "$work/noirvpn.wixpdb")" \
	-ext WixToolset.Util.wixext/$WIX_VERSION \
	-o "$(cygpath -w "$msi")" "$(cygpath -w "$repo/build/msi/noirvpn.wxs")"
# Windows Installer checks (ICE). ICE43 and ICE57 ask for a per-user key path
# for the Start menu shortcut; this package is per-machine only. ICE61:
# AllowSameVersionUpgrades, so two builds of one version do not install side by side.
"$wix" msi validate -sice ICE43 -sice ICE57 -sice ICE61 \
	-pdb "$(cygpath -w "$work/noirvpn.wixpdb")" "$(cygpath -w "$msi")"
echo "== $msi"
sha256sum "$msi" | sed "s|$repo/||"
