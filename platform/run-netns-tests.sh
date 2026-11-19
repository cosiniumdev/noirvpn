#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Run the privileged platform tests (tun device, addresses, routes) in a
# throwaway network namespace, without root on the host and without touching
# the host's network configuration.
#
#   platform/run-netns-tests.sh [options] [package...]
#
# Packages default to the ones with namespace tests: platform/tun, platform/offload,
# platform/sysnet and client. Paths are relative to the repo root.
#
# Options:
#   --musl     Build and run inside the musl build container (rootless podman,
#              --network=none, --cap-add NET_ADMIN, --device /dev/net/tun).
#              The test binary is static musl. Default: build with the host
#              Odin and run it under `unshare -rn`.
#   --         Everything after this goes to `odin build`, for example
#              -define:ODIN_TEST_NAMES=sysnet.netns_packets_through_the_tunnel_v4
#
# How it works: the tests are built with -define:NOIR_NETNS_TESTS=true (the
# privileged tests are not registered without it) and with one test thread
# (the tests share one namespace). The binary then runs as "root" only inside
# a new user and network namespace:
#   unshare -rn  creates both, with a fresh `lo` and no other network. The user
#                namespace maps your uid to 0, so CAP_NET_ADMIN is valid for the
#                new network namespace only, with no power over the host.
# The tests refuse to run outside a non-initial user namespace.
#
# Binaries go to <repo>/out/platform/. The
# exit code is 0 only if every package passed.
#
# Environment:
#   ODIN=odin    host compiler
#   PODMAN=podman
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/.." && pwd -P)
ODIN=${ODIN:-odin}
PODMAN=${PODMAN:-podman}

musl=0
pkgs=()
extra=()
while [[ $# -gt 0 ]]; do
	case $1 in
	-h | --help)
		sed -n '5,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
		exit 0
		;;
	--musl) musl=1 ;;
	--)
		shift
		extra=("$@")
		break
		;;
	-*)
		echo "run-netns-tests.sh: unknown option $1" >&2
		exit 2
		;;
	*) pkgs+=("$1") ;;
	esac
	shift
done
[[ ${#pkgs[@]} -gt 0 ]] || pkgs=(platform/tun platform/offload platform/sysnet client)

for p in "${pkgs[@]}"; do
	if [[ ! -d $repo/$p ]]; then
		echo "run-netns-tests.sh: no such package directory: $p" >&2
		exit 2
	fi
done

outdir=$repo/out/platform
mkdir -p "$outdir"

# Flags shared by both modes.
common=(
	-build-mode:test
	-vet -strict-style
	-define:NOIR_NETNS_TESTS=true
	-define:ODIN_TEST_THREADS=1
	$("$repo/build/microarch.sh")
)

if [[ $musl -eq 0 ]]; then
	if ! command -v "$ODIN" >/dev/null; then
		echo "run-netns-tests.sh: $ODIN not found (set ODIN=...)" >&2
		exit 2
	fi
	if ! unshare -rn true 2>/dev/null; then
		cat >&2 <<'EOF'
run-netns-tests.sh: `unshare -rn` is not allowed here (unprivileged user
namespaces are off, or an LSM blocks them). Try --musl (rootless podman), or
enable them: sysctl kernel.unprivileged_userns_clone=1 (Debian) or
kernel.apparmor_restrict_unprivileged_userns=0 (Ubuntu 24.04+).
EOF
		exit 1
	fi
	if [[ ! -c /dev/net/tun ]]; then
		echo "run-netns-tests.sh: /dev/net/tun is missing (modprobe tun)" >&2
		exit 1
	fi
else
	image=$("$repo/build/image.sh")
fi

failed=()
for p in "${pkgs[@]}"; do
	name=$(basename "$p")
	echo "== $p ($([[ $musl -eq 1 ]] && echo musl/podman || echo host/unshare))" >&2
	if [[ $musl -eq 0 ]]; then
		bin=$outdir/${name}_netns.test
		"$ODIN" build "$repo/$p" -collection:noir="$repo" "${common[@]}" -out:"$bin" "${extra[@]}"
		if unshare -rn "$bin"; then
			echo "PASS $p" >&2
		else
			echo "FAIL $p" >&2
			failed+=("$p")
		fi
	else
		# Build and run in one container, so the static binary never leaves it.
		# The repo is read-only. The container has a private namespace with `lo`
		# only, CAP_NET_ADMIN and the tun device node.
		if "$PODMAN" run --rm \
			--pull=never \
			--network=none \
			--cap-add NET_ADMIN \
			--device /dev/net/tun \
			-v "$repo":/src:ro \
			-w /tmp \
			"$image" \
			sh -c '
				set -e
				pkg=$1
				shift
				odin build "/src/$pkg" -collection:noir=/src '"${common[*]}"' \
					-out:/tmp/netns_test \
					-extra-linker-flags:"-static -L/usr/local/lib -Wl,--strip-debug" "$@"
				/tmp/netns_test
			' sh "$p" "${extra[@]}"; then
			echo "PASS $p" >&2
		else
			echo "FAIL $p" >&2
			failed+=("$p")
		fi
	fi
done

if [[ ${#failed[@]} -gt 0 ]]; then
	echo "run-netns-tests.sh: failed: ${failed[*]}" >&2
	exit 1
fi
echo "run-netns-tests.sh: all passed: ${pkgs[*]}" >&2
