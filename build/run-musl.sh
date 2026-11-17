#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Run a binary that build/musl.sh created (out/musl/<name>) inside the build
# container. Use it for benchmarks, so two builds run under the same conditions
# on the dev machine.
#
#   build/run-musl.sh <name> [program args...]
#
#   build/musl.sh proto/ossl/bench ossl_bench
#   build/run-musl.sh ossl_bench -hs -threads=1,4
#
# <name> is a file name in out/musl/. The container has no network and sees only
# out/musl/ (read-only). It can use all CPUs of the machine.
#
# Environment:
#   PODMAN=podman   container tool
set -euo pipefail

if [[ $# -lt 1 || $1 == -h || $1 == --help ]]; then
	sed -n '5,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
fi

name=$1
shift

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/.." && pwd -P)
PODMAN=${PODMAN:-podman}

if [[ $name == */* || $name == . || $name == .. || -z $name ]]; then
	echo "run-musl.sh: name must be a plain file name in out/musl/, got '$name'" >&2
	exit 2
fi
if [[ ! -x $repo/out/musl/$name ]]; then
	echo "run-musl.sh: $repo/out/musl/$name not found (build it with build/musl.sh)" >&2
	exit 2
fi

image=$("$here/image.sh")

exec "$PODMAN" run --rm \
	--pull=never \
	--network=none \
	-v "$repo/out/musl":/out:ro \
	-w /tmp \
	"$image" \
	"/out/$name" "$@"
