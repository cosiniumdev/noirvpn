#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Print the tag of the noirvpn musl build image. Build the image first if it
# does not exist. Build output goes to stderr, so stdout is only the tag.
#
#   build/image.sh              make sure the image exists, print its tag
#   build/image.sh --tag        only print the tag (no build)
#   build/image.sh --rebuild    rebuild now (podman layer cache is used)
#   build/image.sh --no-cache   rebuild now, from scratch
#
# The pins live in build/Containerfile.alpine (ARG lines). The tag is generated
# from ALPINE_VERSION and the first 7 characters of ODIN_COMMIT.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
containerfile="$here/Containerfile.alpine"
PODMAN=${PODMAN:-podman}

pin() { sed -n "s/^ARG $1=//p" "$containerfile" | head -n 1; }

alpine=$(pin ALPINE_VERSION)
odin=$(pin ODIN_COMMIT)
if [[ ! $odin =~ ^[0-9a-f]{40}$ ]]; then
	echo "image.sh: ODIN_COMMIT in $containerfile must be a full 40-character hash (got '$odin')" >&2
	exit 1
fi
tag="localhost/noirvpn-build:alpine${alpine}-odin${odin:0:7}"

mode=${1:-}
case "$mode" in
--tag)
	echo "$tag"
	exit 0
	;;
--rebuild | --no-cache)
	;;
"")
	if "$PODMAN" image exists "$tag"; then
		echo "$tag"
		exit 0
	fi
	;;
*)
	echo "usage: build/image.sh [--tag | --rebuild | --no-cache]" >&2
	exit 2
	;;
esac

extra=()
[[ $mode == --no-cache ]] && extra+=(--no-cache)

echo "image.sh: building $tag (the first build takes several minutes)" >&2
start=$SECONDS
# The build context is build/ only, so the repo is not sent to podman.
"$PODMAN" build "${extra[@]}" -t "$tag" -f "$containerfile" "$here" >&2
echo "image.sh: built $tag in $((SECONDS - start))s" >&2
echo "$tag"
