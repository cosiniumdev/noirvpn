#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Generates a test identity for pinned mode: a self-signed EC P-256 key and
# certificate, and the lines to paste into the other side's config.
#
#   examples/gen-peer.sh NAME [OUTDIR]
#
# Writes OUTDIR/NAME.key and OUTDIR/NAME.crt (OUTDIR defaults to the current
# directory), then prints two lines:
#
#   NAME sha256:<base64 SHA-256 of the SubjectPublicKeyInfo>
#       one line of a noirvpn server peers file (`peer-keys`)
#   fingerprint AA:BB:...
#       the SHA-256 of the whole certificate, for `peer-fingerprint` in a
#       client (stock OpenVPN or noirvpn) that must trust this one
#
# Only for tests. The key has no password. Needs openssl 1.1.1 or newer. An
# existing key and certificate are kept, so the same NAME gives the same lines.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || $1 == -h || $1 == --help ]]; then
	sed -n '5,/^set -/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
fi

name=$1
dir=${2:-.}

# The peers file takes the name as one word.
if [[ ! $name =~ ^[A-Za-z0-9._@-]+$ ]]; then
	echo "gen-peer.sh: NAME may only have letters, digits and . _ @ -" >&2
	exit 2
fi
mkdir -p "$dir"

key=$dir/$name.key
crt=$dir/$name.crt
if [[ ! -f $key || ! -f $crt ]]; then
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout "$key" -out "$crt" -subj "/CN=$name" -days 3650 2>/dev/null
	chmod 600 "$key"
fi

# SHA-256 of the DER SubjectPublicKeyInfo, in base64 with padding.
spki=$(openssl x509 -in "$crt" -noout -pubkey |
	openssl pkey -pubin -outform DER |
	openssl dgst -sha256 -binary |
	base64 -w0)
fp=$(openssl x509 -in "$crt" -noout -fingerprint -sha256 | cut -d= -f2)

echo "$name sha256:$spki"
echo "fingerprint $fp"
