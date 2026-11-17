#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Rebuilds logo-mask.png from noirvpn-logo-mask.svg (logo without background).
# The mask is the trimmed alpha channel of the letters, 340 px high; the app
# scales it down. Needs inkscape and magick (ImageMagick).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
inkscape --export-type=png --export-filename="$tmp/big.png" --export-width=4000 \
	--export-background-opacity=0 "$here/noirvpn-logo-mask.svg" >/dev/null 2>&1
magick "$tmp/big.png" -trim +repage -alpha extract -resize x340 -depth 8 -colorspace Gray "$here/logo-mask.png"
