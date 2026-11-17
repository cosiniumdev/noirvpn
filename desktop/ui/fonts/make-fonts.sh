#!/bin/sh
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Generates the static Google Sans Flex faces from the variable font of a release
# (https://github.com/googlefonts/googlesans-flex/releases, v5.000).
# Needs Python with fontTools. Usage: make-fonts.sh 'GoogleSansFlex[ROND,opsz,slnt,wdth,wght].ttf'
set -eu
src=$1
out=$(dirname "$0")
python3 -I - "$src" "$out" <<'PY'
import sys
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer
from fontTools import subset
src, out = sys.argv[1], sys.argv[2]
# Basic Latin, Latin-1, Latin Extended-A, punctuation, a few symbols and arrows.
uni = (list(range(0x20, 0x7f)) + list(range(0xa0, 0x180)) + list(range(0x2010, 0x2028))
	+ list(range(0x2030, 0x203b)) + [0x20ac, 0x2122, 0x2190, 0x2191, 0x2192, 0x2193, 0x2212, 0x2713, 0x2715])
for name, w in [("Regular", 400), ("Medium", 500), ("SemiBold", 600), ("Bold", 700)]:
	f = instancer.instantiateVariableFont(TTFont(src),
		{"wght": w, "opsz": 18, "wdth": 100, "ROND": 0, "slnt": 0}, updateFontNames=False)
	o = subset.Options()
	o.layout_features = ["kern"]
	o.hinting = False
	o.name_IDs = ["*"]
	o.notdef_outline = True
	s = subset.Subsetter(o)
	s.populate(unicodes=uni)
	s.subset(f)
	nm = f["name"]
	nm.setName("Google Sans Flex", 1, 3, 1, 0x409)
	nm.setName(name, 2, 3, 1, 0x409)
	nm.setName("Google Sans Flex " + name, 4, 3, 1, 0x409)
	nm.setName("GoogleSansFlex-" + name, 6, 3, 1, 0x409)
	f["OS/2"].usWeightClass = w
	f.save(f"{out}/GoogleSansFlex-{name}.ttf")
PY
