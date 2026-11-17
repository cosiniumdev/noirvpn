#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Cosinium
# SPDX-License-Identifier: Apache-2.0

# Extract the third-party notices that are embedded in Odin core source files.
# usage: odin_notices.py <odin-root>   -> prints the notice text on stdout
import re, sys, pathlib

root = pathlib.Path(sys.argv[1])

def strip_comment(lines):
    out = []
    for l in lines:
        l = l.rstrip("\n").rstrip()
        l = re.sub(r"^\t+", "", l)
        l = re.sub(r"^\s*(//|\*/|/\*|\*)( |$)", "", l) if re.match(r"^\s*(//|/\*|\*)", l) else l
        out.append(l.rstrip())
    while out and not out[0]:
        out.pop(0)
    while out and not out[-1]:
        out.pop()
    return out

def block(rel, start, end, comment=True, first=True):
    lines = (root / rel).read_text(encoding="utf-8").splitlines()
    res = []
    i = 0
    while i < len(lines):
        if re.search(start, lines[i]):
            j = i
            while j < len(lines) and not re.search(end, lines[j]):
                j += 1
            seg = lines[i : j + 1]
            res.append(strip_comment(seg) if comment else [s.rstrip() for s in seg])
            if first:
                break
            i = j
        i += 1
    if not res:
        sys.exit(f"odin_notices: no block /{start}/ in {rel}")
    return res

sections = []

def add(title, files, text_lines):
    sections.append((title, files, text_lines))

add("Go (math functions ported from Go /src/math)",
    ["core/math/math.odin"],
    block("core/math/math.odin", r"Copyright \(c\) 2009 The Go Authors", r"EVEN IF ADVISED OF THE POSSIBILITY")[0])

sun_files = ["core/math/math.odin", "core/math/math_basic.odin", "core/math/math_cbrt.odin",
             "core/math/math_erf.odin", "core/math/math_lgamma.odin", "core/math/math_log1p.odin"]
sun = set()
for f in sun_files:
    for b in block(f, r"Copyright \(C\) 1993 by Sun Microsystems", r"is preserved\.", first=False):
        sun.add("\n".join(b))
# Two forms: "Developed at SunPro" and "Developed at SunSoft".
add("FreeBSD msun / Sun Microsystems fdlibm (math functions)", sun_files,
    "\n\n".join(sorted(sun)).split("\n"))

ceph = set()
for f in ["core/math/math_gamma.odin", "core/math/math_sincos.odin"]:
    for b in block(f, r"Cephes Math Library Release", r"moshier@na-net\.ornl\.gov", first=False):
        ceph.add("\n".join(b))
if len(ceph) != 1:
    sys.exit("odin_notices: the Cephes notices differ")
add("Cephes Math Library (gamma, sin/cos, via Go)", ["core/math/math_gamma.odin", "core/math/math_sincos.odin"],
    ceph.pop().split("\n"))

add("BearSSL constant-time primitives (Thomas Pornin)", ["core/crypto/_subtle/subtle.odin"],
    block("core/crypto/_subtle/subtle.odin", r"Copyright \(c\) 2016 Thomas Pornin", r"SUCH DAMAGE\.")[0])

add("HashMe SHA-512 hardware round function (Marc Schöndorf), arm64 only",
    ["core/crypto/sha2/sha512_impl_hw_arm.odin"],
    block("core/crypto/sha2/sha512_impl_hw_arm.odin", r"The round function's intrinsic", r"This notice may not be removed")[0])

add("Unicode Character Database (Unicode tables)", ["core/unicode/generated.odin"],
    block("core/unicode/generated.odin", r"UNICODE LICENSE V3", r"authorization of the copyright holder", comment=False)[0])

add("fast_float / ffc.h (float parsing)", ["core/strconv/fast_float.odin"],
    block("core/strconv/fast_float.odin", r"^Ported from ffc\.h and fast_float", r"^DEALINGS IN THE SOFTWARE", comment=False)[0])

if (root / "core/strconv/zmij.odin").exists():
    add("Żmij (float formatting)", ["core/strconv/zmij.odin"],
        block("core/strconv/zmij.odin", r"^Ported from the scalar path", r"^DEALINGS IN THE SOFTWARE", comment=False)[0])

for title, files, text in sections:
    text = [re.sub(r"^\t", "", t) for t in text]
    print("=" * 78)
    print(title)
    print("Odin source: " + ", ".join(files))
    print("=" * 78)
    print()
    print("\n".join(text))
    print()
