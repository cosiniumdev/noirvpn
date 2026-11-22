# Third-party notices

noirvpn is licensed under the Apache License 2.0 (`LICENSE`, `NOTICE`). The
programs that the build scripts make contain, or are shipped next to, the
third-party code below. Each component keeps its own license. The license
texts are in `packaging/licenses/` in the source tree; the font licenses are
next to the fonts in `desktop/ui/fonts/`. A binary distribution has them in
`share/licenses/noirvpn/` (Linux, macOS) or in `licenses\` of the install
folder (Windows).

## Components

| Component | Version or pin | License | Notice in binary form | File |
|-----------|----------------|---------|-----------------------|------|
| OpenSSL | 3.5.9 (Alpine `openssl-libs-static`, static musl builds); the system or Homebrew library on Linux and macOS; built from source with the MSYS2 UCRT64 compiler on Windows | Apache-2.0 | yes | `OpenSSL-LICENSE.txt` |
| AWS-LC | 5.0.0 (`AWSLC_VERSION`, static musl builds with `NOIR_CRYPTO=awslc`) | Apache-2.0 OR ISC, with parts under ISC, Apache-2.0, MIT and BSD-3-Clause (see the file) | yes | `AWS-LC-LICENSE.txt` |
| nng | 1.11 (`NNG_VERSION`) | MIT | yes | `nng-LICENSE.txt` |
| SDL3 | 3.4.20 (the Odin `vendor:sdl3` bindings and `SDL3.dll`; Homebrew `sdl3` on macOS) | Zlib | no (included anyway) | `SDL3-LICENSE.txt` |
| musl libc | 1.2.6 (Alpine 3.24 `musl-dev`, static musl builds) | MIT | yes | `musl-LICENSE.txt` |
| GCC runtime library (`libgcc.a`, `libgcc_eh.a`, crt files) | 15.2.0 (Alpine 3.24, static musl builds) | GPL-3.0-or-later WITH GCC-exception-3.1 | no (included anyway) | `libgcc-GPL-3.0.txt`, `libgcc-RUNTIME-EXCEPTION.txt` |
| Wintun | 0.14.1 (`wintun.dll`, Windows) | WireGuard LLC Prebuilt Binaries License | yes, and the DLL must not be changed | `wintun-LICENSE.txt` |
| Odin core and base libraries | `ODIN_COMMIT` of `build/Containerfile.alpine` (static musl builds); the installed Odin release elsewhere | Zlib | no (included anyway) | `Odin-LICENSE.txt` |
| Odin runtime: parts of LLVM compiler-rt (`fixuint`, `fixint`) | as Odin | Apache-2.0 WITH LLVM-exception | no, the LLVM exception covers object code (included anyway) | `Odin-compiler-rt-LICENSE.txt` |
| Code from other projects inside Odin `core` (Go and FreeBSD msun math, Cephes, BearSSL, HashMe, Unicode data, fast_float, Żmij) | as Odin | BSD-3-Clause, the msun notice, Cephes notice, BSD-1-Clause, Zlib, Unicode-3.0, BSL-1.0 | yes for BSD-3-Clause, Unicode-3.0 and the msun notice | `Odin-core-NOTICES.txt` |
| microui (Odin `vendor:microui`) | as Odin | MIT | yes | `microui-LICENSE.txt` |
| stb_image, stb_image_write, stb_truetype, stb_rect_pack (Odin `vendor:stb`) | as Odin | MIT or Unlicense (public domain) | yes for MIT | `stb-LICENSE.txt` |
| Google Sans Flex (fonts in `noirvpn-desktop`) | 5.000 | OFL-1.1 | yes | `desktop/ui/fonts/GOOGLESANSFLEX-OFL.txt` (`GoogleSansFlex-OFL.txt` in a distribution) |
| DejaVu Sans Mono (font in `noirvpn-desktop`) | 2.37 | Bitstream Vera and Arev fonts licenses | yes | `desktop/ui/fonts/DEJAVU-LICENSE.txt` (`DejaVu-LICENSE.txt` in a distribution) |

`Odin-core-NOTICES.txt` is made of the notice blocks in the Odin source files
that name another project, as they are in those files at the pinned commit.
The Odin packages are compiled into the programs; the linker can remove code
that is not used, so a program can contain less of this code than the list
shows.

## What each build contains

| Build (`build/dist.sh`) | Inside the programs | Shipped next to them | Linked from the system, not shipped |
|-------------------------|---------------------|----------------------|-------------------------------------|
| Linux, `--static` (`noirvpn`, `noirvpnctl`, `noirvpn-hook`) | Odin, musl, libgcc, OpenSSL or AWS-LC, nng | - | - |
| Linux, default (all programs; the desktop client also with `--static`) | Odin; desktop client: microui, stb, fonts | - | glibc, OpenSSL, nng, SDL3 |
| macOS | Odin, nng; desktop client: microui, stb, fonts | - | OpenSSL and SDL3 (Homebrew) |
| Windows (and the MSI) | Odin; desktop client: microui, stb, fonts | OpenSSL DLLs, `SDL3.dll`, `wintun.dll` | - |

A distribution has the license texts of all components in its row, and of
the libraries it links from the system.
