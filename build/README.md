# Building noirvpn

You can build noirvpn on Linux, macOS and Windows. The targets are:

| System | Programs |
|--------|----------|
| Linux (amd64, arm64) | `noirvpn`, `noirvpnctl`, `noirvpn-hook`, `noirvpn-desktop` |
| macOS (Apple silicon) | `noirvpn`, `noirvpnctl`, `noirvpn-desktop` |
| Windows 10 and 11 (x64) | `noirvpn.exe`, `noirvpnctl.exe`, `noirvpn-desktop.exe` |

## The Odin compiler

All systems need the Odin compiler, release `dev-2026-11a` or later.

1. Download the compiler archive for your system from
   <https://github.com/odin-lang/Odin/releases>.
2. Unpack it, for example to `~/odin` (Linux and macOS) or `C:\odin` (Windows).
3. Add that folder to your `PATH`, or set `ODIN` to the path of the compiler.

```sh
mkdir -p ~/odin
tar -xf odin-linux-amd64-dev-2026-11a.tar.gz -C ~/odin --strip-components=1
export PATH=$HOME/odin:$PATH
odin version
```

## Linux

There are two ways to build on Linux:

- **Native**: the programs use the system's shared libraries.
- **Static musl**: `noirvpn`, `noirvpnctl` and `noirvpn-hook`
  are built statically in a container. They can run on any
  Linux distribution, with glibc or musl.

### Native build

Install the tools and libraries.

Debian 13, Ubuntu 25.04 or later:

```sh
sudo apt install git make clang libssl-dev libnng-dev libsdl3-dev
```

Fedora 42 or later:

```sh
sudo dnf install git make clang openssl-devel nng-devel SDL3-devel
```

noirvpn needs OpenSSL 3, nng 1.x (nng 2.x does not work) and SDL3 (for the
desktop client only).

Build:

```sh
make dist      # all programs in dist/linux-amd64/
make test      # run the tests
```

To build only one program, such as `noirvpn`:

```sh
odin build cmd/noirvpn -collection:noir=. -o:speed -out:noirvpn
```

### Static musl build in a container

The build script uses `podman` with a container tha has
the compiler and required libraries.

```sh
sudo apt install podman             # or: sudo dnf install podman
build/dist.sh --static              # static programs in dist/linux-amd64/
build/musl.sh cmd/noirvpn noirvpn   # one program, in out/musl/noirvpn
```

- The first run creates the container image. This needs network access and
  takes a few minutes. Later runs reuse the image.
- `noirvpn-desktop` is a native build in both cases, because it needs the
  system graphic libraries.
- `NOIR_CRYPTO=awslc build/dist.sh --static` links AWS-LC in place of OpenSSL.

## macOS

1. Install the Xcode command line tools:

   ```sh
   xcode-select --install
   ```

2. Install [Homebrew](https://brew.sh), then the libraries and tools:

   ```sh
   brew install openssl sdl3 cmake
   ```

3. Build:

   ```sh
   make dist      # all programs in dist/darwin-arm64/
   make test      # run the tests
   ```

Homebrew has only nng 2.x; the build will download nng 1.x for the
static library in `out/macos/nng`. OpenSSL and SDL3 are linked from
Homebrew.

## Windows

Use the MSYS2 MINGW64 shell for all build commands.

1. Install the Visual Studio 2022 Build Tools with the C++ workload. Odin uses
   its linker and the Windows SDK.

   ```
   winget install Microsoft.VisualStudio.2022.BuildTools --override "--passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
   ```

2. Install MSYS2:

   ```
   winget install MSYS2.MSYS2
   ```

3. Open the MSYS2 MINGW64 shell and install the tools and OpenSSL:

   ```sh
   pacman -S --needed git make mingw-w64-x86_64-openssl
   ```

4. Download wintun from <https://www.wintun.net> and uncompress it.
   The `noirvpn` daemon needs `wintun.dll` for its tunnel.

5. Build:

   ```sh
   export ODIN=/c/odin/odin.exe
   export WINTUN_DLL=/c/wintun/bin/amd64/wintun.dll
   build/dist.sh          # all programs in dist/windows-amd64/
   ```

The build will compile the MSVC import libraries for the OpenSSL DLLs of MSYS2 and
copies the DLLs, `SDL3.dll` and `wintun.dll` alongside the programs.

### The installer (optional)

To build an MSI from `dist/windows-amd64/`, install the .NET SDK and WiX 5.0.2:

```sh
winget install Microsoft.DotNet.SDK.8
dotnet tool install --global wix --version 5.0.2
wix extension add --global WixToolset.Util.wixext/5.0.2
build/msi.sh           # dist/noirvpn-<version>-windows-amd64.msi
```

## The output

Builds output to `dist/<os>-<arch>/` with their libraries, documents and
licence texts.

