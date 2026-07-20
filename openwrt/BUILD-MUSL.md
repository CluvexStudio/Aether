# Building Aether for OpenWrt (musl) — Manual Build

> **Note:** CI builds this automatically via the `linux-x86_64-musl` job in `release.yml`.
> This guide is for building manually on your own machine.

OpenWrt uses **musl libc**, but the official Aether release binaries are
compiled against **glibc**. This guide explains how to build a fully
static musl binary that runs on OpenWrt routers.

## The Problem

The prebuilt `aether-linux-x86_64.tar.gz` from GitHub Releases links
against glibc:

```
/lib64/ld-linux-x86-64.so.2   (glibc dynamic linker)
  libgcc_s.so.1
  libm.so.6
  libc.so.6
```

OpenWrt uses musl (`ld-musl-x86_64.so.1`), so this binary fails with
`./aether: not found` even though the file exists — the dynamic linker
doesn't exist on the router.

## Solution: Static musl build with cross-compilation toolchain

### Prerequisites (Ubuntu/Debian host)

```bash
# Build tools
apt install cmake ninja-build

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup target add x86_64-unknown-linux-musl
```

### Install musl cross toolchain

The CI uses AmanoTeam/musl-gcc-cross, which avoids issues with
GitHub Actions runners blocking downloads from musl.cc:

```bash
# Download the musl cross toolchain
curl -fsSL https://github.com/AmanoTeam/musl-gcc-cross/releases/download/gcc-15/x86_64-unknown-linux-gnu.tar.xz -o /tmp/musl-cross.tar.xz
sudo mkdir -p /opt/musl-cross
sudo tar -C /opt/musl-cross --strip-components=1 -xJf /tmp/musl-cross.tar.xz
```

### Build Command

```bash
# Compiler configuration for musl
export CC_x86_64_unknown_linux_musl=/opt/musl-cross/bin/x86_64-unknown-linux-musl-gcc
export CXX_x86_64_unknown_linux_musl=/opt/musl-cross/bin/x86_64-unknown-linux-musl-g++
export AR_x86_64_unknown_linux_musl=/opt/musl-cross/bin/x86_64-unknown-linux-musl-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/opt/musl-cross/bin/x86_64-unknown-linux-musl-gcc

# Bindgen needs to find musl headers (for boring-sys / BoringSSL bindings)
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_musl="--target=x86_64-unknown-linux-musl --sysroot=/opt/musl-cross/x86_64-unknown-linux-musl"

# Modern musl 1.2.x time_t support (avoids type mismatches in boring)
export RUST_LIBC_UNSTABLE_MUSL_V1_2_3=1

# Build
cd aether/
cargo build --release --target x86_64-unknown-linux-musl
```

### Verify the output

```bash
file target/x86_64-unknown-linux-musl/release/aether
# Should show: ELF 64-bit LSB pie executable, x86-64, static-pie linked

ldd target/x86_64-unknown-linux-musl/release/aether
# Should show: "not a dynamic executable" or "statically linked"
```

### Automated build script

See `build-musl.sh` in this directory for a complete automated build
that handles all of the above.

## Why this approach

| Issue | Solution |
|-------|----------|
| glibc binary won't run on musl | Cross-compile with musl-gcc-cross toolchain |
| bindgen needs musl headers | `BINDGEN_EXTRA_CLANG_ARGS` points clang at musl sysroot |
| libc crate assumes old musl time_t | `RUST_LIBC_UNSTABLE_MUSL_V1_2_3=1` tells it to use modern musl |
| musl.cc blocks GitHub Actions | Use AmanoTeam/musl-gcc-cross releases instead |
| boring-sys uses bindgen (clang) | Proper sysroot avoids host glibc header leakage |
