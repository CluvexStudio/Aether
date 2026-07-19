# Building Aether for OpenWrt (musl)

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

Additionally, BoringSSL (used by quiche) references `fopen64`, which is
a glibc extension. musl doesn't provide this symbol because all musl
functions are inherently large-file-safe.

## Solution: Static musl build with a compatibility shim

### Prerequisites (Ubuntu/Debian host)

```bash
# Build tools
apt install cmake clang llvm musl-tools build-essential pkg-config

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup target add x86_64-unknown-linux-musl
```

### The fopen64 Compatibility Shim

BoringSSL's `file.c` calls `fopen64()`, which doesn't exist in musl.
Create a tiny shim that provides the symbol:

**`openwrt/musl-compat/musl_compat.c`**:
```c
/* musl doesn't expose fopen64 — it's always large-file-safe.
   Provide a symbol so BoringSSL can link. */
#include <stdio.h>
FILE *fopen64(const char *path, const char *mode) {
    return fopen(path, mode);
}
```

Build it into a static archive:
```bash
musl-gcc -c -o musl_compat.o musl_compat.c
ar rcs musl_compat.a musl_compat.o
```

### Build Command

```bash
# Compiler configuration for musl
export CC_x86_64_unknown_linux_musl=musl-gcc
export CXX_x86_64_unknown_linux_musl=clang++
export AR_x86_64_unknown_linux_musl=llvm-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang

# Link the fopen64 compat shim into the final binary
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-arg=/path/to/musl_compat.a"

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

See `openwrt/build-musl.sh` for a complete automated build.

## Why this approach

| Issue | Solution |
|-------|----------|
| glibc binary won't run on musl | Cross-compile with musl-gcc + musl target |
| `fopen64` undefined in musl | Small C shim compiled into the binary |
| BoringSSL cmake needs `x86_64-linux-musl-g++` | Symlink `clang` as `x86_64-linux-musl-g++` |
| `ring` crate needs `llvm-ar` | Install `llvm` package on build host |
| Cross-compilation needs proper linker | Use `clang` as the linker (handles musl natively) |
