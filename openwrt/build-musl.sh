#!/bin/bash
# build-musl.sh — Build Aether as a static musl binary for OpenWrt
# Usage: Run from the Aether source root (where aether/ and quiche/ are siblings)
set -e

export PATH="${HOME}/.cargo/bin:${PATH}"

# --- Check prerequisites ---
for cmd in musl-gcc clang llvm-ar; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: $cmd not found. Install: apt install cmake clang llvm musl-tools" >&2
        exit 1
    }
done
command -v rustup >/dev/null 2>&1 || {
    echo "ERROR: rustup not found. Install: https://rustup.rs" >&2
    exit 1
}

echo "=== Rust: $(rustc --version) ==="

# --- Ensure musl target is installed ---
rustup target add x86_64-unknown-linux-musl 2>/dev/null || true

# --- Build the fopen64 compatibility shim ---
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

cat > "$BUILD_DIR/musl_compat.c" << 'SHIM'
/* musl doesn't expose fopen64 — it's always large-file-safe.
   Provide a symbol so BoringSSL (used by quiche) can link. */
#include <stdio.h>
FILE *fopen64(const char *path, const char *mode) {
    return fopen(path, mode);
}
SHIM

echo "=== Building musl fopen64 shim ==="
musl-gcc -c -o "$BUILD_DIR/musl_compat.o" "$BUILD_DIR/musl_compat.c"
ar rcs "$BUILD_DIR/musl_compat.a" "$BUILD_DIR/musl_compat.o"

# --- Set cross-compilation environment ---
export CC_x86_64_unknown_linux_musl=musl-gcc
export CXX_x86_64_unknown_linux_musl=clang++
export AR_x86_64_unknown_linux_musl=llvm-ar
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=clang
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-arg=$BUILD_DIR/musl_compat.a"

echo "=== Building Aether (x86_64-unknown-linux-musl, release) ==="
cargo build --release --target x86_64-unknown-linux-musl

# --- Output ---
OUT="target/x86_64-unknown-linux-musl/release/aether"
ls -lh "$OUT"
file "$OUT"

echo "=== Done ==="
echo "Binary: $OUT"
echo "Copy to router: scp $OUT root@<router-ip>:/usr/bin/aether"
