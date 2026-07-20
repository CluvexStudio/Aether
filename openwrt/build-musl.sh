#!/bin/bash
# build-musl.sh — Build Aether as a static musl binary for OpenWrt
# Usage: Run from the Aether source root (where aether/ and quiche/ are siblings)
set -e

export PATH="${HOME}/.cargo/bin:${PATH}"

# --- Check prerequisites ---
for cmd in cmake ninja-build; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: $cmd not found. Install: apt install cmake ninja-build" >&2
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

# --- Install musl cross toolchain (if not already present) ---
MUSL_CROSS=/opt/musl-cross
if [ ! -d "$MUSL_CROSS" ]; then
    echo "=== Installing musl cross toolchain ==="
    curl -fsSL https://github.com/AmanoTeam/musl-gcc-cross/releases/download/gcc-15/x86_64-unknown-linux-gnu.tar.xz -o /tmp/musl-cross.tar.xz
    sudo mkdir -p "$MUSL_CROSS"
    sudo tar -C "$MUSL_CROSS" --strip-components=1 -xJf /tmp/musl-cross.tar.xz
    rm -f /tmp/musl-cross.tar.xz
fi

# --- Set cross-compilation environment ---
export CC_x86_64_unknown_linux_musl="$MUSL_CROSS/bin/x86_64-unknown-linux-musl-gcc"
export CXX_x86_64_unknown_linux_musl="$MUSL_CROSS/bin/x86_64-unknown-linux-musl-g++"
export AR_x86_64_unknown_linux_musl="$MUSL_CROSS/bin/x86_64-unknown-linux-musl-ar"
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$MUSL_CROSS/bin/x86_64-unknown-linux-musl-gcc"
export BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_linux_musl="--target=x86_64-unknown-linux-musl --sysroot=$MUSL_CROSS/x86_64-unknown-linux-musl"
export RUST_LIBC_UNSTABLE_MUSL_V1_2_3=1

echo "=== Building Aether (x86_64-unknown-linux-musl, release) ==="
cd aether/
cargo build --release --target x86_64-unknown-linux-musl

# --- Output ---
OUT="target/x86_64-unknown-linux-musl/release/aether"
ls -lh "$OUT"
file "$OUT"

echo "=== Done ==="
echo "Binary: $OUT"
echo "Copy to router: scp $OUT root@<router-ip>:/usr/bin/aether"
