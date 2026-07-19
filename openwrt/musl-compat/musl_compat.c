/*
 * musl_compat.c — Compatibility shim for building BoringSSL on musl
 *
 * musl does not expose fopen64(); all musl functions are inherently
 * large-file-safe, so fopen64 is simply an alias for fopen.
 *
 * BoringSSL's file.c references fopen64 at link time. Without this
 * shim the musl build fails with:
 *   undefined reference to `fopen64'
 *
 * Build:
 *   musl-gcc -c -o musl_compat.o musl_compat.c
 *   ar rcs musl_compat.a musl_compat.o
 *
 * Link into the final binary via RUSTFLAGS:
 *   -C link-arg=/path/to/musl_compat.a
 */
#include <stdio.h>

FILE *fopen64(const char *path, const char *mode)
{
    return fopen(path, mode);
}
