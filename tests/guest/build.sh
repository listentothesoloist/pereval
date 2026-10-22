#!/bin/sh
# Builds the guest test programs as static x86-64 Linux executables, without
# needing a Linux machine: clang cross-compiles, musl's libc.a and CRT objects
# come from Rust's `x86_64-unknown-linux-musl` target, rust-lld links.
#
#   rustup target add x86_64-unknown-linux-musl
#   tests/guest/build.sh
#
# Output: tests/guest/bin/*        (committed, used by `cargo test`)
#         tests/guest/build/native-* , build/rosetta-*  (reference builds for benchmarks)
set -eu
cd "$(dirname "$0")"
SYSROOT=$(rustc --print sysroot)
CRT="$SYSROOT/lib/rustlib/x86_64-unknown-linux-musl/lib/self-contained"
LLD="$SYSROOT/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
[ -f "$CRT/libc.a" ] || { echo "missing musl target: rustup target add x86_64-unknown-linux-musl" >&2; exit 1; }
mkdir -p bin build

CFLAGS="-target x86_64-linux-musl -O2 -ffreestanding -fno-builtin -fno-stack-protector -nostdinc"
static() { # name, extra objects...
    "$LLD" -flavor gnu -static -o "bin/$1" "$CRT/crt1.o" "$CRT/crti.o" "$CRT/crtbegin.o" \
        "build/$1.o" "$CRT/libc.a" "$CRT/crtend.o" "$CRT/crtn.o"
}

for p in hello_asm ud2 segv; do
    clang -target x86_64-linux-gnu -c "src/$p.S" -o "build/$p.o"
    "$LLD" -flavor gnu -static -e _start -o "bin/$p" "build/$p.o"
done

for p in hello exit42 args bench; do
    clang $CFLAGS -fno-pic -c "src/$p.c" -o "build/$p.o"
    static "$p"
done

# The same hello world as a static PIE (self-relocating, loaded at PIE_BASE).
clang $CFLAGS -fPIE -c src/hello.c -o build/hello_pie.o
"$LLD" -flavor gnu -static -pie --no-dynamic-linker -o bin/hello_pie \
    "$CRT/rcrt1.o" "$CRT/crti.o" "$CRT/crtbeginS.o" build/hello_pie.o "$CRT/libc.a" "$CRT/crtendS.o" "$CRT/crtn.o"

# Reference builds of the benchmark: native arm64 and x86-64 macOS (runs under Rosetta 2).
clang -O2 -arch arm64 src/bench.c -o build/native-bench 2>/dev/null
clang -O2 -arch x86_64 src/bench.c -o build/rosetta-bench 2>/dev/null
echo "built: $(ls bin | tr '\n' ' ')"
