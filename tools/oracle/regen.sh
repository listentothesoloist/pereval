#!/bin/sh
# Regenerate the Rosetta 2 oracle data used by crates/x86-cpu/tests/oracle.rs.
set -eu
cd "$(dirname "$0")"
clang -O1 -arch x86_64 oracle.c -o oracle
arch -x86_64 ./oracle "${1:-48}" > ../../crates/x86-cpu/tests/data/oracle.txt
wc -l ../../crates/x86-cpu/tests/data/oracle.txt
