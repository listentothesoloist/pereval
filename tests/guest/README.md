# Guest test programs

`src/` — исходники, `bin/` — собранные статические ELF x86-64 для Linux (закоммичены,
чтобы `cargo test` не требовал кросс-тулчейна), `expected/` — эталонный вывод,
полученный от той же программы, собранной нативно под arm64 macOS.

Пересборка: `./build.sh` (clang + `rustup target add x86_64-unknown-linux-musl`).
Бинарники статически слинкованы с musl libc (лицензия MIT) из поставки Rust.
