# pereval

«Перевал» — стек для запуска x86-64 программ на Mac с Apple Silicon: трансляция процессора,
слой системы, Windows API, Direct3D 11 → Metal. Конечная цель — игры на
Unreal Engine 5. Устройство — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Состояние: этап 1 завершён** — интерпретатор x86-64 запускает статические
программы для Linux x86-64. Итоги, замеры и решение «свой JIT или FEX» —
в [docs/decisions/stage1.md](docs/decisions/stage1.md).

```sh
cargo build --release
./target/release/pereval tests/guest/bin/hello
./target/release/pereval --stats tests/guest/bin/bench 8   # скорость интерпретатора
./target/release/pereval --strace tests/guest/bin/args a b # трассировка системных вызовов
cargo test                                              # всё, включая сверку с Rosetta 2
```

| Crate | Слой |
|---|---|
| `guest-mem` | адресное пространство гостя |
| `x86-cpu` | 1 — декодер, интерпретатор, (JIT) |
| `linux-abi` | 2 — ELF, системные вызовы Linux на macOS |
| `pereval` | командная строка |

Гостевые программы для тестов лежат в `tests/guest` (исходники + собранные ELF);
пересобрать их можно без Linux-машины скриптом `tests/guest/build.sh`.
Данные сверки с Rosetta 2 перегенерирует `tools/oracle/regen.sh`.

Ограничение проекта: никаких изменений в файлах игр и античитов, никакого
реверс-инжиниринга и обхода защиты.
