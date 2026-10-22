# Executes an invalid opcode: the process must die with SIGILL (exit 132).
    .globl _start
_start:
    ud2
