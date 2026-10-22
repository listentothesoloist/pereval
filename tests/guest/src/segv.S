# Writes to address 0: the process must die with SIGSEGV (exit 139).
    .globl _start
_start:
    movl $1, 0
    mov $60, %eax
    syscall
