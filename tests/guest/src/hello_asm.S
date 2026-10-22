# Smallest possible static program: raw Linux syscalls, no libc.
    .globl _start
    .text
_start:
    mov $1, %eax            # write
    mov $1, %edi            # stdout
    lea msg(%rip), %rsi
    mov $len, %edx
    syscall
    mov $60, %eax           # exit
    xor %edi, %edi
    syscall
    .section .rodata
msg:
    .ascii "Hello from raw x86-64 syscalls!\n"
    .set len, . - msg
