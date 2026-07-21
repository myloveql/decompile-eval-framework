.text
.globl binoracle_call
.type binoracle_call,@function
binoracle_call:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    subq $8, %rsp
    movq %rdi, %rbx
    movq 64(%rbx), %r11
    movq 0(%rbx), %rdi
    movq 8(%rbx), %rsi
    movq 16(%rbx), %rdx
    movq 24(%rbx), %rcx
    movq 32(%rbx), %r8
    movq 40(%rbx), %r9
    call *%r11
    movq %rax, 48(%rbx)
    movq %rdx, 56(%rbx)
    addq $8, %rsp
    popq %rbx
    popq %rbp
    ret
.size binoracle_call, .-binoracle_call
.section .note.GNU-stack,"",@progbits
