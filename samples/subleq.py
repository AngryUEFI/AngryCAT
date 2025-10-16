#!/usr/bin/env python3

import struct
import sys

from angrycat.testsetup.registry import get_setup
from angrycat.util import hexdump

mc_subleq = f"""
        // backup core context to r15
        mov r15, rax
        mov rdi, [rax]

        mov rbp, 0x200

    loop_start:

        // write subleq "instructions" to start of result buffer
        mov rcx, 24
        mov [rdi + 0x00], rcx
        mov rcx, 8
        mov [rdi + 0x08], rcx
        mov rcx, 0
        mov [rdi + 0x10], rcx

        mov rcx, 16
        mov [rdi + 0x18], rcx
        mov rcx, 8
        mov [rdi + 0x20], rcx
        mov rcx, 0
        mov [rdi + 0x28], rcx

        mov rcx, 0x20
        mov [rdi + 0x30], rcx
        mov rcx, 0x28
        mov [rdi + 0x38], rcx
        mov rcx, 0xffffffffffffffff
        mov [rdi + 0x40], rcx

        // initialize subleq data memory at result buffer + 512
        mov rcx, 0
        mov [rdi + 512 + 0x00], rcx
        mov rcx, 40
        mov [rdi + 512 + 0x08], rcx
        mov rcx, 5
        mov [rdi + 512 + 0x10], rcx
        mov rcx, 10
        mov [rdi + 512 + 0x18], rcx
        // set to 0 to not abort execution and lock the core
        mov rcx, 8
        mov [rdi + 512 + 0x20], rcx
        mov rcx, 8
        mov [rdi + 512 + 0x28], rcx

        // enter subleq
        shld rcx, rcx, 4

        dec rbp
        jne loop_start

        // Return to AnryUEFI
        ret
    """

ucode = f"""
.date 0x10102025
.revision 0x080011ff
.format 0x8004
.cpuid 0x00008082

; shld rcx, rcx, 4
.match_reg 0, 0x420

; Get the result buffer address from CoreContext (passed in rax)
mov rbx, ls:[rax+reg0+0] ; Dereference CoreContext->ResultBuffer into rbx, rbx now holds the address

mov reg9, rbx           ; Initialise program counter to start of result buffer, where program will exist
add reg10, reg9, 512    ; reg10 = [rax + 512] , start of result data buffer

mov r8, reg0           ; Clear op_a/mem_a
mov r9, reg0           ; Clear mem_b
mov r10, reg0           ; Clear op_b
mov r11, reg0           ; Clear jmp_c
mov r12, reg0           ; Clear halt check register
sub r12, reg0, 1        ; r12 = -1

;jmp END_SUBLEQ_LOOP

; Start of subleq loop
SUBLEQ_LOOP:
    ; Load operands from memory into registers
    mov r8, ls:[reg9+reg0+0]   ; Load op_a
    mov r10, ls:[reg9+reg0+8]   ; Load op_b
    mov r8, ls:[reg10+r8]    ; Load mem_a
    mov r9, ls:[reg10+r10]    ; Load mem_b

    mov r11, ls:[reg9+reg0+16]  ; Load jmp_c

    ; Perform subleq operation
    sub.CZ r9, r9, r8  ; mem_b = mem_b - mem_a

    ; Store the result back to memory
    mov ls:[reg10+r10], r9 ; Store updated mem_b back to memory

    ; Check if mem_b <= 0
    jbe.cz  BRANCH_TAKEN      ; If mem_b <= 0, jump to BRANCH_TAKEN

    ; If mem_b > 0, increment program counter to next instruction
    add reg9, reg9, 24     ; Move to next instruction (3 * 8 bytes)
    ; Repeat the loop
    .sw_branch SUBLEQ_LOOP

BRANCH_TAKEN:
    ; subleq branch is taken

    ; Check for halt condition
    ; halt if branch is taken and jmp_c is -1
    sub.Z reg0, r11, r12
    ; If jmp_c == -1, halt the program
    je.z END_SUBLEQ_LOOP

    ; set data pointer to jmp_c
    ; r11 (jmp_c) is the slot offset
    ; add slot offset to base address
    add reg9, rbx, r11

    ; next loop iteration
    .sw_branch SUBLEQ_LOOP

END_SUBLEQ_LOOP:
    ; Cleanup and exit
    mov r8, reg0           ; Clear op_a/mem_a
    mov r9, reg0           ; Clear mem_b
    mov r10, reg0           ; Clear op_b
    mov r11, reg0           ; Clear jmp_c
    mov r12, reg0           ; Clear halt check register
    mov.q r12, 1
    mov ls:[reg10], r12 ; Return 1 in result buffer to indicate success
    mov r12, reg0           ; Clear halt check register
    .sw_complete

"""

zen1 = get_setup("Zen1")
if zen1 is None:
    exit(1)

if sys.argv[2] == "reboot":
    zen1.ready_clean_setup(do_reboot=True)
else:
    zen1.connect()

res = zen1.run_test(ucode, mc_subleq, mark_core_dead=False, core_number=int(sys.argv[1]))
print(res)
if res.core_faulted:
    print(zen1.get_core_status(int(sys.argv[1])))
result = struct.unpack("<Q", res.result_buffer[0x200:0x208])[0]
if result != 1:
    print(f"Expected result 1, got 0x{result:X}")
hexdump(res.result_buffer)
