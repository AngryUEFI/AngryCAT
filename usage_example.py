#!/usr/bin/env python3

# if needed use this to add another folder:
# export ANGRYCAT_TESTSETUP_DIRS="/path/to/setups1:/path/to/setups2"

from pprint import pprint

from angrycat.testsetup.registry import get_cpu_type, get_setup, get_all_config

mc = f"""
        nop
        nop
        // Load &result_buf
        mov rbx, [rax]
        mov r15, rax

        // Load ucode address from slot 2
        // call ASR 0x1001
        // arg 2, rsi = slot number
        mov rdi, r15
        mov rsi, 2
        mov rax, 0x1001
        call [rdi+0x58]
        mov rcx, rax

        mov rbx, [r15]

        // Apply ucode update (should crash if MR in ucode update procedure)
        mov eax, ecx
        mov rdx, rcx
        shr rdx, 32
        mov ecx, 0xc0010020
        wrmsr

        // Return to AnryUEFI
        ret
    """

ucode = [
        "--match", "all=0",
        "--nop", "all",
        "--match", f"0=1",

        # @0x1fc0
        "--insn", "q0i0=0x0",


        # @0x1fc4
        "--insn", "q4i0=mov r11, r11, 0x0",
        "--insn", "q4i1=mov r11, r11, 0x0",
        "--insn", "q4i2=mov r11, r11, 0x0",
        "--insn", "q4i3=mov r11, r11, 0x0",
        "--seq",  "4=0x03100082",

        "--hdr-revlow", f"{0x23}",
        "--hdr-autorun", "false"
    ]

cpu = get_cpu_type("AMD Ryzen 5 1600")
print(cpu)

zen1 = get_setup("Zen1")
print(zen1)
zen2 = get_setup("Zen2")
print(zen2)
zen3 = get_setup("Zen3")
print(zen3)
zen4 = get_setup("Zen4")
print(zen4)
zen5 = get_setup("Zen5")
print(zen5)

if zen1 is None or zen2 is None or zen3 is None or zen4 is None or zen5 is None:
    exit(1)

# zen1.ready_clean_setup(do_reboot=True)
zen3.connect()
zen3.start_all_cores()
zen3.wait_for_ready()
zen3.ping()
zen3.get_core_status(1)
zen3.get_ucode_revision(1)
zen3.get_all_cores_info()
# zen3.reboot()
zen3.ping()
zen3.disconnect()


zen3.ready_clean_setup(do_reboot=True)
res = zen3.run_test(ucode, mc)
zen3.reboot()
print(res)
