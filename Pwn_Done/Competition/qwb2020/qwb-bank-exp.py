from pwn import *
import hashlib

p = remote('39.101.134.52',8005)
context.log_level = 'debug'

p.recvuntil('sha256(XXX+')
data = p.recvuntil(')')
data = data[:-1]
print 'an half :'+data

p.recvuntil('== ')
flag = p.recvuntil('\n')[:-1]
print 'flag :'+flag

p.recvuntil('Give me XXX:')

l = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

i = 'a'
j = 'a'
k = 'a'
for i in l :
    for j in l:
        for k in l:
            string = i+j+k+data
            sha = hashlib.sha256()
            sha.update(string.encode('utf-8'))
            resu = sha.hexdigest()
            if resu == flag :
                print i+j+k
                p.send(i+j+k)
                break

sleep(0.5)
p.sendline('icq56f86a27c630a39b53d6f8a9ba47d')
p.interactive()
