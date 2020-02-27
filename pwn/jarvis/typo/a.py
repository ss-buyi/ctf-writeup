from pwn import *

#r = remote('', )
r = process("./typo")


r.recvuntil("")

r.interactive()
