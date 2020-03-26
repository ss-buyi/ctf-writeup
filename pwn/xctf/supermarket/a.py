from pwn import *
context.log_level = 'debug'

#r = remote('', )
r = process('./supermarket')
elf = ELF('./supermarket')
libc = ELF('./libc.so.6')













r.interactive()
