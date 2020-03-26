from ctypes import *
libc = cdll.LoadLibrary("./libc.so.6")
libc.srand(0)




for i in range(1, 50):
    print (libc.rand() % 6 + 1)
