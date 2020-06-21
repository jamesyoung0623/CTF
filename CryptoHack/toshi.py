#!/usr/bin/env python3

import os
import telnetlib
import json
import codecs
import base64
import binascii
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST = "socket.cryptohack.org"
PORT = 13384

tn = telnetlib.Telnet(HOST, PORT)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)

MSG = 0
received = json_recv()
ori = int(received['y'], 16)   
print(received)
print(readline())
print(readline())
print(readline())
print(readline())
request = {"sender": "your_share", "x": 6, "y": "0x123"}
print("\n")
json_send(request)
received = json_recv()
share = int(received['privkey'], 16)   
print(received)
print(readline())
print(readline())

prime = 2**521 - 1
my_1k_wallet_privkey = "8b09cfc4696b91a1cc43372ac66ca36556a41499b495f28cc7ab193e32eadd30"
fake1 = 0x123
they = share - 5*fake1
fake2 = int(my_1k_wallet_privkey, 16) - they

while fake2%5 != 0:
    fake2 = fake2 + prime

request['y'] = hex(fake2//5)
json_send(request)
print(readline())
print(readline())
print(readline())
json_send({"privkey": hex((they+ori*5)%prime)})
print(readline())
