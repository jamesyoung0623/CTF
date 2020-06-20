import os
import pickle
import random
from base64 import b64decode, b64encode
from Crypto.Util import Counter
from Crypto.Cipher import Blowfish

p = open('user.pickle','rb').read()

#print("Original text: ", b64encode(p).decode(), end="\n\n")

TOKEN    = input("Their TOKEN : ")

key = [ord(a) ^ ord(b) for a,b in zip(TOKEN, b64encode(p).decode())]

print()

objs = pickle.loads(p)
for obj in objs :
    print("username: ", obj['name'])
    print("password: ", obj['password'])
    obj['admin'] = True
    break

s = b64encode(pickle.dumps(objs)).decode()

ntoken = ''.join(chr(ord(a) ^ b) for a,b in zip(s, key))

print("New TOKEN: ", ntoken)
