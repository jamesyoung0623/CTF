# My First CTF
This is a write up of the contest [My First CTF](https://mfctf.ais3.org/challenges)

## MISC
### Piquero
I can’t see the flag. Where is it?
<img src="https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/Piquero.jpg" alt="Piquero" style="zoom:15%;" />

**SOL:** This is a jpg of braille!

### Karuego
Students who fail to summon will be dropped out.
<img src="https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/Karuego.png" alt="Piquero" style="zoom:15%;" />
**SOL:** a zip file is hidden inside of Karuego.png. So we need to extract the zip from the image.
```bash
xxd Karuefo.png | grep IEND 
```
we will see ``001f6d20: f940 72ae 0000 0000 4945 4e44 ae42 6082  .@r.....IEND.B`.``.
It meens that the terminate byte of the png is 001f6d20.
Now check for the 001f6d30 byte
```bash
xxd Karuefo.png | grep 001f6d30 
```
The result was `001f6d30: 504b 0304 0a00 0000 0000 408a bd50 0000  PK........@..P..` and we can see there's `PK` in the line. `PK` are the initials of Phil Katz, the inventor of the zip file, and indicate that a zip file starts at that point.

As *0x001f6d30 = 2059568*
```bash
dd if=Karuego.png bs=1 skip=2059568 of=foo.zip
```
The zip file was locked, so I use `fcrackzip` and common password in rockyou.txt to brute search for the correct password.
```bash
fcrackzip -D -p rockyou.txt -u foo.zip
```
And the password of the zip file was *lafire*. Flag is in Demon.png

***
## Crypto
### T-Rex
Tyrannosaurus-rex is an nihilist. [prob](https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/prob)
**SOL:** Like substitution cipher(?)
I wrote an execution file[T-Rex](https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/T-Rex) to quickly solve this problem. Usage as
```bash
./T-rex <input_file>
```
The source code of T-Rex was [trex.cpp](https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/trex.cpp)

### KcufsJ
Brontosaurus peek at last year’s problems with a long neck and picked up "KcufsJ". [KcufsJ](https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/KcufsJ)
**SOL:** *KcufsJ* is the inverse of *Jsfuck*, an esoteric subset of JavaScript. So inverse the context provided, and execute them in chrome console.

### Blowfish
Don’t poke the puffer, it is poisonous. [user.pickle](https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/user.pickle) [prob.py](https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/server.py)
```bash 
nc 60.250.197.227 12001
```
**SOL:** The `TOKEN` was encrypted with CTR mode, and we knew the plaintext(user.pickle)!
<img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/4d/CTR_encryption_2.svg/902px-CTR_encryption_2.svg.png" alt="CTR" style="zoom:80%;" />
So by XORing the given token and the plaintext, we now can fake a new TOKEN and get the flag!
> See [blowfish.py](https://github.com/jamesyoung0623/CTF/blob/master/myFirstCTF2020/blowfish.py)
