# Buffer Overflow

How buffer overflow occurs: https://www.coengoedegebure.com/buffer-overflow-attacks-explained/

How arguments are added to stack: https://en.wikibooks.org/wiki/X86_Disassembly/Calling_Conventions

## Challenge Discussion:

1. Run checksec to get the binary details:

	```
	pwn checksec shellthis                                                                                
	[*] '/root/learning/pwn/learn2pwn/buffer_overflow/shellthis'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
	```
1. Decompiling binary (DIY section):  
    >Important sections to note `vuln()` and `get_shell()`

1. Identifying vulnerable section for buffer overflow:

    ```c
    void vuln(void)

    {
        char name [40];
        
        printf("Please tell me your name: ");
        gets(name);
        return;
    }
    ```

    `gets()` allows us to read in more characters than the specified 40 characters in the name buffer, allowing for potential buffer overflow.

1. Debugging steps:  
    gdb cheat-sheet: breakpoint, search-pattern, info frame

    Some commands I used:
    -  b *vuln+42 --> adds a breakpoint on `nop` command of vuln 
    - search-pattern aaaa --> searches the string `aaaa` in the memory 
    - info frame --> returns the current pointer values stored on the stack   


1. The final solution file is available in sol.py file.
