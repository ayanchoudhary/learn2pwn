# Buffer Overflow - Mitigations 

Three main mitigation techniques:
1. Canary/Cookies: https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/
1. PIE & ASLR: https://guyinatuxedo.github.io/5.1-mitigation_aslr_pie/index.html
1. NX: https://guyinatuxedo.github.io/6.1-mitigation_nx/index.html

Note: ASLR is kernel based whereas PIE is binary specific

Can view them when you run checksec:

```
	[*] '/root/learning/pwn/learn2pwn/bof/shellthis'
	    Arch:     amd64-64-little
	    RELRO:    Partial RELRO
	    Stack:    No canary found
	    NX:       NX enabled
	    PIE:      No PIE (0x400000)
```

Passing parameters from registers: http://6.s081.scripts.mit.edu/sp18/x86-64-architecture-guide.html

### Canary leaking

1. The most common way of achieving this is through format string vulnerability and leaking the canary.

1. For static canaries we can brute force it or we can find a way to cheese the canary during the overflow.


### ROP Chaining
> We will talk about this in detail during the ROP segment

In this example we will only use ROP chain to leak the libc base address and then return to system in the libc and execute `/bin/sh`

For leaking the libc base address we execute the chain with puts with the chain as
```
	pop rdi, ret
	push puts_got
	exec puts # got address as arg
	exec main
```
When main execs the second time we get the puts got entry address as the leak

For getting the shell, we execute the following chain
```
 	pop rdi, ret
 	push /bin/sh
 	exec system # /bin/sh as arg
```



