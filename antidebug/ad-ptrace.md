## Defeating anti-debug techniques: MacOS `ptrace()`

Every reverse engineer who handles software for macOS knows about ptrace(PT_DENY_ATTACH, 0, 0, 0), the infamous kernel-enforced anti-tracing DRM feature added to OS X years back (somewhere around Leopard) and most-notably used in iTunes. There are plenty of resources out there on how to bypass the common use of this feature, ranging from using a debugger to loading up a custom kernel-extension, but clever hackers have found new ways to abuse this feature to try to prevent researchers from debugging their malicious code.

I debated publishing this for a while as this information could misused, but since these techniques are being used in malware in the wild, I think it’s important to document how to defeat them.

NOTE: All of these examples assume compilation for x86_64, the default now for years. Also, all bypasses will be done in-debugger, without patching the binary itself (which may not be feasible when dealing with packed code).

### Common implementation:

To start off, let’s cover the common implementation.

```
// clang -o main main.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    printf("SUCCESS\n");
    return 0;
}
```

Now if you compile and run this code both without and with a debugger, you will see that when run under a debugger, it crashes.

```
$ ./main
PT_DENY_ATTACH
$ lldb main
(lldb) target create "main"
Current executable set to 'main' (x86_64).
(lldb) r
Process 5672 launched: '.../main' (x86_64)
Process 5672 exited with status = 45 (0x0000002d)
(lldb)
```

The message “Process # exited with status = 45 (0x0000002d)” is usually a tell-tale sign that the debug target is using PT_DENY_ATTACH.

Now defeating this trick is pretty easy, just set a breakpoint on the ptrace symbol, and change the argument value to something else, like NULL. In x86_64, the PT_DENY_ATTACH value (0x1f) is stored in the rdi register.

```
$ lldb main
(lldb) target create "main"
Current executable set to 'main' (x86_64).
(lldb) b ptrace
Breakpoint 1: where = libsystem_kernel.dylib`__ptrace, address = 0x00007fff642febac
(lldb) r
Process 5704 launched: '.../main' (x86_64)
Process 5704 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x00007fff642febac libsystem_kernel.dylib`__ptrace
libsystem_kernel.dylib`__ptrace:
->  0x7fff642febac <+0>:  xorq   %rax, %rax
    0x7fff642febaf <+3>:  leaq   0x384c9752(%rip), %r11    ; errno
    0x7fff642febb6 <+10>: movl   %eax, (%r11)
    0x7fff642febb9 <+13>: movl   $0x200001a, %eax          ; imm = 0x200001A
Target 0: (main) stopped.
(lldb) reg r rdi
     rdi = 0x000000000000001f
(lldb) reg w rdi 0
(lldb) c
Process 5704 resuming
PT_DENY_ATTACH
Process 5704 exited with status = 0 (0x00000000)
(lldb)
```

Success! Changing the register prevented the anti-tracing call from working, and the debugger ran the code to completion.

Now, with that out of the way, on to the trickier variants…

### ASM syscall

What if you run an executable, and when debugging it crashes saying “exited with status = 45 (0x0000002d)” but the binary does not use ptrace?

In our previous example, we could see the _ptrace symbol is used by the binary:

```
$ nm -um main
                 (undefined) external _printf (from libSystem)
                 (undefined) external _ptrace (from libSystem)
                 (undefined) external dyld_stub_binder (from libSystem)
```

But what if that symbol is not there or a breakpoint on ptrace never trips?

It’s possible the binary calls the underlying syscall (0x200001A) directly:

```
// clang -o main main.c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    asm(
        "pushq %rax\n"
        "pushq %rdi\n"
        "movq $0x1f, %rdi\n"
        "movq $0x200001A, %rax\n"
        "syscall\n"
        "popq %rdi\n"
        "popq %rax\n"
    );
    printf("SUCCESS\n");
    return 0;
}
```

Defeating this one is a bit more of a pain, as it requires locating the syscall in the assembly directly, but still very doable.

```
$ lldb main
(lldb) target create "main"
Current executable set to 'main' (x86_64).
(lldb) di -n main
main`main:
main[0x100000f40] <+0>:  pushq  %rbp
main[0x100000f41] <+1>:  movq   %rsp, %rbp
main[0x100000f44] <+4>:  subq   $0x20, %rsp
main[0x100000f48] <+8>:  movl   $0x0, -0x4(%rbp)
main[0x100000f4f] <+15>: movl   %edi, -0x8(%rbp)
main[0x100000f52] <+18>: movq   %rsi, -0x10(%rbp)
main[0x100000f56] <+22>: pushq  %rax
main[0x100000f57] <+23>: pushq  %rdi
main[0x100000f58] <+24>: movq   $0x1f, %rdi
main[0x100000f5f] <+31>: movq   $0x200001a, %rax          ; imm = 0x200001A
main[0x100000f66] <+38>: syscall
main[0x100000f68] <+40>: popq   %rdi
main[0x100000f69] <+41>: popq   %rax
main[0x100000f6a] <+42>: leaq   0x35(%rip), %rdi          ; "PT_DENY_ATTACH\n"
main[0x100000f71] <+49>: movb   $0x0, %al
main[0x100000f73] <+51>: callq  0x100000f86               ; symbol stub for: printf
main[0x100000f78] <+56>: xorl   %ecx, %ecx
main[0x100000f7a] <+58>: movl   %eax, -0x14(%rbp)
main[0x100000f7d] <+61>: movl   %ecx, %eax
main[0x100000f7f] <+63>: addq   $0x20, %rsp
main[0x100000f83] <+67>: popq   %rbp
main[0x100000f84] <+68>: retq

(lldb) b 0x100000f66
Breakpoint 1: address = 0x0000000100000f66
(lldb) r
Process 6690 launched: '.../main' (x86_64)
Process 6690 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x0000000100000f66 main`main + 38
main`main:
->  0x100000f66 <+38>: syscall
    0x100000f68 <+40>: popq   %rdi
    0x100000f69 <+41>: popq   %rax
    0x100000f6a <+42>: leaq   0x35(%rip), %rdi          ; "PT_DENY_ATTACH\n"
Target 0: (main) stopped.
(lldb) reg w rax 0
(lldb) c
Process 6690 resuming
PT_DENY_ATTACH
Process 6690 exited with status = 0 (0x00000000)
(lldb)
```

Success! Changing the rax register to 0 does the trick.

Alternately, a kernel extension that disables the feature in the kernel could be employed to defeat this.

### Detecting if `pt_deny_attach` is called

Now for the most-dastardly ptrace-based technique I’ve seen, detecting if ptrace(PT_DENY_ATTACH, 0, 0, 0) actually worked, and changing what the code does based on this. It’s a little-known fact that attempting to attach to a process that has called ptrace(PT_DENY_ATTACH, 0, 0, 0) results in a catch-able segmentation fault, so code that first requests no attaching, can then attempt to attach to itself to see if that worked.

Additionally as you may have guessed, doing this enables the code to detect if a PT_DENY_ATTACH disabling kernel extension was loaded, forcing us to defeat it manually, which is one of the main reason this technique is so dastardly.

```
// clang -o main main.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <unistd.h>

int deny_attach_successful = 0;

void sigsegv_handler(int sig) {
    printf("sigsegv_handler: %i\n", sig);
    deny_attach_successful = 1;
}

int main(int argc, char *argv[]) {
    pid_t pid = getpid();
    ptrace(PT_DENY_ATTACH, 0, 0, 0);
    signal(SIGSEGV, sigsegv_handler);
    ptrace(PT_ATTACH, pid, 0, 0);

    if (!deny_attach_successful) {
        printf("FAILURE\n");
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}
```

Getting past this code is actually kinda tricky. Basically, you would have to do the following:

Breakpoint ptrace.
Disable the first ptrace call.
Disable the second ptrace call.
Manually send a SIGSEGV signal after the second ptrace call.
  
Trouble is, LLDB cannot actually send a SIGSEGV signal, another reason this technique is a bit of work to beat. I’m not sure if this is an issue unique to LLDB or if other debuggers on macOS suffer from this limitation, but never-the-less we can still defeat this sneaky trick by manually calling the signal handler. So our new plan of attack is:

Breakpoint ptrace.
Breakpoint signal.
Disable the first ptrace call.
Capture the signal handler address.
Disable the second ptrace call.
Manually run the signal handler.
Allow me to show you how it’s done:

```
$ lldb main
(lldb) target create "main"
Current executable set to 'main' (x86_64).
(lldb) b ptrace
Breakpoint 1: where = libsystem_kernel.dylib`__ptrace, address = 0x000000000001cbac
(lldb) b signal
Breakpoint 2: where = libsystem_c.dylib`signal, address = 0x000000000002d788
(lldb) r
Process 11257 launched: '.../main' (x86_64)
Process 11257 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x00007fff642febac libsystem_kernel.dylib`__ptrace
libsystem_kernel.dylib`__ptrace:
->  0x7fff642febac <+0>:  xorq   %rax, %rax
    0x7fff642febaf <+3>:  leaq   0x384c9752(%rip), %r11    ; errno
    0x7fff642febb6 <+10>: movl   %eax, (%r11)
    0x7fff642febb9 <+13>: movl   $0x200001a, %eax          ; imm = 0x200001A
Target 0: (main) stopped.
(lldb) reg w rdi 0
(lldb) c
Process 11257 resuming
Process 11257 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 2.1
    frame #0: 0x00007fff6422a788 libsystem_c.dylib`signal
libsystem_c.dylib`signal:
->  0x7fff6422a788 <+0>: pushq  %rbp
    0x7fff6422a789 <+1>: movq   %rsp, %rbp
    0x7fff6422a78c <+4>: movl   $0x1, %edx
    0x7fff6422a791 <+9>: popq   %rbp
Target 0: (main) stopped.
(lldb) reg read rsi
     rsi = 0x0000000100000e60  main`sigsegv_handler
(lldb) c
Process 11257 resuming
Process 11257 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x00007fff642febac libsystem_kernel.dylib`__ptrace
libsystem_kernel.dylib`__ptrace:
->  0x7fff642febac <+0>:  xorq   %rax, %rax
    0x7fff642febaf <+3>:  leaq   0x384c9752(%rip), %r11    ; errno
    0x7fff642febb6 <+10>: movl   %eax, (%r11)
    0x7fff642febb9 <+13>: movl   $0x200001a, %eax          ; imm = 0x200001A
Target 0: (main) stopped.
(lldb) reg w rdi 0
(lldb) fin
Process 11257 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = step out
    frame #0: 0x0000000100000ee9 main`main + 89
main`main:
->  0x100000ee9 <+89>:  cmpl   $0x0, 0x140(%rip)         ; (void *)0x0000000000000000
    0x100000ef0 <+96>:  movl   %eax, -0x24(%rbp)
    0x100000ef3 <+99>:  jne    0x100000f16               ; <+134>
    0x100000ef9 <+105>: leaq   0x99(%rip), %rdi          ; "FAILURE\n"
Target 0: (main) stopped.
(lldb) expr -- typedef void (*handler_t)(int sig); handler_t $handler = (handler_t) 0x0000000100000e60; $handler(11);
sigsegv_handler: 11
(lldb) c
Process 11257 resuming
SUCCESS
Process 11257 exited with status = 0 (0x00000000)
(lldb)
```

Success! Clever, but beatable like all the rest.

Alright, now you know how to defeat all the different variants of ptrace-based anti-debugging techniques on macOS that I have discovered thus-far. If you find a new one, leave a comment letting me know! Until then never let malware stop you and hack on!

Taken from: https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/
