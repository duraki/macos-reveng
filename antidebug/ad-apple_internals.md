`References: https://developer.apple.com/library/archive/qa/qa1361/_index.html`

## Defeating anti-debug techniques: MacOS `AmIBeingDebugged`

For a long time Apple has had a debugger-detection function on their developer site. It’s not very hard to defeat with a debugger, but since this technique is sometimes used by malware to try to prevent debugging, I decided to document how to defeat it.

NOTE: These examples assume compiling to x86_64, the current default.

An minimal program using Apple’s function goes something like this:

```
// clang -o main main.c
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>

static int AmIBeingDebugged(void) {
    int junk;
    int mib[4];
    struct kinfo_proc info;
    size_t size;

    info.kp_proc.p_flag = 0;

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);

    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

int main(int argc, char *argv[]) {
    int debugger = AmIBeingDebugged();
    if (debugger) {
        printf("FAILURE\n");
        return 1;
    }

    printf("SUCCESS\n");
    return 0;
}
```

If we run it with and without a debugger, we get 2 different results:

```
$ ./main
SUCCESS
$ echo $?
0
```

```
$ lldb main
(lldb) target create "main"
rCurrent executable set to 'main' (x86_64).
(lldb) r
Process 17532 launched: '.../main' (x86_64)
FAILURE
Process 17532 exited with status = 1 (0x00000001)
(lldb)
```

Let’s use a debugger to change that! As we can see, sysctl is populating a struct with data, and info.kp_proc.p_flag ends up with a P_TRACED flag set if the progress is being traced (debugged).

Let’s checkout the headers for these structs.

```
struct kinfo_proc
struct extern_proc
```

From that we learn that info.kp_proc.p_flag has a type of int, and we can calculate the offset, but an even easier way to calculate the offset of the value, and the value of P_TRACED is to just compile and run a little C program.

```
// clang -o sample sample.c
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/sysctl.h>

int main(int argc, char *argv[]) {
    struct kinfo_proc info;
    printf("%lu %i\n", offsetof(typeof(info), kp_proc.p_flag), P_TRACED);
    return 0;
}
```

```
$ ./testing
32 2048
```

Alright, now we have everything we need! Now it’s just a simple matter of setting a breakpoint on sysctl to read the structure address from the rdx register, finish the function call, and use an LLDB expression to XOR out the P_TRACED flag for each sysctl call.

The LLDB expression might looks something like this, substituting the address for the one read at function start.

`expr -- *((int *)(0x00007ffeefbfda98 + 32)) = *((int *)(0x00007ffeefbfda98 + 32)) ^ 2048;`

Here’s how it all works in action:

```
$ lldb main
(lldb) target create "main"
Current executable set to 'main' (x86_64).
(lldb) b sysctl
Breakpoint 1: where = libsystem_c.dylib`sysctl, address = 0x000000000002e100
(lldb) r
Process 16681 launched: '.../main' (x86_64)
Process 16681 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x00007fff6422b100 libsystem_c.dylib`sysctl
libsystem_c.dylib`sysctl:
->  0x7fff6422b100 <+0>: pushq  %rbp
    0x7fff6422b101 <+1>: movq   %rsp, %rbp
    0x7fff6422b104 <+4>: movl   (%rdi), %eax
    0x7fff6422b106 <+6>: cmpl   $0x8, %eax
Target 0: (main) stopped.
(lldb) reg read rdx
     rdx = 0x00007ffeefbfda98
(lldb) fin
Process 16681 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = step out
    frame #0: 0x00007fff644fd6b2 libxpc.dylib`_xpc_pid_is_being_debugged + 116
libxpc.dylib`_xpc_pid_is_being_debugged:
->  0x7fff644fd6b2 <+116>: movl   0x20(%rbx), %eax
    0x7fff644fd6b5 <+119>: movq   0x382e795c(%rip), %rcx    ; (void *)0x00007fff9c7b9070: __stack_chk_guard
    0x7fff644fd6bc <+126>: movq   (%rcx), %rcx
    0x7fff644fd6bf <+129>: cmpq   -0x18(%rbp), %rcx
Target 0: (main) stopped.
(lldb) expr -- *((int *)(0x00007ffeefbfda98 + 32)) = *((int *)(0x00007ffeefbfda98 + 32)) ^ 2048;
(int) $0 = 20486
(lldb) c
Process 16681 resuming
Process 16681 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x00007fff6422b100 libsystem_c.dylib`sysctl
libsystem_c.dylib`sysctl:
->  0x7fff6422b100 <+0>: pushq  %rbp
    0x7fff6422b101 <+1>: movq   %rsp, %rbp
    0x7fff6422b104 <+4>: movl   (%rdi), %eax
    0x7fff6422b106 <+6>: cmpl   $0x8, %eax
Target 0: (main) stopped.
(lldb) reg read rdx
     rdx = 0x00007ffeefbff3d8
(lldb) fin
Process 16681 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = step out
    frame #0: 0x0000000100000e46 main`AmIBeingDebugged + 134
main`AmIBeingDebugged:
->  0x100000e46 <+134>: movl   %eax, -0x2ac(%rbp)
    0x100000e4c <+140>: cmpl   $0x0, -0x2ac(%rbp)
    0x100000e53 <+147>: sete   %r10b
    0x100000e57 <+151>: xorb   $-0x1, %r10b
Target 0: (main) stopped.
(lldb) expr -- *((int *)(0x00007ffeefbff3d8 + 32)) = *((int *)(0x00007ffeefbff3d8 + 32)) ^ 2048;
(int) $1 = 20486
(lldb) c
Process 16681 resuming
0x7ffeefbff3d8 0x7ffeefbff3f8
SUCCESS
Process 16681 exited with status = 0 (0x00000000)
(lldb)
```

Success! We have fooled the debugger detection code! Obviously if you are doing this to avoid debugger detection in a piece of software, you will probably want to script this for your use-case. Fortunately, LLDB has python scripting capabilities, which I recommend you take advantage of.

Hack on!

Taken from: https://alexomara.com/blog/defeating-anti-debug-techniques-macos-amibeingdebugged/
