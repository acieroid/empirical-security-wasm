
# env.c
WebAssembly's environment is empty by default.
This program accesses the PATH environment variable, which is therefore empty for WebAssembly.
In the native version it has a specific value inherited by the execution environment.

# fclose.c
`open` is used to open a file, and returns a file descriptor as an `int`.
A file opened with `open` should be closed with `close`.
However, this program closes the file with `fclose` instead, which itself expects a `FILE` datatype instead of an `int`.
Somehow, the WebAssembly version does not crash, while the native one does (as expected).

# fopen.c
`fopen` is used to open a file. It can be the case that opening a file fails.
This program then tries to close the file with `fclose`, which will crash in case the file has not been successfully opened.
In native, the program runs to completion because the file has been successfully opened
In WebAssembly, the program crashes because the WebAssembly execution environment has not, by default, the capability of opening files.

# fputs.c
The `fputs` function prints something to the console and its specification is that it retuns a positive value (>0) upon success.
This program checks that `fputs` returns 0, and if so, prints `fputs failed!`.
This check is incorrect: it should check that `fputs` returns a value `< 0`.
In the native version, it does not consider `fputs` has having failed, as indeed it returns `0`. This is the behaviour of `glibc`.
In WebAssembly, `musl` is used as the standard library however, and `musl`'s `fputs` returns 0 upon success, in adherence with the specification.

# free.c
This program performs a double `free` operation memory allocated with `malloc`.
Only one `free` operation should be allowed, so the second one should crash.
This is the behaviour in the native binary.
However, the program runs to completion in WebAssembly despite this double free.
This could come from a different implementation of `free` in musl.

# freopen.c
This program opens a file with `freopen`, and closes it twice with `fclose`.
In the native version, it runs to completion, while in WebAssembly it crashes.
This is probably because WebAssembly does not have by default the ability to open a file. (But this requires more investigation)

# incorrectarg.c
This program calls `sprintf` with `%s` as a format string, but passes an int as argument.
This is incorrect.
The native program fails, as expected.
However, the WebAssembly binary succeeds.
This is because the int argument is treated as a string pointer, of which the first element is likely `0` due to WebAssembly initializing its linear memory with zeroes. As a result, this is interpretes as passing the empty string to `sprintf`.

# invalid-free.c
This program allocates memory on the stack using `alloca`.
It then tries to free the memory by calling `free`, which should only be used for heap-allocated memory.
This crashes in native, but works in WebAssembly.
This could come from a different implementation of `free` in musl.

# null-deref.c
This program opens a file with `fopen` and then tries to close it with `fclose`, but does not check whether it was successfully opened.
In WebAssembly, the file likely fails to open, and therefore `fclose` is called on an invalid file descriptor, thereby crashing the program.
In native code, this works as the file successfully opened.

# number-of-args.c
This program calls `sprintf` with the format string `%s %s` which expects two strings as argument.
However, only one is given.
In WebAssembly, it works and treats the second string as null.
In native, it crashes as it cannot provide a value for the second string.

# pointer-not-at-start.c
This program allocates heap memory with `malloc`, and then moves the allocated pointer further in the allocated region.
This is perfectly fine so far.
However, afterwards it tries to `free` the memory by passing this incremented pointer as argument, which is invalid: `free` should be called on the pointer to the initial allocated region.
This therefore crashes in native.
This works in WebAssembly, which could come from a different implementation of `free` in musl.

# pointer-subtract.c
This program performs invalid pointer manipulation by subtracting two different pointers.
This prints a different value in WebAssembly and in native.

# stack.c
This one requires more investigation: it causes a stack smashing exception in native and not in WebAssembly.
However, it does not seem to contain an overflow.

# strncpy.c
This program allocates a string and fills it with A characters, but does not provide the null character to indicate the end of the string.
As a result, the printed string in native contains garbage.
However, in WebAssembly, due to the fact that linear memory is zero-initialized, there is - by chance - a 0 value at the end of the string, and the string is printed correctly.

# undefined-behavior.c
This programs allocates a stack pointer with `alloca`, and then performs invalid pointer manipulation by accessing as a pointer the uninitialized value in the allocated region.
It then tries to print that value as a string.
In WebAssembly, the empty string is printed, because the linear memory is zero-initialized.
In native however, another string of the program is printed because it is lying there by chance.

# uninitialized.c
This program prints an uninitialized string.
Similarly to undefined-behavior.c, in WebAssembly this uninitialized string is the empty string due to the zero-initialization of WebAssembly's linear memory.
In native, this string points - by chance - to another string in the program.

# va.c
This program seems to incorrectly use the varargs mechanism of C.
More investigation is necessary

# wchar.c
This program calls `wprintf` to print a wide-character string.
In native code, this prints the string as expected.
However, in WebAssembly, nothing is printed.
This is due to the difference in the libc being used, as `musl` and `glibc` by default do not print wide-character strings in the same way.
In the case of `musl`, it is necessary to first declare that we are printing a wide-character string, which is not done in the program.
