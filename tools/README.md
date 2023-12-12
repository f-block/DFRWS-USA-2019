# Code Injection Tools

This folder contains the source code and binaries for all Code Injection tools.

* atom.bombing: AtomBombing PoC by [Liberman](https://github.com/BreakingMalwareResearch/atom-bombing/tree/629ff1d79bd032cf4c3fc173751a979cb4821d7f).
* dep: Stores and executes shellcode on the stack.
* gargoyle: The Gargoyle hiding technique PoC by [Lospinoso](https://github.com/JLospinoso/gargoyle/tree/38416e4cbce28cd0f1884801393da2d2ccd6726e), including a modified version using the protection-change trick.
* loadExe: Based on the original Process Hollowing PoC by [Keong](https://web.archive.org/web/20070808231220/http://www.security.org.sg/code/loadexe.html) and a modified version using the protection-change trick.
* process.hollowing: The orignal Process Hollowing executables by [Leitch](https://github.com/m0n0ph1/Process-Hollowing/tree/fd6e6e8dcacd0ec81e3b75e86418c9de1352e897) and a modified version using the protection-change trick.
* remote.shellcode: Implements the Remote Shellcode Injection.
* reflective.dll.injection: The Reflective DLL Injection PoC by [Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection/tree/178ba2a6a9feee0a9d9757dcaa65168ced588c12) and a [modified version](https://github.com/f-block/ReflectiveDLLInjection) using the protection-change trick.
* self.modifying: This executable modifies its own executable code, serving as a test scenario for hashtest and paged out pages.

Other tools:

* [MemTest](http://www.opening-windows.com/wmip/testcode/download/license.html) - Also, check out the according great book "What Makes It Page?: The Windows 7 (x64) Virtual Memory Manager Paperback" by Enrico Martignetti (available on Amazon).


## Build instructions

Following the MinGW build instructions for `dep`, `self.modifying` and `remote.shellcode`:

```
i686-w64-mingw32-gcc -Wl,--no-nxcompat DEP.c -o DEP.exe

x86_64-w64-mingw32-gcc selfmodify.cpp -o selfmodify.x64.exe
i686-w64-mingw32-gcc selfmodify.cpp -o selfmodify.x86.exe

i686-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ RS.cpp -o rs.x86.exe
i686-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ RS_m.cpp -o rs_m.x86.exe
x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ RS.cpp -o rs.x64.exe
x86_64-w64-mingw32-g++ -static -static-libgcc -static-libstdc++ RS_m.cpp -o rs_m.x64.exe
```


## Usage

### DEP

Simply start the `DEP.exe` executable and press enter once: A popup should show up.
Thanks to DEP exceptions for 32 bit binaries, we can execute shellcode in RO/RW memory.
The result of attempting this is a protection change of the corresponding page, performed by the OS for us (so no virtualprotect necessary).
The modified executable page is located within the `DEP.exe` mapped in memory.

### self.modifying

Simply start the `selfmodify.x64.exe` or `selfmodify.x86.exe` executable.
The application will tell you what it's doing in the background, just press enter to proceed.
The important point is at the message: "Before running funca again"
When pressing enter here, the output of the `funca` function changes and `i` has now the value 42, which results from a direct modification of the `funca` function in memory.


### remote.shellcode

Start a target process (either 32 or 64 bit; e.g. notepad) and inject the shellcode via:

```
rs_m.x64.exe PID

rs_m.x86.exe PID
```

A popup should show up in the context of the target process.
