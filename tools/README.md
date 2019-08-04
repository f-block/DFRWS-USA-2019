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
