# minehack
Simple 64-bit Minesweeper DLL injection and hooking to extract mine position information.

See [minehack.pdf](https://github.com/charlesnathansmith/minehack/blob/main/minehack.pdf) for a step by step breakdown of how to reverse engineer it and write the hook.

Download the repository then open minehack.sln in Visual Studio and build it for Release x64.
The source files should build fine in other compilers, though loader.cpp needs to be explicitly linked with shlwapi.lib to use PathFileExists.

Start Minesweeper and let it finish loading, then run loader.exe with injected.dll in the same folder,
or you can specify DLL from command line:

>loader.exe [injected.dll]
