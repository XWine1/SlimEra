# SlimEra
This project provides "slim" Win32 reference implementations of select DLLs from the Xbox ERA (Exclusive Resource Application) operating system.

These implementations primarily target tool-focused use cases (such as writing programs to utilize ERA's `D3DCompiler_46.dll`, `xg_x.dll`, etc. binaries for research and analysis purposes). They do not (on their own) enable more complex ERA applications such as games to run on desktop. However, these implementations can still be used as a base to build full translation layers capable of running games (XWine1 itself derives from SlimEra).

Each library is implemented in its own `.cpp` file and requires no external dependencies aside from the Windows SDK and the included `era.h`.

# Supported Libraries
* `combase.dll`
* `EtwPlus.dll`
* `kernelx.dll`
* `pixEvt.dll`
* `toolhelpx.dll`

# Building
Run `make.cmd` from a Visual Studio developer command prompt.
