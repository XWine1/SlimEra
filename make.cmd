@echo off
set MAKE=cl /O2 /std:c++20 /I..
set MAKEDLL=%MAKE% /LD
if not exist bin mkdir bin
pushd bin
%MAKEDLL% ..\combase.cpp
%MAKEDLL% ..\kernelx.cpp 
%MAKEDLL% ..\toolhelpx.cpp
%MAKEDLL% ..\EtwPlus.cpp
%MAKEDLL% ..\pixEvt.cpp
popd
