@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set PATH=%USERPROFILE%\.cargo\bin;%PATH%;C:\Program Files\CMake\bin;C:\Program Files\NASM
cd /d D:\Projekte\browser-clone
echo === BUILD START ===
cargo check 2>&1 > D:\Projekte\browser-clone\build.log 2>&1
echo EXIT_CODE=%ERRORLEVEL% >> D:\Projekte\browser-clone\build.log
echo === BUILD DONE ===
