@echo off
rem Rebuilds flash.tlb from flash.idl with MIDL. Needs Visual Studio (or the
rem Build Tools) with the C++ workload and a Windows SDK. The .tlb is checked
rem in, so a normal "cargo build" does not need MIDL.
setlocal
set "HERE=%~dp0"
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (
  echo Visual Studio with C++ tools not found.
  exit /b 1
)
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul || exit /b 1
midl /nologo /win32 /tlb "%HERE%flash.tlb" "%HERE%flash.idl" /out "%HERE%." /h nul /iid nul /proxy nul /dlldata nul
