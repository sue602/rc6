@echo off
ml64 /Cp /c /nologo src\x64\rc6.asm
lib /nologo /out:lib\x64\rc6.lib rc6.obj
cl /nologo /O1 rc6_test.c lib\x64\rc6.lib
move rc6_test.exe bin\x64\
del *.obj *.err