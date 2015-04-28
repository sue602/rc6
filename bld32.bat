@echo off
ml /coff /Cp /c /nologo src\x86\rc6.asm
lib /nologo /out:lib\x86\rc6.lib rc6.obj
cl /nologo /O1 rc6_test.c lib\x86\rc6.lib
move rc6_test.exe bin\x86\
del *.obj *.err