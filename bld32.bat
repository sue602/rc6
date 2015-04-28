@echo off
ml /coff /Cp /c /nologo src\x86\rc6.asm
cl /nologo /O1 rc6_test.c rc6.obj
del *.obj *.err
move rc6_test.exe bin\x86\