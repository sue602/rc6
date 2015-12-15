@echo off
yasm -fwin32 r6.asm -o r6.obj
yasm -DBIN -fbin r6.asm -o r6.bin
cl /nologo /O2 /Os /GS- rc6_test.c rc6.c
move rc6_test.exe c_test.exe
cl /nologo /DUSE_ASM /O2 /Os /GS- rc6_test.c r6.obj
move rc6_test.exe asm_test.exe
del *.obj *.err