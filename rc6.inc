

; RC6 in x86 assembly

ifndef RC6_H
RC6_H equ <>

RC6_ROUNDS equ 20
; set the next part yourself
; 16=128-bit, 24=192-bit, 32=256-bit
RC6_KEYLEN equ 32
RC6_KR     equ (2*(RC6_ROUNDS+2))
RC6_P      equ 0b7e15163h
RC6_Q      equ 09e3779b9h

RC6_KEY struct
  S DWORD RC6_KR dup (?)
RC6_KEY ends

endif