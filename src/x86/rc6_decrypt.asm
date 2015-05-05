

.686
.model flat, C

option casemap:none
option prologue:none
option epilogue:none

include rc6.inc

.code

_A equ esi
_B equ ebx
_C equ edx
_D equ ebp

  public rc6_decrypt
  public _rc6_decrypt
  
_rc6_decrypt:
rc6_decrypt proc ; rc6key:dword, input:dword, output:dword
    pushad

    mov    edi, [esp+32+4]
    mov    esi, [esp+32+8]
    
    ; load ciphertext
    lodsd
    xchg   eax, ecx
    lodsd
    xchg   eax, _B
    lodsd
    xchg   eax, _C
    lodsd
    xchg   eax, _D
    xchg   ecx, _A
    
    ; move to end of key
    add    edi, (RC6_KR*4)
    ; load backwards
    std
    
    ; C -= key->x[43];
    scasd
    sub    _C, [edi]
    ; A -= key->x[42];
    scasd
    sub    _A, [edi]
    
    push   RC6_ROUNDS
    
    .repeat
      ; t = ROTL(A * (2 * A + 1), 5);
      lea    ecx, [_A+_A+1]
      imul   ecx, _A
      rol    ecx, 5
      ; u = ROTL(C * (2 * C + 1), 5);
      lea    eax, [_C+_C+1]
      imul   eax, _C
      rol    eax, 5
      ; B = ROTR(B - key->x[i + 1], t) ^ u;
      scasd
      sub    _B, [edi]
      ror    _B, cl   ; t
      xor    _B, eax  ; u
      ; D = ROTR(D - key->x[i], u) ^ t;
      xchg   eax, ecx ; swap u and t
      scasd
      sub    _D, [edi]
      ror    _D, cl   ; u
      xor    _D, eax  ; t
      ; swap
      mov    eax, _D
      mov    _D, _C
      mov    _C, _B
      mov    _B, _A
      mov    _A, eax 
      ; decrease counter
      dec    dword ptr[esp]    ; _I--
    .until zero?

    pop    eax
    
    ; out[3] -= key->x[1];
    scasd
    sub    _D, [edi]
    ; out[1] -= key->x[0];
    scasd
    sub    _B, [edi]
    
    ; clear direction and move forward
    cld
    ; save ciphertext
    mov    edi, [esp+32+12]
    mov    eax, _A
    stosd
    xchg   eax, _B
    stosd
    xchg   eax, _C
    stosd
    xchg   eax, _D
    stosd
    popad
    ret
rc6_decrypt endp

    end
    