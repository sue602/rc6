
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

  public rc6_encrypt
  public _rc6_encrypt
  
_rc6_encrypt:
rc6_encrypt proc ; rc6key:dword, input:dword, output:dword
    pushad

    mov    edi, [esp+32+4]
    mov    esi, [esp+32+8]

    ; load plaintext
    lodsd
    xchg   eax, ecx
    lodsd
    xchg   eax, _B
    lodsd
    xchg   eax, _C
    lodsd
    xchg   eax, _D
    xchg   ecx, _A
    
    ; B += key->x[0];
    add    _B, [edi]
    scasd
    ; D += key->x[1];
    add    _D, [edi]
    scasd
    
    push   RC6_ROUNDS

    .repeat
      ; t = ROTL(B * (2 * B + 1), 5);
      lea    eax, [_B+_B+1]
      imul   eax, _B
      rol    eax, 5
      ; u = ROTL(D * (2 * D + 1), 5);
      lea    ecx, [_D+_D+1]
      imul   ecx, _D
      rol    ecx, 5
      ; A = ROTL(A ^ t, u) + key->x[i];
      xor    _A, eax
      rol    _A, cl
      add    _A, [edi]  ; key->x[i]
      scasd
      ; C = ROTL(C ^ u, t) + key->x[i+1];
      xor    _C, ecx
      mov    cl, al
      rol    _C, cl
      add    _C, [edi]  ; key->x[i+1]
      scasd
      ; swap
      mov    eax, _A
      mov    _A, _B
      mov    _B, _C
      mov    _C, _D
      mov    _D, eax
      ; decrease counter
      dec    dword ptr[esp]    ; _I--
    .until zero?

    pop    eax
    
    ; out[0] += key->x[42];
    add    _A, [edi]
    scasd
    ; out[2] += key->x[43];
    add    _C, [edi]
    
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
rc6_encrypt endp
    
    end