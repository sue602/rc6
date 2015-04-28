

; RC6 in x86 assembly
; Odzhan

.686
.model flat, C

option casemap:none
option prologue:none
option epilogue:none

include rc6.inc

.code

  public rc6_setkey
  public _rc6_setkey
  
_rc6_setkey:
rc6_setkey proc
    pushad
    mov    edx, [esp+32+ 4]    ; rc6key
    mov    esi, [esp+32+ 8]    ; key
    mov    ecx, [esp+32+12]    ; keylen
    ; should check key length?
    ; we assume it's multiple of 4
    ; something else would mess up stack
    sub    esp, ecx
    mov    edi, esp
    
    shr    ecx, 2              ; /= 4
    push   ecx                 ; save keylen/4
    ; copy key to local buffer
    rep    movsd

    mov    eax, RC6_P
    mov    esi, edx
    mov    edi, edx
    push   RC6_KR
    pop    ecx
init_key:
    stosd
    add    eax, RC6_Q
    loop   init_key
    
    xor    eax, eax    ; A=0
    xor    ebx, ebx    ; B=0
    xor    ebp, ebp    ; k=0
    xor    edi, edi    ; i=0
    xor    edx, edx    ; j=0
    
    .repeat
      ; A = key->S[i] = ROTL(key->S[i] + A+B, 3); 
      add    eax, ebx
      add    eax, [esi][RC6_KEY.x][4*edi]
      rol    eax, 3
      lea    ecx, [eax+ebx]
      mov    [esi][RC6_KEY.x][4*edi], eax
      ; B = L[j] = ROTL(L[j] + A+B, A+B);
      add    ebx, eax
      add    ebx, [esp+4*edx+4]
      rol    ebx, cl
      mov    [esp+4*edx+4], ebx
  
      ; i++
      inc    edi          
      ; i %= (RC6_ROUNDS*2)+4
      cmp    edi, RC6_KR  
      sbb    ecx, ecx
      and    edi, ecx
      
      ; j++
      inc    edx       
      ; j %= RC6_KEYLEN/4
      cmp    edx, [esp]
      sbb    ecx, ecx
      and    edx, ecx
      inc    ebp
    .until ebp == RC6_KR*3
    
    pop    ecx
    shl    ecx, 2
    add    esp, ecx
    popad
    ret
rc6_setkey endp

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