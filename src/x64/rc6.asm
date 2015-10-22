

; RC6 in x64 assembly
; Odzhan

ifdef __JWASM__
.x64
.model flat
endif

option casemap:none
option prologue:none
option epilogue:none

include rc6.inc

.code

  public rc6_setkey
  public _rc6_setkey
  
_rc6_setkey:
rc6_setkey proc
    push   rbx
    push   rsi
    push   rbp
    push   rdi
    
    ; rsi=key bytes
    push   rdx
    pop    rsi
    ; rdx=rc6 key
    push   rcx
    pop    rdx
    ; rcx=key len
    push   r8
    pop    rcx
    ; should check key length?
    ; we assume it's multiple of 4
    ; something else would mess up stack
    sub    rsp, rcx
    mov    rdi, rsp
    
    shr    ecx, 2              ; /= 4
    push   rcx                 ; save keylen/4
    ; copy key to local buffer
    rep    movsd

    mov    eax, RC6_P
    push   rdx
    pop    rsi
    push   rdx
    pop    rdi
    push   RC6_KR
    pop    rcx
init_key:
    stosd
    add    eax, RC6_Q
    loop   init_key
    
    xor    eax, eax    ; A=0
    xor    ebx, ebx    ; B=0
    xor    ebp, ebp    ; k=0
    xor    edi, edi    ; i=0
    xor    edx, edx    ; j=0
    
setkey_loop:
    ; A = key->S[i] = ROTL(key->S[i] + A+B, 3); 
    add    eax, ebx
    add    eax, [rsi][RC6_KEY.x][4*rdi]
    rol    eax, 3
    lea    ecx, [eax+ebx]
    mov    [rsi][RC6_KEY.x][4*rdi], eax
    ; B = L[j] = ROTL(L[j] + A+B, A+B);
    add    ebx, eax
    add    ebx, [rsp+4*rdx+4]
    rol    ebx, cl
    mov    [rsp+4*rdx+4], ebx

    ; i++
    inc    edi          
    ; i %= (RC6_ROUNDS*2)+4
    cmp    edi, RC6_KR  
    sbb    ecx, ecx
    and    edi, ecx
    
    ; j++
    inc    edx       
    ; j %= RC6_KEYLEN/4
    cmp    edx, [rsp]
    sbb    ecx, ecx
    and    edx, ecx
    inc    ebp
    cmp    ebp, RC6_KR*3
    jne    setkey_loop
      
    pop    rcx
    shl    ecx, 2
    add    rsp, rcx
    
    pop    rdi
    pop    rbp
    pop    rsi
    pop    rbx
    
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
    push   rbx
    push   rsi
    push   rbp
    push   rdi
    
    ; rdi=key
    push   rcx
    pop    rdi
    ; rsi=input
    push   rdx
    pop    rsi
    
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
    add    _B, [rdi]
    scasd
    ; D += key->x[1];
    add    _D, [rdi]
    scasd
    
    push   RC6_ROUNDS

encrypt_loop:
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
    add    _A, [rdi]  ; key->x[i]
    scasd
    ; C = ROTL(C ^ u, t) + key->x[i+1];
    xor    _C, ecx
    mov    cl, al
    rol    _C, cl
    add    _C, [rdi]  ; key->x[i+1]
    scasd
    ; swap
    mov    eax, _A
    mov    _A, _B
    mov    _B, _C
    mov    _C, _D
    mov    _D, eax
    ; decrease counter
    dec    dword ptr[rsp]    ; _I--
    jne    encrypt_loop

    pop    rax
    
    ; out[0] += key->x[42];
    add    _A, [rdi]
    scasd
    ; out[2] += key->x[43];
    add    _C, [rdi]
    
    ; save ciphertext
    push   r8
    pop    rdi
    mov    eax, _A
    stosd
    xchg   eax, _B
    stosd
    xchg   eax, _C
    stosd
    xchg   eax, _D
    stosd
    
    pop    rdi
    pop    rbp
    pop    rsi
    pop    rbx
    ret
rc6_encrypt endp

  public rc6_decrypt
  public _rc6_decrypt
  
_rc6_decrypt:
rc6_decrypt proc ; rc6key:dword, input:dword, output:dword
    push   rbx
    push   rsi
    push   rbp
    push   rdi
    
    ; rdi=key
    push   rcx
    pop    rdi
    ; rsi=input
    push   rdx
    pop    rsi
    
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
    add    rdi, (RC6_KR*4)
    ; load backwards
    std
    
    ; C -= key->x[43];
    scasd
    sub    _C, [rdi]
    ; A -= key->x[42];
    scasd
    sub    _A, [rdi]
    
    push   RC6_ROUNDS
    
decrypt_loop:
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
    sub    _B, [rdi]
    ror    _B, cl   ; t
    xor    _B, eax  ; u
    ; D = ROTR(D - key->x[i], u) ^ t;
    xchg   eax, ecx ; swap u and t
    scasd
    sub    _D, [rdi]
    ror    _D, cl   ; u
    xor    _D, eax  ; t
    ; swap
    mov    eax, _D
    mov    _D, _C
    mov    _C, _B
    mov    _B, _A
    mov    _A, eax 
    ; decrease counter
    dec    dword ptr[rsp]    ; _I--
    jne    decrypt_loop

    pop    rax
    
    ; out[3] -= key->x[1];
    scasd
    sub    _D, [rdi]
    ; out[1] -= key->x[0];
    scasd
    sub    _B, [rdi]
    
    ; clear direction and move forward
    cld
    ; save plaintext
    push   r8
    pop    rdi
    mov    eax, _A
    stosd
    xchg   eax, _B
    stosd
    xchg   eax, _C
    stosd
    xchg   eax, _D
    stosd
    
    pop    rdi
    pop    rbp
    pop    rsi
    pop    rbx
    ret
rc6_decrypt endp

    end