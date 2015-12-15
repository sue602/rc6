

; RC6 in x86 assembly
; 293 bytes
; Odzhan

    bits 32
  
%define RC6_ROUNDS 20
%define RC6_KR     (2*(RC6_ROUNDS+2))
%define RC6_P      0b7e15163h
%define RC6_Q      09e3779b9h

struc RC6_KEY
  x resd RC6_KR
endstruc

  %ifndef BIN
    global _rc6_setkeyx
    global _rc6_cryptx
  %endif
  
_rc6_setkeyx:
rc6_setkey:
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
    
sk_l1:
    ; A = key->S[i] = ROTL(key->S[i] + A+B, 3); 
    add    eax, ebx
    add    eax, [esi+4*edi]
    rol    eax, 3
    lea    ecx, [eax+ebx]
    mov    [esi+4*edi], eax
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
    cmp    ebp, RC6_KR*3
    jnz    sk_l1
      
    pop    ecx
    shl    ecx, 2
    add    esp, ecx
    popad
    ret

%define A esi
%define B ebx
%define C edx
%define D ebp

_rc6_cryptx:
rc6_crypt:
    pushad

    mov    edi, [esp+32+4] ; rc6 key
    mov    esi, [esp+32+8] ; input
    
    ; load ciphertext
    lodsd
    xchg   eax, ecx
    lodsd
    xchg   eax, B
    lodsd
    xchg   eax, C
    lodsd
    xchg   eax, D
    xchg   ecx, A
    
    mov    ecx, [esp+32+16] ; enc
    jecxz  r6c_l1
    
    ; B += key->x[0];
    add    B, [edi]
    scasd
    ; D += key->x[1];
    add    D, [edi]
    scasd
    jmp    r6c_l2
r6c_l1:
    ; move to end of key
    add    edi, (RC6_KR*4) - 4
    ; load backwards
    std
    
    ; C -= key->x[43];
    sub    C, [edi]
    ; A -= key->x[42];
    scasd
    sub    A, [edi]
r6c_l2:
    push   RC6_ROUNDS
    pop    eax
r6c_l3:
    push   eax
    push   ecx
    dec    ecx
    js     r6c_l4
    
    ; T0 = ROTL(B * (2 * B + 1), 5);
    lea    eax, [B+B+1]
    imul   eax, B
    rol    eax, 5
    ; T1 = ROTL(D * (2 * D + 1), 5);
    lea    ecx, [D+D+1]
    imul   ecx, D
    rol    ecx, 5
    ; A = ROTL(A ^ T0, T1) + key->x[i];
    xor    A, eax
    rol    A, cl
    add    A, [edi]  ; key->x[i]
    scasd
    ; C = ROTL(C ^ T1, T0) + key->x[i+1];
    xor    C, ecx
    xchg   eax, ecx
    rol    C, cl
    add    C, [edi]  ; key->x[i+1]
    scasd
    ; swap
    mov    eax, A
    mov    A, B
    mov    B, C
    mov    C, D
    mov    D, eax
    jmp    r6c_l5
r6c_l4:    
    ; t = ROTL(A * (2 * A + 1), 5);
    lea    ecx, [A+A+1]
    imul   ecx, A
    rol    ecx, 5
    ; u = ROTL(C * (2 * C + 1), 5);
    lea    eax, [C+C+1]
    imul   eax, C
    rol    eax, 5
    ; B = ROTR(B - key->x[i + 1], t) ^ u;
    scasd
    sub    B, [edi]
    ror    B, cl   ; t
    xor    B, eax  ; u
    ; D = ROTR(D - key->x[i], u) ^ t;
    xchg   eax, ecx ; swap u and t
    scasd
    sub    D, [edi]
    ror    D, cl   ; u
    xor    D, eax  ; t
    ; swap
    mov    eax, D
    mov    D, C
    mov    C, B
    mov    B, A
    mov    A, eax 
r6c_l5:
    ; decrease counter
    pop    ecx
    pop    eax
    dec    eax    ; _I--
    jnz    r6c_l3

    jecxz  r6c_l6
    ; out[0] += key->x[42];
    add    A, [edi]
    scasd
    ; out[2] += key->x[43];
    add    C, [edi]
    jmp    r6c_l7
r6c_l6:
    ; out[3] -= key->x[1];
    scasd
    sub    D, [edi]
    ; out[1] -= key->x[0];
    scasd
    sub    B, [edi]
    
r6c_l7:
    cld
    ; save ciphertext
    mov    edi, [esp+32+12] ; output
    mov    eax, A
    stosd
    xchg   eax, B
    stosd
    xchg   eax, C
    stosd
    xchg   eax, D
    stosd
    popad
    ret
    