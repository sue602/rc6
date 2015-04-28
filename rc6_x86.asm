

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
    mov    edx, [esp+32+4]     ; rc6key
    mov    esi, [esp+32+8]     ; key
    push   RC6_KEYLEN
    pop    ecx
    sub    esp, ecx
    mov    edi, esp
    
    ; copy key to local buffer
    rep    movsb

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
	    add    eax, [esi][RC6_KEY.S][4*edi]
	    rol    eax, 3
	    lea    ecx, [eax+ebx]
	    mov    [esi][RC6_KEY.S][4*edi], eax
      ; B = L[j] = ROTL(L[j] + A+B, A+B);
	    add    ebx, eax
	    add    ebx, [esp+4*edx]
	    rol    ebx, cl
	    mov    [esp+4*edx], ebx
  
      ; i++
      inc    edi          
      ; i %= (RC6_ROUNDS*2)+4
      cmp    edi, RC6_KR  
      sbb    ecx, ecx
      and    edi, ecx
      
      ; j++
      inc    edx       
      ; j %= RC6_KEYLEN/4
      cmp    edx, RC6_KEYLEN/4
      sbb    ecx, ecx
      and    edx, ecx
      inc    ebp
    .until ebp == RC6_KR*3
    
    add    esp, RC6_KEYLEN
    popad
    ret
rc6_setkey endp

  public rc6_encrypt
  public _rc6_encrypt
  
_rc6_encrypt:
rc6_encrypt proc rc6key:dword, input:dword, output:dword
    pushad
    mov    eax, rc6key
    mov    esi, input
    mov    edx, output
    ; copy input to local buffer
    push   16
    pop    ecx
    sub    esp, ecx
    mov    edi, esp
    rep    movsb
    
    xchg   eax, esi
    
    ; w[1] += key->x[0];
    lodsd
    add    [esp+4*1], eax
    ; w[3] += key->x[1];
    lodsd
    add    [esp+4*3], eax
    
    ; t = rotl(w[1] * (w[1] + w[1] + 1), 5);
    mov    ebx, [esp+4*1]
    lea    ebx, [ebx+ebx+1]
    imul   ebx, [esp+4*1]
    rol    ebx, 5
    ; u = rotl(w[3] * (w[3] + w[3] + 1), 5);
    mov    ecx, [esp+4*3]
    lea    ecx, [ecx+ecx+1]
    imul   ecx, [esp+4*3]
    rol    ecx, 5
    ; w[0] = rotl(w[0] ^ t, u) + key->x[i];
    mov    edx, [esp+4*0]
    xor    edx, ebx
    rol    edx, cl
    lodsd
    add    edx, eax
    mov    [esp+4*0], edx
    ; w[2] = rotl(w[2] ^ u, t) + key->x[i+1];
    xchg   ebx, ecx
    mov    edx, [esp+4*2]
    xor    edx, ebx
    rol    edx, cl
    lodsd
    add    edx, eax
    mov    [esp+4*2], edx
    ; shift w
    pushad
    mov    esi, esp
    mov    edi, esp
    push   4
    pop    ecx
    lodsd  ; w[0]
shift_w:
    scasd
    xchg   eax, [edi]
    stosd
    loop   shift_w
    popad
    ; save w
    rep    movsd
    
    popad
    ret
rc6_encrypt endp

comment #
rc6_decrypt proc rc6key:dword, ct:dword, pt:dword
    pushad
    mov    esi, pt
    mov    edi, ct
    lodsd
    sub    _a, [edi][RC6_KEY][0]
    xchg   _a, _d
    lodsd
    xchg   _a, _b
    lodsd
    xchg   _a, _c
    sub    _c, [edi][RC6_KEY][4]
    lodsd
    xchg   _a, _d
    .repeat
      sub  _c, RC6_KEY[4*_i+1*4]
      lea  eax, [_d+_d+1]
      sub  _a, RC6_KEY[4*_i+0*4]
      lea  edx, [_b+_b+1]
      imul eax, _d
      imul edx, _b
      rol  eax, 5
      rol  edx, 5
      mov  cl, dl
      ror  _c, cl
      mov  cl, al
      ror  _a, cl
      xor  _c, eax
      xor  _a, edx
    .until zero?
    ; ct[0] = a
    stosd
    ; ct[1] = b - key->x[0]
    sub   _b, [edi][0]
    xchg  _a, _b
    stosd
    ; ct[2] = c
    xchg  _a, _c
    stosd
    ; ct[3] = d - key->[1]
    sub   _d, [edi][0]
    xchg  _a, _d
    stosd
    popad
    ret
rc6_decrypt endp
#
    end