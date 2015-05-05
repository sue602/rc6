

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
    
    xor    eax, eax       ; A=0
    xor    ebx, ebx       ; B=0
    mov    ebp, -RC6_KR*3 ; k=RC6_KR*3
    xor    edi, edi       ; i=0
    xor    edx, edx       ; j=0
    
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
    .until zero?
    
    pop    ecx
    shl    ecx, 2
    add    esp, ecx
    popad
    ret
rc6_setkey endp

    end