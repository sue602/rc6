

; RC6 in x86 assembly
; Odzhan

rc6_set_key proc
    pushad
    popad
    ret
rc6_set_key endp

rc6_encrypt proc rc6key:dword, pt:dword, ct:dword
    pushad
    mov    esi, pt
    mov    edi, ct
    add   _b, [edi][RC6_KEY][0]
    add   _d, [edi][RC6_KEY][4]
    .repeat
      lea  eax, [_b+_b+1]
      lea  ecx, [_d+_d+1]
      imul eax, _b
      imul ecx, _d
      rol  eax, 5
      rol  ecx, 5
      xor  _a, eax
      xor  _c, ecx
      rol  _a, cl
      mov  cl, al
      rol  _c, cl
      add  _a, [edi][RC6_KEY][4*_i]
      add  _c, [edi][RC6_KEY][4*_i+4]
      add  _i, 2
      cmp  _i, 42
    .until zero?
    add   _a, [edi][RC6_KEY][4*_i]
    stosd
    xchg  _a, _b
    stosd
    add   _c, [edi][RC6_KEY][4*_i+4]
    xchg  _a, _c
    stosd
    xchg  _a, _d
    stosd
    popad
    ret
rc6_encrypt endp

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

    end