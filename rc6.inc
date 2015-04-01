comment *

Algo	: RC6-32/20/16 (w/r/b)
Block	: 16 bytes
Key	: 16 bytes (128 b)


	push	offset password		;16 bytes readed as key
	call	rc6_setkey

	push	offset Data		;16 bytes encrypted
	call	rc6_encrypt
	
	push	offset Data		;16 bytes decrypted
	call	rc6_decrypt
	
	call	rc6_clear		;clear internal key buffer


07.02.2002 WiteG//xtreeme (witeg@poczta.fm, www.witeg.prv.pl)
*

.386
P equ 0b7e15163h
Q equ 09e3779b9h

.code
rc6_setkey	proc	ptrPass :DWORD

	pushad

	mov	esi, offset rc6_padded_key
	mov	edi, ptrPass
	mov	ecx, 16
@@:
	mov	eax, dword ptr [edi+ecx-4]
	mov	dword ptr [esi+ecx-4], eax
	sub	ecx, 4
	jnz	@B

	mov	esi, offset rc6_s_table - 4
	mov	eax, P-Q
	mov	ecx, 44
@@:
	add	esi, 4
	add	eax, Q
	dec	ecx
	mov	dword ptr [esi], eax
	jnz	@B

	mov	edx, 132		;k

	push	ebp

	xor	eax, eax		;A
	xor	ebp, ebp		;B
	xor	edi, edi		;i
	xor	esi, esi		;j

@main_loop:
	add	eax, ebp				;eax = A + B
	
	cmp	edi, 44
	jb	@F

	xor	edi, edi
@@:
	add	eax, dword ptr [rc6_s_table+4*edi]	;eax = A + B + S[i]
	mov	ecx, ebp				;ecx = B
	
	cmp	esi, 4
	jb	@F

	xor	esi, esi	
@@:
	rol	eax, 3					;A = eax = (A + B + S[i]) ROL 3

	mov	ebp, dword ptr [rc6_padded_key+4*esi]	;ebp = L[j]

	add	ecx, eax				;ecx = A + B
	inc	esi
	add	ebp, ecx				;ebp = L[j] + A + B
	inc	edi
	and	ecx, 31					;ecx = (A + B) and 31
	mov	dword ptr [rc6_s_table+4*edi-4], eax
	rol	ebp, cl
	dec	edx
	mov	dword ptr [rc6_padded_key+4*esi-4], ebp
	jnz	@main_loop

	pop	ebp

	mov	edi, offset rc6_padded_key
	mov	ecx, 16
@@:
	mov	dword ptr [edi+ecx-4], edx
	sub	ecx, 4
	jnz	@B
	
	popad
	ret
rc6_setkey	endp

rc6_encrypt	proc	ptrData :DWORD
LOCAL	counter :DWORD

	pushad

	mov	esi, ptrData
	mov	edi, offset rc6_s_table

	push	esi

	mov	eax, dword ptr [esi]		;A
	mov	ebx, dword ptr [esi+4]		;B
	mov	edx, dword ptr [esi+8]		;C
	mov	esi, dword ptr [esi+12]		;D

	add	ebx, dword ptr [edi]		;B + S[0]
	add	esi, dword ptr [edi+4]		;D + S[1]
	add	edi, 8

	mov	counter, 20
@mainloop:
	push	ebp

	lea	ebp, [2*ebx +1]
	imul	ebp, ebx
	rol	ebp, 5				;t

	lea	ecx, [2*esi +1]
	imul	ecx, esi
	rol	ecx, 5				;u

	xor	eax, ebp			;A ^ t
	xor	edx, ecx			;C ^ u

	and	ebp, 31
	and	ecx, 31

	rol	eax, cl

	mov	ecx, ebp
	rol	edx, cl

	add	eax, dword ptr [edi]
	add	edx, dword ptr [edi+4]
	add	edi, 8

	xchg	eax, ebx
	xchg	edx, ebx
	xchg	edx, esi

	pop	ebp
	dec	counter
	jnz	@mainloop

	add	eax, dword ptr [edi]
	add	edx, dword ptr [edi+4]

	pop	edi				; ptrData

	mov	dword ptr [edi], eax
	mov	dword ptr [edi+4], ebx
	mov	dword ptr [edi+8], edx
	mov	dword ptr [edi+12], esi

	popad
	ret
rc6_encrypt	endp

rc6_decrypt	proc	ptrData :DWORD

LOCAL	counter :DWORD

	pushad

	mov	esi, ptrData
	mov	edi, offset rc6_s_table + 4*44 -4

	push	esi

	mov	eax, dword ptr [esi]		;A
	mov	ebx, dword ptr [esi+4]		;B
	mov	edx, dword ptr [esi+8]		;C
	mov	esi, dword ptr [esi+12]		;D

	sub	eax, dword ptr [edi-4]
	sub	edx, dword ptr [edi]
	sub	edi, 8

	mov	counter, 20
@mainloop:
	push	ebp

	xchg	eax, ebx
	xchg	eax, edx
	xchg	eax, esi

	lea	ecx, [2*esi +1]
	imul	ecx, esi
	rol	ecx, 5
	mov	ebp, ecx			;u
	and	ecx, 31

	sub	edx, dword ptr [edi]
	sub	eax, dword ptr [edi-4]

	ror	eax, cl				;jeszcze xor t

	lea	ecx, [2*ebx +1]
	imul	ecx, ebx
	rol	ecx, 5				;t

	xor	eax, ecx

	and	ecx, 31
	ror	edx, cl
	xor	edx, ebp

	sub	edi, 8

	pop	ebp
	dec	counter
	jnz	@mainloop

	sub	esi, dword ptr [edi]		;D - S[1]
	sub	ebx, dword ptr [edi-4]		;B - S[0]

	pop	edi				; ptrData

	mov	dword ptr [edi], eax
	mov	dword ptr [edi+4], ebx
	mov	dword ptr [edi+8], edx
	mov	dword ptr [edi+12], esi

	popad
	ret

rc6_decrypt	endp

rc6_clear	proc
	pushad

	xor	eax, eax
	mov	ecx, 44
	mov	edi, offset rc6_s_table
	cld
	rep	stosd

	popad
	ret
rc6_clear	endp

.data?
rc6_padded_key	dd  4 dup (?)
rc6_s_table	dd 44 dup (?)