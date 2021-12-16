%include "lib/pe/pe.inc"
[bits 64]

DLL64

; #region Macros

%define movv movdqu
%define vmovv vmovdqu

%macro enter 1 
	push rbp
	mov rbp, rsp
	sub rsp, %1
%endmacro

%macro enter 0 
	push rbp
	mov rbp, rsp
%endmacro

%macro leave 0 
	mov rsp, rbp
	pop rbp
%endmacro	

; i dont need all of these, just 1:7 but whatever
RCON0:  equ 0x8D
RCON1:  equ 0x01
RCON2:  equ 0x02
RCON3:  equ 0x04
RCON4:  equ 0x08
RCON5:  equ 0x10
RCON6:  equ 0x20
RCON7:  equ 0x40
RCON8:  equ 0x80
RCON9:  equ 0x1B
RCON10: equ 0x36
RCON11: equ 0x6C
RCON12: equ 0xD8
RCON13: equ 0xAB
RCON14: equ 0x4D
RCON15: equ 0x9A

; Reference: https://github.com/intel/isa-l_crypto/blob/42daf271be419de78be0c33085aa61e331c15ca1/aes/keyexp_256.asm#L39
; #region SSE

; Get the f() from the aeskeygen result
; %1: key0
; %2: temp
; @xmm15: zeros
%macro KeyExpansion0 2
    pshufd		%2, %2, 0b11111111
    shufps		xmm15, %1, 0b00010000
    pxor		%1, xmm15
    shufps		xmm15, %1, 0b10001100
    pxor		%1, xmm15
	pxor		%1, %2
%endmacro

; Get the subword from the aeskeygen result
; %1: key1
; %2: temp
; @xmm15: zeros
%macro KeyExpansion1 2
    pshufd		%2, %2, 0b10101010
    shufps		xmm15, %1, 0b00010000
    pxor		%1, xmm15
    shufps		xmm15, %1, 0b10001100
    pxor		%1, xmm15
	pxor		%1, %2
%endmacro

; #endregion SSE

; #region AVX

; Get the f() from the aeskeygen result
; %1: key0
; %2: temp
; @xmm15: zeros
%macro vKeyExpansion0 2
    vpshufd		%2, %2, 0b11111111
    vshufps		xmm15, xmm15, %1, 0b00010000
    vpxor		%1, %1, xmm15
    vshufps		xmm15, xmm15, %1, 0b10001100
    vpxor		%1, %1, xmm15
	vpxor		%1, %1, %2
%endmacro

; Get the subword from the aeskeygen result
; %1: key1
; %2: temp
; @xmm15: zeros
%macro vKeyExpansion1 2
    vpshufd		%2, %2, 0b10101010
    vshufps		xmm15, xmm15, %1, 0b00010000
    vpxor		%1, %1, xmm15
    vshufps		xmm15, xmm15, %1, 0b10001100
    vpxor		%1, %1, xmm15
	vpxor		%1, %1, %2
%endmacro

; #endregion AVX

; #endregion

START
mov rax, 1
	ret

; #region Expand Key

%define KEY rcx
%define rKeys rdx
%define KEY_0 xmm0
%define KEY_1 xmm1
%define temp xmm10
%define keyimc xmm2

; #region ExpandKeyENC_SSE
; @rcx: ptr to key (256 bit)
; @rdx: ptr to rkeys buffer (128*15 bits)
ExpandKeyENC_SSE:

	; Load key
	movv KEY_0, [KEY]
	movv KEY_1, [KEY+16]
	movv [rKeys], KEY_0
	movv [rKeys+16], KEY_1
	
	; zero xmm15 for key_expansion
	pxor xmm15, xmm15

	; keygen shit yes.

	; Round Key [2]
	aeskeygenassist temp, KEY_1, RCON1
	KeyExpansion0 KEY_0, temp
	movv [rKeys+16*2], KEY_0

	; Round Key [3]
	aeskeygenassist temp, KEY_0, RCON1
	KeyExpansion1 KEY_1, temp
	movv [rKeys+16*3], KEY_1

	; Round Key [4]
	aeskeygenassist temp, KEY_1, RCON2
	KeyExpansion0 KEY_0, temp
	movv [rKeys+16*4], KEY_0

	; Round Key [5]
	aeskeygenassist temp, KEY_0, RCON2
	KeyExpansion1 KEY_1, temp
	movv [rKeys+16*5], KEY_1

	; Round Key [6]
	aeskeygenassist temp, KEY_1, RCON3
	KeyExpansion0 KEY_0, temp
	movv [rKeys+16*6], KEY_0

	; Round Key [7]
	aeskeygenassist temp, KEY_0, RCON3
	KeyExpansion1 KEY_1, temp
	movv [rKeys+16*7], KEY_1

	; Round Key [8]
	aeskeygenassist temp, KEY_1, RCON4
	KeyExpansion0 KEY_0, temp
	movv [rKeys+16*8], KEY_0

	; Round Key [9]
	aeskeygenassist temp, KEY_0, RCON4
	KeyExpansion1 KEY_1, temp
	movv [rKeys+16*9], KEY_1

	; Round Key [10]
	aeskeygenassist temp, KEY_1, RCON5
	KeyExpansion0 KEY_0, temp
	movv [rKeys+16*10], KEY_0

	; Round Key [11]
	aeskeygenassist temp, KEY_0, RCON5
	KeyExpansion1 KEY_1, temp
	movv [rKeys+16*11], KEY_1

	; Round Key [12]
	aeskeygenassist temp, KEY_1, RCON6
	KeyExpansion0 KEY_0, temp
	movv [rKeys+16*12], KEY_0

	; Round Key [13]
	aeskeygenassist temp, KEY_0, RCON6
	KeyExpansion1 KEY_1, temp
	movv [rKeys+16*13], KEY_1

	; Round Key [14]
	aeskeygenassist temp, KEY_1, RCON7
	KeyExpansion0 KEY_0, temp
	movv [rKeys+16*14], KEY_0

ret
; #endregion

; #region ExpandKeyENC_AVX
; @rcx: ptr to key (256 bit)
; @rdx: ptr to rkeys buffer (128*15 bits)
ExpandKeyENC_AVX:

	; Load key
	vmovv KEY_0, [KEY]
	vmovv KEY_1, [KEY+16]
	vmovv [rKeys], KEY_0
	vmovv [rKeys+16], KEY_1
	
	; zero xmm15 for key_expansion
	vpxor xmm15, xmm15

	; keygen shit yes.

	; Round Key [2]
	vaeskeygenassist temp, KEY_1, RCON1
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys+16*2], KEY_0

	; Round Key [3]
	vaeskeygenassist temp, KEY_0, RCON1
	vKeyExpansion1 KEY_1, temp
	vmovv [rKeys+16*3], KEY_1

	; Round Key [4]
	vaeskeygenassist temp, KEY_1, RCON2
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys+16*4], KEY_0

	; Round Key [5]
	vaeskeygenassist temp, KEY_0, RCON2
	vKeyExpansion1 KEY_1, temp
	vmovv [rKeys+16*5], KEY_1

	; Round Key [6]
	vaeskeygenassist temp, KEY_1, RCON3
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys+16*6], KEY_0

	; Round Key [7]
	vaeskeygenassist temp, KEY_0, RCON3
	vKeyExpansion1 KEY_1, temp
	vmovv [rKeys+16*7], KEY_1

	; Round Key [8]
	vaeskeygenassist temp, KEY_1, RCON4
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys+16*8], KEY_0

	; Round Key [9]
	vaeskeygenassist temp, KEY_0, RCON4
	vKeyExpansion1 KEY_1, temp
	vmovv [rKeys+16*9], KEY_1

	; Round Key [10]
	vaeskeygenassist temp, KEY_1, RCON5
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys+16*10], KEY_0

	; Round Key [11]
	vaeskeygenassist temp, KEY_0, RCON5
	vKeyExpansion1 KEY_1, temp
	vmovv [rKeys+16*11], KEY_1

	; Round Key [12]
	vaeskeygenassist temp, KEY_1, RCON6
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys+16*12], KEY_0

	; Round Key [13]
	vaeskeygenassist temp, KEY_0, RCON6
	vKeyExpansion1 KEY_1, temp
	vmovv [rKeys+16*13], KEY_1

	; Round Key [14]
	vaeskeygenassist temp, KEY_1, RCON7
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys+16*14], KEY_0

ret

; #endregion

; #region ExpandKeyDEC_SSE
; @rcx: ptr to key (256 bit)
; @rdx: ptr to rkeys buffer (128*15 bits)
ExpandKeyDEC_SSE:

	; Load key
	movv KEY_0, [KEY]
	movv KEY_1, [KEY+16]

	; Round Key [14]
	movv [rKeys+16*14], KEY_0

	; Round Key [13]
	aesimc keyimc, KEY_1
	movv [rKeys+16*13], keyimc
	
	; zero xmm15 for key_expansion
	pxor xmm15, xmm15

	; keygen shit yes.

	; Round Key [12]
	aeskeygenassist temp, KEY_1, RCON1
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys+16*12], keyimc

	; Round Key [11]
	aeskeygenassist temp, KEY_0, RCON1
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys+16*11], keyimc

	; Round Key [10]
	aeskeygenassist temp, KEY_1, RCON2
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys+16*10], keyimc

	; Round Key [9]
	aeskeygenassist temp, KEY_0, RCON2
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys+16*9], keyimc

	; Round Key [8]
	aeskeygenassist temp, KEY_1, RCON3
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys+16*8], keyimc

	; Round Key [7]
	aeskeygenassist temp, KEY_0, RCON3
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys+16*7], keyimc

	; Round Key [6]
	aeskeygenassist temp, KEY_1, RCON4
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys+16*6], keyimc

	; Round Key [5]
	aeskeygenassist temp, KEY_0, RCON4
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys+16*5], keyimc

	; Round Key [4]
	aeskeygenassist temp, KEY_1, RCON5
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys+16*4], keyimc

	; Round Key [3]
	aeskeygenassist temp, KEY_0, RCON5
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys+16*3], keyimc

	; Round Key [2]
	aeskeygenassist temp, KEY_1, RCON6
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys+16*2], keyimc

	; Round Key [1]
	aeskeygenassist temp, KEY_0, RCON6
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys+16*1], keyimc

	; Round Key [0]
	aeskeygenassist temp, KEY_1, RCON7
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0
ret

; #endregion

; #region ExpandKeyDEC_AVX

; @rcx: ptr to key (256 bit)
; @rdx: ptr to rkeys buffer (128*15 bits)
ExpandKeyDEC_AVX:

	; Load key
	vmovv KEY_0, [KEY]
	vmovv KEY_1, [KEY+16]

	; Round Key [14]
	vmovv [rKeys+16*14], KEY_0

	; Round Key [13]
	vaesimc keyimc, KEY_1
	vmovv [rKeys+16*13], keyimc
	
	; zero xmm15 for key_expansion
	vpxor xmm15, xmm15, xmm15

	; keygen shit yes.

	; Round Key [12]
	vaeskeygenassist temp, KEY_1, RCON1
	vKeyExpansion0 KEY_0, temp
	vaesimc keyimc, KEY_0
	vmovv [rKeys+16*12], keyimc

	; Round Key [11]
	vaeskeygenassist temp, KEY_0, RCON1
	vKeyExpansion1 KEY_1, temp
	vaesimc keyimc, KEY_1
	movv [rKeys+16*11], keyimc

	; Round Key [10]
	vaeskeygenassist temp, KEY_1, RCON2
	vKeyExpansion0 KEY_0, temp
	vaesimc keyimc, KEY_0
	vmovv [rKeys+16*10], keyimc

	; Round Key [9]
	vaeskeygenassist temp, KEY_0, RCON2
	vKeyExpansion1 KEY_1, temp
	vaesimc keyimc, KEY_1
	vmovv [rKeys+16*9], keyimc

	; Round Key [8]
	vaeskeygenassist temp, KEY_1, RCON3
	vKeyExpansion0 KEY_0, temp
	vaesimc keyimc, KEY_0
	vmovv [rKeys+16*8], keyimc

	; Round Key [7]
	vaeskeygenassist temp, KEY_0, RCON3
	vKeyExpansion1 KEY_1, temp
	vaesimc keyimc, KEY_1
	vmovv [rKeys+16*7], keyimc

	; Round Key [6]
	vaeskeygenassist temp, KEY_1, RCON4
	vKeyExpansion0 KEY_0, temp
	vaesimc keyimc, KEY_0
	vmovv [rKeys+16*6], keyimc

	; Round Key [5]
	vaeskeygenassist temp, KEY_0, RCON4
	vKeyExpansion1 KEY_1, temp
	vaesimc keyimc, KEY_1
	vmovv [rKeys+16*5], keyimc

	; Round Key [4]
	vaeskeygenassist temp, KEY_1, RCON5
	vKeyExpansion0 KEY_0, temp
	vaesimc keyimc, KEY_0
	vmovv [rKeys+16*4], keyimc

	; Round Key [3]
	vaeskeygenassist temp, KEY_0, RCON5
	vKeyExpansion1 KEY_1, temp
	vaesimc keyimc, KEY_1
	vmovv [rKeys+16*3], keyimc

	; Round Key [2]
	vaeskeygenassist temp, KEY_1, RCON6
	vKeyExpansion0 KEY_0, temp
	vaesimc keyimc, KEY_0
	vmovv [rKeys+16*2], keyimc

	; Round Key [1]
	vaeskeygenassist temp, KEY_0, RCON6
	vKeyExpansion1 KEY_1, temp
	vaesimc keyimc, KEY_1
	vmovv [rKeys+16*1], keyimc

	; Round Key [0]
	vaeskeygenassist temp, KEY_1, RCON7
	vKeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0
ret

; #endregion

%undef KEY
%undef rKeys
%undef KEY_0
%undef KEY_1
%undef temp
%undef keyimc

; #endregion Expand Key

; #region Encryption

%define plainText rcx
%define rKeys rdx
%define output r8
%define state xmm0

; #region Encrypt_SSE
; @rcx: ptr to plaintext (128 bits)
; @rdx: ptr to rKeys (128*15 bits)
; @r8: ptr to output (128 bits)
Encrypt_SSE:
	; xmm0: state
	movv state, [plainText]

	; round 0 / whitening with k1
	pxor state, [rKeys+16*0]

	; perform rounds
	aesenc		state,	[rKeys+16*1]
	aesenc		state,	[rKeys+16*2]
	aesenc		state,	[rKeys+16*3]
	aesenc		state,	[rKeys+16*4]
	aesenc		state,	[rKeys+16*5]
	aesenc		state,	[rKeys+16*6]
	aesenc		state,	[rKeys+16*7]
	aesenc		state,	[rKeys+16*8]
	aesenc		state,	[rKeys+16*9]
	aesenc		state,	[rKeys+16*10]
	aesenc		state,	[rKeys+16*11]
	aesenc		state,	[rKeys+16*12]
	aesenc		state,	[rKeys+16*13]
	aesenclast	state,	[rKeys+16*14]

	; store result [r8]
	movv [output], state
ret

; #endregion Encrypt_SSE

; #region Encrypt_AVX
; @rcx: ptr to plaintext (128 bits)
; @rdx: ptr to rKeys (128*15 bits)
; @r8: ptr to output (128 bits)
Encrypt_AVX:

	; read plaintext
	vmovv state, [plainText]
	
	; round 0 / whitening with k1
	vpxor state, state, [rKeys]

	; perform rounds
	vaesenc		state,	state,	[rKeys+16*1]
	vaesenc		state,	state,	[rKeys+16*2]
	vaesenc		state,	state,	[rKeys+16*3]
	vaesenc		state,	state,	[rKeys+16*4]
	vaesenc		state,	state,	[rKeys+16*5]
	vaesenc		state,	state,	[rKeys+16*6]
	vaesenc		state,	state,	[rKeys+16*7]
	vaesenc		state,	state,	[rKeys+16*8]
	vaesenc		state,	state,	[rKeys+16*9]
	vaesenc		state,	state,	[rKeys+16*10]
	vaesenc		state,	state,	[rKeys+16*11]
	vaesenc		state,	state,	[rKeys+16*12]
	vaesenc		state,	state,	[rKeys+16*13]
	vaesenclast	state,	state,	[rKeys+16*14]

	; store result [r8]
	vmovv [output], state
ret
; #endregion Encrypt_AVX

%undef plainText
%undef rKeys
%undef output
%undef state

; #endregion Encryption

; #region Decryption
; Note: the round keys MUST be in the REVERSE ORDER for these functions to work.
; if you are not using my implementation of the expand keys you must make sure
; the order matches with the order in which i decrypt (or change the src idk)

%define state xmm0

; #region Decrypt_SSE
; @rcx: ptr to ciphertext
; @rdx: ptr to rKeys
; @r8: ptr to output
Decrypt_SSE:

	; load ciphertext into state
	movv state, [rcx]

	; whitening
	pxor state, [rdx+16*0] ; rKey[14]

	; preform rounds
	aesdec state, [rdx+16*1]		; rKey[13]
	aesdec state, [rdx+16*2]		; rKey[12]
	aesdec state, [rdx+16*3]		; rKey[11]
	aesdec state, [rdx+16*4]		; rKey[10]
	aesdec state, [rdx+16*5]		; rKey[9]
	aesdec state, [rdx+16*6]		; rKey[8]
	aesdec state, [rdx+16*7]		; rKey[7]
	aesdec state, [rdx+16*8]		; rKey[6]
	aesdec state, [rdx+16*9]		; rKey[5]
	aesdec state, [rdx+16*10]		; rKey[4]
	aesdec state, [rdx+16*11]		; rKey[3]
	aesdec state, [rdx+16*12]		; rKey[2]
	aesdec state, [rdx+16*13]		; rKey[1]
	aesdeclast state, [rdx+16*14]	; rKey[0]

	; load plaintext into return buffer
	movv [r8], state
ret

; #endregion Decrypt_AVX

; #region Decrypt_AVX
; @rcx: ptr to ciphertext
; @rdx: ptr to rKeys
; @r8: ptr to output
Decrypt_AVX:

	; load ciphertext into state
	vmovv state, [rcx]

	; whitening
	vpxor state, state, [rdx+16*0] ; rKey[14]

	; preform rounds
	vaesdec		state,	state,	[rdx+16*1]		; rKey[13]
	vaesdec		state,	state,	[rdx+16*2]		; rKey[12]
	vaesdec		state,	state,	[rdx+16*3]		; rKey[11]
	vaesdec		state,	state,	[rdx+16*4]		; rKey[10]
	vaesdec		state,	state,	[rdx+16*5]		; rKey[9]
	vaesdec		state,	state,	[rdx+16*6]		; rKey[8]
	vaesdec		state,	state,	[rdx+16*7]		; rKey[7]
	vaesdec		state,	state,	[rdx+16*8]		; rKey[6]
	vaesdec		state,	state,	[rdx+16*9]		; rKey[5]
	vaesdec		state,	state,	[rdx+16*10]		; rKey[4]
	vaesdec		state,	state,	[rdx+16*11]		; rKey[3]
	vaesdec		state,	state,	[rdx+16*12]		; rKey[2]
	vaesdec		state,	state,	[rdx+16*13]		; rKey[1]
	vaesdeclast	state,	state,	[rdx+16*14]		; rKey[0]

	; load plaintext into return buffer
	vmovv [r8], state
ret

; #endregion Decrypt_AVX

%undef state

; #endregion Decryption

; NOTE: THESE MUST BE IN ALPHABETICAL ORDER! (caps first, then lowercase) eg: FUNC Banana, FUNC apple
EXPORT
	FUNC Decrypt_AVX
	FUNC Decrypt_SSE

	FUNC Encrypt_AVX
	FUNC Encrypt_SSE

	FUNC ExpandKeyDEC_AVX
	FUNC ExpandKeyDEC_SSE

	FUNC ExpandKeyENC_AVX
	FUNC ExpandKeyENC_SSE
ENDEXPORT

END