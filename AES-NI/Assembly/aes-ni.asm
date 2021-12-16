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

; Reference from: https://github.com/intel/isa-l_crypto/blob/42daf271be419de78be0c33085aa61e331c15ca1/aes/keyexp_256.asm#L39

; Uses the f() function of the aeskeygenassist result
; %1: key0
; %2: temp
; @xmm15: zeros
%macro KeyExpansion0 2
    pshufd	%2, %2, 0b11111111
    shufps	xmm15, %1, 0b00010000
    pxor	%1, xmm15
    shufps	xmm15, %1, 0b10001100
    pxor	%1, xmm15
	pxor	%1, %2
%endmacro

; Uses the SubWord function of the aeskeygenassist result
; %1: key1
; %2: temp
; @xmm15: zeros
%macro KeyExpansion1 2
    pshufd	%2, %2, 0b10101010
    shufps	xmm15, %1, 0b00010000
    pxor	%1, xmm15
    shufps	xmm15, %1, 0b10001100
    pxor	%1, xmm15
	pxor	%1, %2
%endmacro

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
	push rKeys

	lea KEY, [KEY]
	lea rKeys, [rKeys]

	; Load key
	movv KEY_0, [KEY]
	movv KEY_1, [KEY+16]
	movv [rKeys], KEY_0
	movv [rKeys+16], KEY_1
	
	; zero xmm15 for key_expansion
	pxor xmm15, xmm15

	; keygen shit yes.

	; Round Key [2]
	add rKeys, 0x20
	aeskeygenassist temp, KEY_1, RCON1
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0

	; Round Key [3]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON1
	KeyExpansion1 KEY_1, temp
	movv [rKeys], KEY_1

	; Round Key [4]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON2
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0

	; Round Key [5]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON2
	KeyExpansion1 KEY_1, temp
	movv [rKeys], KEY_1

	; Round Key [6]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON3
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0

	; Round Key [7]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON3
	KeyExpansion1 KEY_1, temp
	movv [rKeys], KEY_1

	; Round Key [8]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON4
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0

	; Round Key [9]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON4
	KeyExpansion1 KEY_1, temp
	movv [rKeys], KEY_1

	; Round Key [10]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON5
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0

	; Round Key [11]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON5
	KeyExpansion1 KEY_1, temp
	movv [rKeys], KEY_1

	; Round Key [12]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON6
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0

	; Round Key [13]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON6
	KeyExpansion1 KEY_1, temp
	movv [rKeys], KEY_1

	; Round Key [14]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON7
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0

	pop rKeys
ret
; #endregion

; #region ExpandKeyENC_AVX
; @rcx: ptr to key (256 bit)
; @rdx: ptr to rkeys buffer (128*15 bits)
ExpandKeyENC_AVX:
	push rKeys

	lea KEY, [KEY]
	lea rKeys, [rKeys]

	; Load key
	vmovv KEY_0, [KEY]
	vmovv KEY_1, [KEY+16]
	vmovv [rKeys], KEY_0
	vmovv [rKeys+16], KEY_1
	
	; zero xmm15 for key_expansion
	vpxor xmm15, xmm15

	; keygen shit yes.

	; Round Key [2]
	add rKeys, 0x20
	vaeskeygenassist temp, KEY_1, RCON1
	KeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0

	; Round Key [3]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_0, RCON1
	KeyExpansion1 KEY_1, temp
	vmovv [rKeys], KEY_1

	; Round Key [4]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_1, RCON2
	KeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0

	; Round Key [5]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_0, RCON2
	KeyExpansion1 KEY_1, temp
	vmovv [rKeys], KEY_1

	; Round Key [6]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_1, RCON3
	KeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0

	; Round Key [7]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_0, RCON3
	KeyExpansion1 KEY_1, temp
	vmovv [rKeys], KEY_1

	; Round Key [8]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_1, RCON4
	KeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0

	; Round Key [9]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_0, RCON4
	KeyExpansion1 KEY_1, temp
	vmovv [rKeys], KEY_1

	; Round Key [10]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_1, RCON5
	KeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0

	; Round Key [11]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_0, RCON5
	KeyExpansion1 KEY_1, temp
	vmovv [rKeys], KEY_1

	; Round Key [12]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_1, RCON6
	KeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0

	; Round Key [13]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_0, RCON6
	KeyExpansion1 KEY_1, temp
	vmovv [rKeys], KEY_1

	; Round Key [14]
	add rKeys, 0x10
	vaeskeygenassist temp, KEY_1, RCON7
	KeyExpansion0 KEY_0, temp
	vmovv [rKeys], KEY_0

	pop rKeys
ret

; #endregion

; #region ExpandKeyDEC_SSE

; @rcx: ptr to key (256 bit)
; @rdx: ptr to rkeys buffer (128*15 bits)
ExpandKeyDEC_SSE:

	lea KEY, [KEY]
	lea rKeys, [rKeys]

	; Load key
	movv KEY_0, [KEY]
	movv KEY_1, [KEY+16]
	movv [rKeys+16*14], KEY_0
	aesimc keyimc, KEY_1
	movv [rKeys+16*13], keyimc
	
	; zero xmm15 for key_expansion
	pxor xmm15, xmm15

	; keygen shit yes.

	; Round Key [2]
	add rKeys, 16*12
	aeskeygenassist temp, KEY_1, RCON1
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [3]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON1
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [4]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON2
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [5]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON2
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [6]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON3
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [7]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON3
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [8]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON4
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [9]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON4
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [10]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON5
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [11]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON5
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [12]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON6
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [13]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON6
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [14]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON7
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0
ret

; #endregion

; #region ExpandKeyDEC_AVX

; @rcx: ptr to key (256 bit)
; @rdx: ptr to rkeys buffer (128*15 bits)
ExpandKeyDEC_AVX:

	lea KEY, [KEY]
	lea rKeys, [rKeys]

	; Load key
	movv KEY_0, [KEY]
	movv KEY_1, [KEY+16]
	movv [rKeys+16*14], KEY_0
	aesimc keyimc, KEY_1
	movv [rKeys+16*13], keyimc
	
	; zero xmm15 for key_expansion
	pxor xmm15, xmm15

	; keygen shit yes.

	; Round Key [2]
	add rKeys, 16*12
	aeskeygenassist temp, KEY_1, RCON1
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [3]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON1
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [4]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON2
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [5]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON2
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [6]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON3
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [7]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON3
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [8]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON4
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [9]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON4
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [10]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON5
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [11]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON5
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [12]
	add rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON6
	KeyExpansion0 KEY_0, temp
	aesimc keyimc, KEY_0
	movv [rKeys], keyimc

	; Round Key [13]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_0, RCON6
	KeyExpansion1 KEY_1, temp
	aesimc keyimc, KEY_1
	movv [rKeys], keyimc

	; Round Key [14]
	sub rKeys, 0x10
	aeskeygenassist temp, KEY_1, RCON7
	KeyExpansion0 KEY_0, temp
	movv [rKeys], KEY_0
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
	
	lea rKeys, [rKeys]
	lea output, [output]

	; round 0 / whitening with k1
	pxor state, [rKeys+16*0]

	; mov [xmm1:xmm14], rKeys
	;movv xmm1, [rKeys+16*1]
	;movv xmm2, [rKeys+16*2]
	;movv xmm3, [rKeys+16*3]
	;movv xmm4, [rKeys+16*4]
	;movv xmm5, [rKeys+16*5]
	;movv xmm6, [rKeys+16*6]
	;movv xmm7, [rKeys+16*7]
	;movv xmm8, [rKeys+16*8]
	;movv xmm9, [rKeys+16*9]
	;movv xmm10, [rKeys+16*10]
	;movv xmm11, [rKeys+16*11]
	;movv xmm12, [rKeys+16*12]
	;movv xmm13, [rKeys+16*13]
	;movv xmm14, [rKeys+16*14]

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
	
	; get dma
	lea rKeys, [rKeys]
	lea output, [output]

	; read plaintext
	vmovv state, [plainText]
	
	; round 0 / whitening with k1
	vpxor state, state, [rKeys]

	; mov [xmm1:xmm14], rKeys
	;movv xmm1, [rKeys+16*1]
	;movv xmm2, [rKeys+16*2]
	;movv xmm3, [rKeys+16*3]
	;movv xmm4, [rKeys+16*4]
	;movv xmm5, [rKeys+16*5]
	;movv xmm6, [rKeys+16*6]
	;movv xmm7, [rKeys+16*7]
	;movv xmm8, [rKeys+16*8]
	;movv xmm9, [rKeys+16*9]
	;movv xmm10, [rKeys+16*10]
	;movv xmm11, [rKeys+16*11]
	;movv xmm12, [rKeys+16*12]
	;movv xmm13, [rKeys+16*13]
	;movv xmm14, [rKeys+16*14]

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

; #region Decryption (TODO)



; #endregion Decryption

; NOTE: THESE MUST BE IN ALPHABETICAL ORDER! (caps first, then lowercase) eg: FUNC Banana, FUNC apple
EXPORT
	FUNC Encrypt_AVX
	FUNC Encrypt_SSE
	FUNC ExpandKeyDEC_AVX
	FUNC ExpandKeyDEC_SSE
	FUNC ExpandKeyENC_AVX
	FUNC ExpandKeyENC_SSE
ENDEXPORT

END