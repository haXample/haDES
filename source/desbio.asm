;; -------------------------------------------------------------------------
;; Microsoft Visual Studio 2019
;;
;;command line:  ml /nologo /c /Sn /Sg /Sp84 /Fl desbio.asm

SUBTTL  desbio.asm - DES algorithm for chipcard 
;----------------------------------------------------------------------------
;
;   The DES is an encryption algorithm that complies with       
;   international standards: "ANSI X3.92-1981".
;
;   Acknowledements:                       
;    Refer to Matthew Fischer's paper "DESHOWTO.TXT"    
;    A tutorial description of how to implement the Data Encryption Standard.
;
;               ---------------------------------------
;              | DESbio 1.00  5/1997 for MS-MASM 6.11. |
;              | This is  finally  a source code  that |  
;              | implements the  DES as a paradigm. If |
;              | you  want  to learn DES,  this is it. |  
;              | The  source  is well  documented  and |   
;              | can  be  easily  ported  for any CPU. |   
;              | A test suite  is  available  allowing |
;              | to encrypt / decipher your own files. |
;               ---------------------------------------
;
;  -------------------------------------------------------------------------
; |         Copyright (c)1997 by Helmut Altmann, Munich, Germany.           |
; |           Permission is hereby given for non-commercial use.            |
;  -------------------------------------------------------------------------

.686p
.MODEL FLAT
.NOLISTMACRO

_TEXT SEGMENT
        MemCpy32 PROTO C, destPtr:DWORD, srcPtr:DWORD, cnt:DWORD
        MemCpy16 PROTO C, destPtr:DWORD, srcPtr:DWORD, cnt:DWORD
        MemXor16 PROTO C, destPtr:DWORD, srcPtr:DWORD, cnt:DWORD

desAlgorithm PROTO C, inblock:DWORD, outblock:DWORD

kinit PROTO C, key:DWORD, edf:DWORD
_TEXT ENDS

;;-----------------------------------------------------------------------------
;;
;; Special DES Macros
;;
;; The following macros are supported to improve the understanding of the DES
;; algorithm. The program code itself looks pretty much like what you find
;; in the DES documentation. These macros can be easily tailored for any other
;; assembly language. This makes porting the DES very easy. No guessing and
;; wading through crooked and screwed code anymore. The macros finally
;; provide a very good compromise between speed and code size. Now everyone
;; should be able to understand how to program the DES.
;;
PERMUTATION_START MACRO inbuf, outbuf
  IN_BUF        =       0       ;; inBitField[0]
  INBIT_POS     =       0       ;; Init bit offset for inBitField
  OUT_BUF       =       0       ;; outBitField[0]
  OUTBIT_POS    =       0       ;; Init bit offset for outBitField

;;ha;;  lea     esi, inbuf      ;; Init pointer to cs:inBitField
;;ha;;  lea     edi, outbuf     ;; Init pointer to cs:outBitField
  mov   esi, inbuf              ;; Init pointer to cs:inBitField
  mov   edi, outbuf             ;; Init pointer to cs:outBitField
  ENDM


;;
;; Dummy, for documentation purpose only
;; Could be coded to "close" a macro
;;
PERMUTATION_END MACRO
  ENDM


;;
;; The DES bit notation differs from the one normally used. The MAP_BIT macro
;; maps the DES notation into the standard notation used by the CPU:
;;
;;  The bit definition in a byte according to the DES:  b1 b2 b3 b4 b5 b6 b7 b8
;;  The CPU will look at the same byte differently:     b7 b6 b5 b4 b3 b2 b1 b0
;;
;; This macro takes care of the translation DES -> CPU so that we can go ahead
;; keeping us close to the DES documentation. The advantage is that later we can
;; easily verify whether our code complies the DES. So we put some intelligence
;; into the macros here, in order to suffer less headaches later when looking
;; at the algorithm straitforwardly.
;;
MAP_BIT MACRO b
  INBIT_INDEX = ((b-1+INBIT_POS) XOR 07h) + IN_BUF
  OUTBIT_INDEX = (OUTBIT_POS XOR 07h) + OUT_BUF

    ;;
    ;; Get the value of the current inBit (ah)
    ;; Put current inBit into the outBit position (al)
    ;;

    mov    ax, (INBIT_INDEX SHL 8) OR OUTBIT_INDEX
    call   MapBit               ;; Call the map routine

  OUTBIT_POS = OUTBIT_POS + 1   ;; Advance outBit pointer
  ENDM


;;
;; The PERMUTATION_32BIT_BLOCK macro permutes the bits of high nibbles of eight
;; bytes of the inBitField (DES notation) into four bytes of the outBitField.
;;
PERMUTATION_32BIT_BLOCK MACRO b1, b2, b3, b4
  INBIT_POS     = ((b1-1)/4)*4
  MAP_BIT b1
  INBIT_POS     = ((b2-1)/4)*4
  MAP_BIT b2
  INBIT_POS     = ((b3-1)/4)*4
  MAP_BIT b3
  INBIT_POS     = ((b4-1)/4)*4
  MAP_BIT b4
  ENDM


;;
;; The PERMUTATION_48BIT_BLOCK macro permutes the bits of eight bytes of the
;; inBitField (DES notation) into the lower six bits (right-justified)
;; of eight bytes of the outBitField.
;;
PERMUTATION_48BIT_BLOCK MACRO b1, b2, b3, b4, b5, b6
  OUTBIT_POS    = OUTBIT_POS + 2        ;; Right justify, map into bits [5:0]
  MAP_BIT b1
  MAP_BIT b2
  MAP_BIT b3
  MAP_BIT b4
  MAP_BIT b5
  MAP_BIT b6
  ENDM


;;
;; The PERMUTATION_64BIT_BLOCK macro permutes the bits of eight bytes of the
;; inBitField (DES notation) into the bits of eight bytes of the outBitField.
;;
PERMUTATION_64BIT_BLOCK MACRO b1, b2, b3, b4, b5, b6, b7, b8
  MAP_BIT b1
  MAP_BIT b2
  MAP_BIT b3
  MAP_BIT b4
  MAP_BIT b5
  MAP_BIT b6
  MAP_BIT b7
  MAP_BIT b8
  ENDM


;;
;; The PERMUTATION_BIT_MATRIX macro permutes the bits of eight bytes of the
;; inBitField (DES notation) into the bits of the bytes in outBitField.
;; This macro expands into less code than the PERMUTATION_48/64BIT_BLOCK macros.
;; It can be used alternatively in conjunction with the MapBitMatrix procedure
;; as a code saver.
;;
PERMUTATION_BIT_MATRIX MACRO bn:VARARG
  LOCAL ???matrix
  LOCAL ???matrixend

  _argcnt = 0                   ;; Initialize local variables

  jmp   ???matrixend            ;; Perform the bit mapping

  ???matrix:                    ;; Create the bit mapping matrix
  FOR b, <bn>
    IFB <b>                     ;; If blank, expand the token (-1)
      DB (-1)                   ;; (-1) positions are not mapped (skipped)
    ELSE
      DB ((b-1+INBIT_POS) XOR 07h) + IN_BUF ;; Define next bit position to map
    ENDIF
    _argcnt = _argcnt + 1       ;; Keep track of the arguments processed
  ENDM

  IF (_argcnt NE 56) AND (_argcnt NE 64) ;; We demand exactly 56 or 64 arguments
    .ERR <PERMUTATION_BIT_MATRIX - Incorrect number of required arguments.>
  ENDIF

  ???matrixend:                 ;; Map the bits
  push  ebx                     ;; Save (bx)
  push  ecx                     ;; Save (cx)
  mov   ebx, OFFSET ???matrix   ;; Init pointer to cs:matrix
  mov   ecx, _argcnt            ;; Load number of bits to be mapped
  call  MapBitMatrix            ;; Map the bits according to the matrix
  pop   ecx                     ;; Restore (cx)
  pop   ebx                     ;; Restore (bx)
  ENDM


;;
;; The S_BOX macro supports the definition of the SBox tables. It compresses
;; two 4-bit values into a byte. Odd parameters s1,s3,..s15 are placed into the
;; hi nibble, even parameters s2,s4,..s14 are placed into the low nibble of the
;; corresponding SBox table entry.
;;
S_BOX MACRO sn:VARARG
  _argcnt = 0                           ;; Initialize local variables
  _hi = -1                              ;; High nibble flag: Low nibble first

  FOR sbox:REQ, <sn>
    IF _hi NE -1                        ;; Get lo nibble first, hi nibble next
      DB  (_hi SHL 4) OR sbox           ;; Define next SBox entry: _hi | _lo
      _hi = -1                          ;; Low nibble comes next
    ELSE
      _hi = sbox                        ;; Prepare high nibble
    ENDIF
  _argcnt = _argcnt + 1                 ;; Keep track of the arguments processed
  ENDM

  IF _argcnt NE 16                      ;; We demand exactly 16 arguments
    .ERR <S_BOX - Incorrect number of required arguments.>
  ENDIF
  ENDM


;
; Miscellaneous Equates
;
BLOCK_SIZE      EQU     8       ; Size of DES data block (64 bits)

;
; Supported DES Algorithm Modes
;
ENCRYPT         EQU     0       ; Encrypts a block of plain text (see desmain.cpp)
DECIPHER        EQU     1       ; Deciphers a block of encrypted text  (see desmain.cpp)


_BSS SEGMENT
;------------------------------------------------------------------------------
;
; RAM layout and working storage definitions
;
inBitField      DB      8 DUP(?) ; Start of 64-bit input area
outBitField     DB      8 DUP(?) ; Start of 64-bit permutation area

KeyBuf          DB      7 DUP(?)    ; 7-byte array: secret key (56 bits)
                DB      1 DUP(0FFh) ; Available

KeyPC2          DB      8 DUP(?) ; 8-byte array: DES Permuted Choice 2 (PC-2)

P_Block         DB      4 DUP(?) ; 8 bytes output block (P_Block+L_Block)
L_Block         DB      4 DUP(?) ; 1st half of input data (Shared w/ P_Block)
R_Block         DB      4 DUP(?) ; 2nd half of input data

KeyArray        DB      16*8 DUP(?) ; Array of permuted key elements
_BSS ENDS


_TEXT SEGMENT
;-----------------------------------------------------------------------------
;
;       MemXor16 - void MemXor16(void FPTR *dest, void FPTR *src, int count);
;
;       Entry:
;         src = offset32
;         dest= offset32
;         cnt
;
;       Exit:
;
;       Modifies:
;
;       Description:
;         This routine applies the keybuffer bits to the encrypted
;         data in order to decipher and reconstruct the plain text
;         (original data).
;
;
MemXor16 PROC C USES ebx edi esi ecx, dest:DWORD, src:DWORD, cnt:DWORD
        mov     edi, DWORD PTR dest     ; Load Pointer to destination buffer
        mov     esi, DWORD PTR src      ; Load Pointer to source buffer
        mov     ecx, DWORD PTR cnt      ; Load counter
@@:
        lodsb
        xor     BYTE PTR [edi], al      ; Xor data of destination with source
        inc     edi                     ; Advance to next destination byte
        loopd   @B                      ; Perform next xor
        ret                             ; Done.
MemXor16 ENDP

;-----------------------------------------------------------------------------
;
;       MemCpy32 - void MemCpy32(void FPTR *dest, void FPTR *src, int count);
;
;       Entry:
;         src = offset32 = Start of source memoryblock 
;         dest= offset32 = Start of destination memoryblock
;         cnt
;
;       Exit:
;         A copy of the 'src' data in 'dest'
;
;       Modifies:
;         none
;
;       Processing:
;         Copy a block of memory residing at any physical address within 
;         the 4G space into the destination block. This routine is universal, 
;         it works in all processor modes (real, big real, prot, ..).
;
MemCpy32 PROC C USES ebx edi esi ecx, dest:DWORD, src:DWORD, cnt:DWORD
        mov     edi, DWORD PTR dest     ; Load Pointer to destination buffer
        mov     esi, DWORD PTR src      ; Load Pointer to source buffer
        mov     ecx, DWORD PTR cnt      ; Load counter
        rep movsb                       ; Copy data from source to destination
        ret                             ; Done.
MemCpy32 ENDP

;------------------------------------------------------------------------------
;
;       MapBit
;
;       Entry:
;         ah = INBIT_INDEX,    esi = pointer to inBitField
;         al = OUTBIT_INDEX,   edi = pointer to outBitField
;
;       Modifies:
;
;       Description:
;         The following routine supports the permutation macros.
;         This routine is CPU dependent. The maximum entity of the Intel 80x86
;         CPUs is 32 bits (DWORD). So we must do bit munipulations in chunks of
;         32 bits when using the BT, BTR, BTS, ... instructions.
;
MapBit PROC C USES ebx edi esi edx      ; Maps a bit inBitField -> outBitField
        xor     ebx, ebx                ; Init alignment to 1st DWORD
        cmp     ah, 32                  ; Check which DWORD the index points to.
        jb      @F                      ; Go and test the 1st
        mov     ebx, 4                  ; Advance to next DWORD boundary
        sub     ah, 32                  ; Maximum entity of 80x86 is 32 bits.
@@:     movzx   edx, ah                 ; Build bit index
        bt      DWORD PTR [esi][ebx], edx ; Test the value in inBitField

                                        ; Map the value (CY) into outBitField
        lahf                            ; Save bit status from previous test
        xor     ebx, ebx                ; Init alignment to 1st DWORD
        cmp     al, 32                  ; Check which DWORD the index points to.
        jb      @F                      ; Go and test the 1st
        mov     ebx, 4                  ; Advance to next DWORD boundary
        sub     al, 32                  ; Maximum entity of 80x86 is 32 bits.
@@:     movzx   edx, al                 ; Build bit index
        btr     DWORD PTR [edi][ebx], edx ; Map a zero (assume inBit = 0)
        sahf                            ; Restore bit status
        jnc     @F                      ; Done, if inBit is zero
        bts     DWORD PTR [edi][ebx], edx ; Map a one (inBit = 1)
@@:     ret
MapBit ENDP

;------------------------------------------------------------------------------
;
;       MapBitMatrix
;
;       Entry:
;         esi = pointer to inBitField
;         edi = pointer to outBitField
;         ebx = pointer to bitMapMatrix
;         ecx = Number of bits to be mapped (Matrix entries)
;
;       Modifies:
;         ax ecx flags
;
;       Description:
;         The following routine supports the permutation macros.
;         This routine is CPU dependent. The maximum entity of the Intel x86
;         CPUs is 32 bits (DWORD). So we must do bit manipulations in chunks of
;         32 bits when using the BT, BTR, BTS, ... instructions.
;
;         Note: inBitField positions at (-1) are not mapped, while the outBitField
;               pointer is advanced to the next position.
;
MapBitMatrix PROC C USES ebx edi esi edx; Maps a bit inBitField -> outBitField
        xor     al, al                  ; Start at outBitField bit position 0

MapBitMx_1:
        mov     ah, BYTE PTR [ebx]      ; Read next map inBitField position
        inc     ebx                     ; Advance matrix pointer
        push    ebx                     ; Save pointer to mapping matrix

        cmp     ah, (-1)                ; Skip (-1), for right justification, etc.
        je      MapBitMx_3              ; Don't map this outBitField position

        xor     ebx, ebx                ; Init alignment to 1st DWORD
        cmp     ah, 32                  ; Check which DWORD the index points to.
        jb      @F                      ; Go and test the 1st
        mov     ebx, 4                  ; Advance to next DWORD boundary
        sub     ah, 32                  ; Maximum entity of 80x86 is 32 bits.
@@:     movzx   edx, ah                 ; Build bit index
        bt      DWORD PTR [esi][ebx], edx ; Test the value in inBitField

                                        ; Map the value (CY) into outBitField
        lahf                            ; Save bit status from previous test
        xor     ebx, ebx                ; Init alignment to 1st DWORD

        push    ax                      ; Save outBitField position
        xor     al, 07h                 ; Convert DES notation -> CPU convention

        cmp     al, 32                  ; Check which DWORD the index points to.
        jb      @F                      ; Go and test the 1st
        mov     ebx, 4                  ; Advance to next DWORD boundary
        sub     al, 32                  ; Maximum entity of 80x86 is 32 bits.
@@:     movzx   edx, al                 ; Build bit index

        pop     ax                      ; Restore outBitField position

        btr     DWORD PTR [edi][ebx], edx ; Map a zero (assume inBit = 0)
        sahf                            ; Restore bit status
        jnc     MapBitMx_3              ; Done, if inBit is zero
        bts     DWORD PTR [edi][ebx], edx ; Map a one (inBit = 1)

MapBitMx_3:
        inc     al                      ; Next outBitField position
        pop     ebx                     ; Restore pointer to mapping matrix
        loop    MapBitMx_1              ; Do all bits

        ret
MapBitMatrix ENDP

;------------------------------------------------------------------------------
;
;       InitialPermutation - (IP)
;
;       Entry:
;         Data in L_Block
;
;       Exit:
;         Permuted data in L_Block
;
;       Modifies:
;         ax ecx flags
;
;       Description:
;         Permutes the data according to the DES specification
;
;       Before the (E) operation, perform the following permutation
;       on the 64-bit data block.
;
;       Data block                        Initial Permutation (IP)
;
;       -----------------------           -----------------------
;        1  2  3  4  5  6  7  8           58 50 42 34 26 18 10  2
;        9 10 11 12 13 14 15 16           60 52 44 36 28 20 12  4
;       17 18 19 20 21 22 23 24           62 54 46 38 30 22 14  6
;       25 26 27 28 29 30 31 32           64 56 48 40 32 24 16  8
;       33 34 35 36 37 38 39 40    ->     57 49 41 33 25 17  9  1
;       41 42 43 44 45 46 47 48           59 51 43 35 27 19 11  3
;       49 50 51 52 53 54 55 56           61 53 45 37 29 21 13  5
;       57 58 59 60 61 62 63 64           63 55 47 39 31 23 15  7
;       -----------------------           -----------------------
;
InitialPermutation PROC C USES ebx edi esi

        PERMUTATION_START               OFFSET L_Block, OFFSET outBitField
        PERMUTATION_BIT_MATRIX          58, 50, 42, 34, 26, 18, 10, 2, \
                                        60, 52, 44, 36, 28, 20, 12, 4, \
                                        62, 54, 46, 38, 30, 22, 14, 6, \
                                        64, 56, 48, 40, 32, 24, 16, 8, \
                                        57, 49, 41, 33, 25, 17,  9, 1, \
                                        59, 51, 43, 35, 27, 19, 11, 3, \
                                        61, 53, 45, 37, 29, 21, 13, 5, \
                                        63, 55, 47, 39, 31, 23, 15, 7
        PERMUTATION_END


        mov     edi, OFFSET L_Block     ; L_Block+R_Block <- outBitField
        mov     esi, OFFSET outBitfield
        INVOKE  MemCpy32, edi, esi, BLOCK_SIZE

        ret
InitialPermutation ENDP

;------------------------------------------------------------------------------
;
;       FinalPermutation (IP**-1)
;
;       Entry:
;         Data in cs:P_Block
;
;       Exit:
;         Permuted data in cs:P_Block
;
;       Modifies:
;         ax ecx flags
;
;       Description:
;         Permutes the data according to the DES specification
;
;       After the DES encrypt / decipher process is complete, perform the
;       following permutation on the 64-bit data block.
;
;       Data block                        Final Permutation (IP**-1)
;
;       -----------------------           -----------------------
;        1  2  3  4  5  6  7  8           40  8 48 16 56 24 64 32
;        9 10 11 12 13 14 15 16           39  7 47 15 55 23 63 31
;       17 18 19 20 21 22 23 24           38  6 46 14 54 22 62 30
;       25 26 27 28 29 30 31 32           37  5 45 13 53 21 61 29
;       33 34 35 36 37 38 39 40    ->     36  4 44 12 52 20 60 28
;       41 42 43 44 45 46 47 48           35  3 43 11 51 19 59 27
;       49 50 51 52 53 54 55 56           34  2 42 10 50 18 58 26
;       57 58 59 60 61 62 63 64           33  1 41  9 49 17 57 25
;       -----------------------           -----------------------
;
FinalPermutation PROC C USES ebx edi esi

        PERMUTATION_START               OFFSET P_Block, OFFSET outBitField
        PERMUTATION_BIT_MATRIX          40, 8, 48, 16, 56, 24, 64, 32, \
                                        39, 7, 47, 15, 55, 23, 63, 31, \
                                        38, 6, 46, 14, 54, 22, 62, 30, \
                                        37, 5, 45, 13, 53, 21, 61, 29, \
                                        36, 4, 44, 12, 52, 20, 60, 28, \
                                        35, 3, 43, 11, 51, 19, 59, 27, \
                                        34, 2, 42, 10, 50, 18, 58, 26, \
                                        33, 1, 41,  9, 49, 17, 57, 25
        PERMUTATION_END


        mov     edi, OFFSET P_Block     ; P_Block <- outBitField
        mov     esi, OFFSET outBitfield
        INVOKE  MemCpy32, edi, esi, BLOCK_SIZE

        ret
FinalPermutation ENDP

;------------------------------------------------------------------------------
;
;       BuildPermutedChoice1  - Public interface for using 'C' convention
;
;       Entry:
;         ebx = pointer to the caller's secret key (64 bit)
;
;       Exit:
;         cs:KeyBuf = 7 bytes (56 bit) secret key of permuted choice 1
;
;       Modifies:
;         ax ecx flags
;
;       Description:
;         Get a 64-bit key from the user. Create a new 56-bit key
;         by discarding the parity bits (every 8th bit) and
;         reordering the bits according to the pattern as defined
;         in DES Permutation Choice 1 (PC-1).
;
;         Note: For a key to have the correct parity, each byte
;               should have an odd number of 1s.
;
BuildPermutedChoice1 PROC C USES ebx esi edi
        mov     edi, OFFSET inBitField  ; Get 64-bit key: inBitField <- gs:bx
        INVOKE  MemCpy32, edi, ebx, BLOCK_SIZE

;
;  Create a 56-bit DES key of Permutation Choice 1 (PC-1)
;
        PERMUTATION_START               OFFSET inBitField, OFFSET KeyBuf
        PERMUTATION_BIT_MATRIX          57, 49, 41, 33, 25, 17,  9, \
                                         1, 58, 50, 42, 34, 26, 18, \
                                        10,  2, 59, 51, 43, 35, 27, \
                                        19, 11,  3, 60, 52, 44, 36, \
                                        63, 55, 47, 39, 31, 23, 15, \
                                         7, 62, 54, 46, 38, 30, 22, \
                                        14,  6, 61, 53, 45, 37, 29, \
                                        21, 13,  5, 28, 20, 12,  4
        PERMUTATION_END

        ret
BuildPermutedChoice1 ENDP

;------------------------------------------------------------------------------
;
;       kinit - Build a DES KeyArray shedule (encrypt/decipher)
;
;       Entry:
;         _key
;         _edf = 0: ENCRYPT
;         _edf = 1: DECIPHER
;
;       Exit:
;         _key, containing 16 permuted keys according to PC-2
;
;       Modifies:
;         ax ecx
;
;       Description:
;         Permutes the key according to the DES specification amd creates
;         an array of 16 keys, each key suits for a corresponding DES round.
;
kinit PROC C PUBLIC USES ebx edi esi, _key:DWORD, _edf:DWORD

        mov     ebx, DWORD PTR _key
        call    BuildPermutedChoice1    ; Discard key parity and permute key

        mov     ecx, 16                 ; Init DES loop counter for 16 loops

BuildKey:                               ; Loop of the data Encrypt algorithm
;
; 1) Split the key into two halves and rotate it according to the DES.
;
        call    LeftRotateKey           ; Rotate the key to the left

;
; 2) The process is the same for ENCRYPTION and DECIPHER, except that the key
;   order must be reversed. That is, when applying K[1] for the first encryption
;   iteration, and then K[2] for the second, on to K[16] - apply K[16] for the
;   first decipher iteration, and then K[15] for the second, on to K[1].
;   The steps below prepare and fill the KeyArray appropriately, depending on
;   the selected DES mode. It's just like locking or unlocking a door: Turn the
;   Key to lock, turn it reverse in order to unlock.
;
        mov     edi, ecx                ; DECIPHER: Reverse key
        dec     edi                     ; Calculate array index

        cmp     DWORD PTR _edf, ENCRYPT ; Test the DES mode
        jne     @F                      ; Build a key for decipher

        mov     edi, 16                 ; ENCRYPT: Normal key
        sub     edi, ecx                ; Calculate array index
@@:
        shl     edi, 3                  ; *8 (multiply by BLOCK_SIZE)
        add     edi, OFFSET KeyArray    ; Calculate KeyArray[i] pointer
                                        ;  where to put the next key element.
;
; 3) Create a new 48-bit key by reordering 48 bits of the 56-bit shifted key
;    according to the pattern as defined in DES Permutation Choice 2 (PC-2).
;
; Note: The key bits 9, 18, 22, 25, 35, 38, 43, 54 are not used in DES PC-2.
; For simplification the macro permutes the key into the lower 6 bits
; of 8 bytes.
;
        PERMUTATION_START               OFFSET KeyBuf, edi
        PERMUTATION_BIT_MATRIX          , , 14, 17, 11, 24,  1,  5, \
                                        , ,  3, 28, 15,  6, 21, 10, \
                                        , , 23, 19, 12,  4, 26,  8, \
                                        , , 16,  7, 27, 20, 13,  2, \
                                        , , 41, 52, 31, 37, 47, 55, \
                                        , , 30, 40, 51, 45, 33, 48, \
                                        , , 44, 49, 39, 56, 34, 53, \
                                        , , 46, 42, 50, 36, 29, 32
        PERMUTATION_END

        dec     ecx
        jnz     BuildKey                ; Loop until all 16 keys are created

        ret                             ; Return the key elements in KeyArray
kinit ENDP

;------------------------------------------------------------------------------
;
;       LeftRotateKey
;
;       Entry:
;         cx = LoopCntDES, KeyBuf
;         1st half bits [1:28]  -  2nd half bits [29:56]
;
;       Exit:
;
;       Description:
;         We have 56 bits of key in KeyBuf..KeyBuf+6. Rotate left
;         the two 28 bits halves (split is in the middle of KeyBuf+3).
;         We do the shift all-at-once and deal with the carry bits
;         of the halves.
;
;         Note: Some implementations vary the DES and right-rotate the key.
;               For these applications just rewrite this routine to meet your
;               specific needs.
;
;
;   Number of DES rotations depend on the current loop count:
;
;   # Rotations:    1  1  2  2  2  2  2  2  1  2  2  2  2  2  2  1  -
;   LoopCntDES:    10  F  E  D  C  B  A  9  8  7  6  5  4  3  2  1  0
;
ShiftTableDES:
        DB      1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 ; DES shifts per loop


LeftRotateKey PROC C USES ebx edi esi ecx
        mov     ax, cx                  ; Get DES loop counter
        neg     al                      ; Calculate index for DES shift table
                                        ;  count 16..1  -> index 0..15
        and     al, 0Fh                 ; Mask significant bits
        mov     ebx, OFFSET ShiftTableDES; Init pointer to access shift table
        xlat    BYTE PTR [ebx]          ; Get number of shifts for this loop
        movzx   ecx, al                 ; Load DES shift counter

LRotateKey:
        push    ecx                     ; Save number of DES shifts

        mov     esi, OFFSET KeyBuf      ; Init pointer to KeyBuf
        bt      DWORD PTR [esi], 27     ; Initial key bit 28
        lahf                            ; Save CY

        mov     ecx, BLOCK_SIZE-1       ; Size of key
        add     esi, ecx                ; Point to end of the key

LRotateKey_1:
        dec     esi                     ; Move KeyBuf pointer
        mov     al, [esi]               ; Read KeyBuf
        sahf                            ; Restore the bit to feed into CY
        rcl     al, 1                   ; Rotate the key byte
        lahf                            ; Save the carry bit
        mov     [esi], al               ; Store KeyBuf
        loop    LRotateKey_1            ; Do all key bytes

        btr     DWORD PTR [esi], 28     ; Assume NC
        sahf                            ; Restore the bit to feed
        jnc     @F                      ; CY set?
        bts     DWORD PTR [esi], 28     ; Put carry into key bit 29
@@:
        pop     ecx                     ; Restore number of DES shifts
        loop    LRotateKey              ; Rotations according to shift table

        ret                             ; Done
LeftRotateKey ENDP

;------------------------------------------------------------------------------
;
;       desAlgorithm - Encrypt/Decipher an 8 byte data block using DES
;                      Public interface for using 'C' convention
;
;       Entry:
;         KeyArray = (k[n]): 16*56 bits (DECIPHER or ENCRYPT)
;         esi = Pointer to an 8 byte-block of input text
;         edi = Pointer to an output buffer intercepting encrypted or plain text
;
;       Exit:
;         edi = pointer to the plain text (p) or the encrypted text (c)
;
;       Modified:
;         ax, all other registers are preserved
;
;       Description:
;         This is the DES algorithm encrypt/decipher routine.
;         The key shedule has been created previously by the
;         procedure "BuildKeyArray". Depending on the KeyArray the
;         algorithm will encrypt or decipher an 8-byte block of data.
;
desAlgorithm PROC C USES ebx edi esi ecx, inbuf:DWORD, outbuf:DWORD
        mov     esi, DWORD PTR inbuf
        mov     edi, DWORD PTR outbuf

        push    edi                     ; Save pointer to interception buffer
;
; Get the input data and split the data into L_block + R_Block.
;
        mov     edi, OFFSET L_Block     ; Get data - L_Block+R_Block <- ds:si
        INVOKE  MemCpy32, edi, esi, BLOCK_SIZE

;
; Perform the initial permutation (IP) on the data block
; and split the permuted data into L_block + R_Block.
; Note: Some implementations omit this step. Just put a comment in
;       front of the CALL below to comply your specific application.
;
        call    InitialPermutation      ; Permute L_Block and build (IP)

;
; Init and run the DES algorithm
;
        mov     ecx, 16                 ; Init DES loop counter for 16 loops

AlgorithmNextBlock:
;
; Next permute the data bits according to the E-Table (E) and build up indexes
; of 6 bits each needed to access the S-Boxes later.
; For simplification the macro permutes the data into the lower 6 bits
; of a byte. The E-Table consists of 8 bytes.
;
; 3) Expansion (E) table block:
;
        PERMUTATION_START               OFFSET R_Block, OFFSET outBitField
        PERMUTATION_BIT_MATRIX          , , 32,  1,  2,  3,  4,  5, \
                                        , ,  4,  5,  6,  7,  8,  9, \
                                        , ,  8,  9, 10, 11, 12, 13, \
                                        , , 12, 13, 14, 15, 16, 17, \
                                        , , 16, 17, 18, 19, 20, 21, \
                                        , , 20, 21, 22, 23, 24, 25, \
                                        , , 24, 25, 26, 27, 28, 29, \
                                        , , 28, 29, 30, 31, 32,  1
        PERMUTATION_END


;
; 4) XOR the E-Block with the corresponding PC-2 key:
;
        mov     edi, OFFSET outBitField ; outBitField <- outBitField XOR KeyPC2
        mov     esi, OFFSET KeyArray
        mov     eax, ecx                        ; Get DES number of round
        neg     eax                     ; Calculate index for the current key
                                        ;  count 16..1  -> index 0..15
        and     eax, 000Fh              ; Mask significant bits
        shl     eax, 3                  ;*8
        add     esi, eax                        ; Apply the key
        INVOKE  MemXor16, edi, esi, BLOCK_SIZE


;
; 5) S-Box substitution:
;
        mov     edi, OFFSET outBitField ; Init pointer to S-Box Index array
        call    SubstitutionBox         ; Substitute: outBitField <- S-Boxes


;
; 6) Permutation (P) of the S-Box values:
;
        PERMUTATION_START              OFFSET outBitField, OFFSET P_Block
        PERMUTATION_32BIT_BLOCK        16,  7, 20, 21
        PERMUTATION_32BIT_BLOCK        29, 12, 28, 17
        PERMUTATION_32BIT_BLOCK         1, 15, 23, 26
        PERMUTATION_32BIT_BLOCK         5, 18, 31, 10
        PERMUTATION_32BIT_BLOCK         2,  8, 24, 14
        PERMUTATION_32BIT_BLOCK        32, 27,  3,  9
        PERMUTATION_32BIT_BLOCK        19, 13, 30,  6
        PERMUTATION_32BIT_BLOCK        22, 11,  4, 25
        PERMUTATION_END


;
; 7) We finished a Decipher/Encryption round.
;    Now XOR with the other half of the data.
;
        mov     edi, OFFSET P_Block     ; P_Block <- P_Block XOR L_Block
        mov     esi, OFFSET L_Block
        INVOKE  MemXor16, edi, esi, BLOCK_SIZE/2

;
; 8) Re-organize the Left and Right halves
;
        mov     edi, OFFSET L_Block     ; L_Block <- R_Block
        mov     esi, OFFSET R_Block
        INVOKE  MemCpy32, edi, esi, BLOCK_SIZE/2

        mov     edi, OFFSET R_Block     ; R_Block <- P_Block
        mov     esi, OFFSET P_Block
        INVOKE  MemCpy32, edi, esi, BLOCK_SIZE/2

        dec     ecx
        jnz     AlgorithmNextBlock      ; Loop the next DES round

;
; Finally perform the inverse permutation on the data block (IP**-1)
; Note: Some implementations omit this step. Just put a comment in
;       front of the next CALL to comply your specific application.
;
        call    FinalPermutation        ; Permute P_Block and build (IP**-1)

;
; Transfer the result into the user's interception buffer.
;
        pop     edi                     ; Restore pointer to interception buffer
        mov     esi, OFFSET P_Block     ; Transfer the result - es:di <- P_Block
        INVOKE  MemCpy32, edi, esi, BLOCK_SIZE

        ret                             ; Done
desAlgorithm ENDP

;------------------------------------------------------------------------------
;
;       SubstitutionBox - sBox substitution
;
;       Entry:
;         edi = Pointer to start of buffer intercepting the substituion values
;
;       Exit:
;         edi = Pointer to end of buffer containing the substituion values
;
;       Modified:
;         ax, edi
;
;       Description:
;         For a block of data the "DES S-Box" substitution is performed.
;
SubstitutionBox PROC C USES ebx esi ecx edx
        mov     ebx, OFFSET SBoxTable   ; Address the substitution-box table
        mov     dl, (-1 SHL 5)          ; Init S-Box offset
        mov     ecx, BLOCK_SIZE         ; Number of substitutions

SubstituteBox:                          ; DES Substitution
        add     dl, (1 SHL 5)           ; Increment S-Box counter (0..7)

        mov     al, BYTE PTR [edi]      ; Get index into SBox table
                                        ;  and calculate the entry's address
        and     al, 00111111b           ; 0  0  r1 c3 c2 c1 c0 r0
        btr     ax, 5                   ; Reset S-Box bit: row1 and save in CY
        jnc     @F
        bts     ax, 6                   ; Init S-Box bit: row1 into bit 6
@@:                                     ; 0  r1 0  c3 c2 c1 c0 r0
        shr     al, 1                   ; 0  0  r1 0  c3 c2 c1 c0   Carry = r0
        jnc     @F
        bts     ax, 4                   ; Init S-Box bit: row0 into bit 4
@@:                                     ; 0  0  r1 r0 c3 c2 c1 c0
        shr     al, 1                   ; 0  0  0  r1 r0 c3 c2 c1   Carry = c0
        lahf                            ; Save c0

        or      al, dl                  ; Build offset address into S-Box table
        xlat    BYTE PTR [ebx]          ; Read S-Box bits S[n].1 .. S[n].4

        sahf                            ; Restore c0
        jnc     substB_1                ; Even S-Box columns are lsb, odd msb
        rol     al, 4                   ; Store them all as msb (DES notation),
                                        ;  i.e., swap (al).
substB_1:                               ; Here only the upper 4 bits are valid.
        mov     BYTE PTR [edi], al      ; Store substitutes back into inBitField
        inc     edi                     ; Advance ptr to next S-Box index
        loop    SubstituteBox           ; Loop eight S-Boxes

        ret
SubstitutionBox ENDP

;------------------------------------------------------------------------------
;
;       DES Substitution Boxes
;
; The S-Box Table is compressed. An entry is actually 4 bits in size,
; so the even indexes extract the high nibble - the odd extract the low nibble.
; The table is organized just as described in the common DES documentations.
; It is very easy to survey and understand.
;
; Half-bytes are organized as shown below:
;
;            msb  lsb    msb      lsb
;       E4 =  14,  4  =  S[1][0], S[1][1]
;       D1 =  13,  1  =  S[1][2], S[1][3]
;       2F =   2, 15  =  S[1][4], S[1][5]
;       B8 =  11,  8  =  S[1][6], S[1][7]
;       ..    ..  ..      ...       ...
;
; The SBoxTable is accessed by a 6-bit index:
;
;       [ *  *  r1 c3 c2 c1 c0 r0 ]
;
;        Bits r1r0 = [5,0] select one of 4 rows in a box
;        Bits c3..c0 = [4:1] select one of 16 colums in a box
;
;       Within a loop all eight S-Boxes are consulted for DES substitution.
;
;       Depending on the selection either the lsb or the msb from the
;       table value (column) is used for substitution (see DES specification).
;
;
SBoxTable:
;
; S[1]    c0  c1  c2  c3  c4  c5  c6  c7  c8  c9  cA  cB  cC  cD  cE  cF
;
  S_BOX   14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7   ; r0
  S_BOX    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8   ; r1
  S_BOX    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0   ; r2
  S_BOX   15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13   ; r3


;
; S[2]
;
  S_BOX   15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10
  S_BOX    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5
  S_BOX    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15
  S_BOX   13,  8,  10, 1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9

;
; S[3]
;
  S_BOX   10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8
  S_BOX   13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1
  S_BOX   13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7
  S_BOX   1,  10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12

;
; S[4]
;
  S_BOX    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15
  S_BOX   13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9
  S_BOX   10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4
  S_BOX   3,  15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14

;
; S[5]
;
  S_BOX    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9
  S_BOX   14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6
  S_BOX    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14
  S_BOX   11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3

;
; S[6]
;
  S_BOX   12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11
  S_BOX   10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8
  S_BOX    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6
  S_BOX    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13

;
; S[7]
;
  S_BOX    4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1
  S_BOX   13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6
  S_BOX    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2
  S_BOX    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12

;
; S[8]
;
  S_BOX   13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7
  S_BOX   01, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2
  S_BOX   07, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8
  S_BOX   02,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11

;------------------------------------------------------------------------------
 _TEXT ENDS
        END
