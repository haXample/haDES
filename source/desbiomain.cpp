// DES Algorithm Encryption Modes for chipcard reader
//
//  ---------------------------------------------------------------------------
// |     Copyright (c)1997-2021  Helmut Altmann                                |
// |     This program contains proprietary and confidential information.       |
// | All rights reserved, except as may be permitted by prior written consent. |
//  ---------------------------------------------------------------------------
//
//  $_GENERAL   : Added function to verify Siemens CardOS M4.01 SmartCards.
//  $_TECHNICAL : Implemented ISO Padded ECB/CBC Modes for Encrypt/Decipher.
//  $_SCOPE     : V1.03
//  $_CHANGEDID : 0002
//  $_DATE      : 06.08.03
//  $_AUTHOR    : HelmutAltmann
//  
//  $_GENERAL   : Did no longer work like PROMBIOS.EXE. This is now fixed.    
//                Ciphertext stealing mistakenly acted on the wrong buffer, 
//                and messed up the last two blocks. When building the PVCS
//                directory obviously a wrong source file has been checked in.
//  $_TECHNICAL : Added check to prevent output file from being accidentally
//                overwritten. Shipped to Phoenix for source encryption.
//  $_SCOPE     : V1.02
//  $_CHANGEDID : 0001
//  $_DATE      : 26.03.03
//  $_AUTHOR    : HelmutAltmann
//  
//  $_GENERAL   : Additional features in conjunction with PROMBIOS.EXE.
//  $_TECHNICAL : Added: CBC-mode for crypto MAC signature
//                Added: Ciphertext Stealing, so the last block must not be
//                padded, when passed through the algorithm. The goal is to
//                keep the size of the encrypted file unaltered.                  
//  $_SCOPE     : V1.01
//  $_CHANGEDID : 0000
//  $_DATE      : 20.02.99
//  $_AUTHOR    : HelmutAltmann
//  
//  $_GENERAL   : Initial coding. ECB Mode only.
//  $_TECHNICAL : 
//  $_SCOPE     : V1.00
//  $_CHANGEDID : 0000
//  $_DATE      : 19.04.97
//  $_AUTHOR    : HelmutAltmann
//  
//  $Revision:   1.6  $
//  $Date:   03 Sep 2003 18:49:50  $
//  $Archive:   H:/UTILITY/ARCHIVE/SNI/TOOLBOX/CRYPTO/DES/DESMAIN.C_v  $
//
//#******************************************************************************
//#
//#   Currently this project can be maintained, compiled and assembled with the
//#   following NMAKE makefile script:
//#
//#  ##########################  START OF MAKEFILE  ############################
//#
//# This is a NMake file for the Project: DESBIO.EXE      01.10.1994 H.A.
//#                 23.04.2021 ha
//#     ----------------------------------
//#    | Invocation:  NMAKE DESBIO.NMK    |
//#     ----------------------------------
//#
//#      C:\Program Files (x86)\Microsoft Visual Studio\2010\BuildTools:  XP SP3
//#
//#  Microsoft (R) Macro Assembler Version 10.00.30319.01
//#  Microsoft (R) C/C++-Optimierungscompiler Version 10.00.30319.01 for x86 XP
//#  Microsoft (R) Incremental Linker Version 10.00.30319.01
//#  Microsoft (R) Program Maintenance Utility, Version 10.00.30319.01
//#
//#      C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools:  Windows 10
//#  Microsoft (R) Macro Assembler Version 14.28.29910.0
//#  Microsoft (R) C/C++-Optimierungscompiler Version 19.28.29910 for x86
//#  Microsoft (R) Incremental Linker Version 14.28.29910.0
//#  Microsoft (R) Program Maintenance Utility, Version 14.28.29910.0
//#
//# Product: DESbio.EXE                                                          
//# Module: desbio.NMK                                                        
//#
//#-------------------------------------------------------------------------------------------
//#                                                                                           |
//# Usage of Visual Studio 2010 x86 Native Build Tools Command Prompt for Windows XP          |     
//# 1) Define a folder where the source resides                                               |
//#     (e.g. c:\Temp600\__\_\_\*.nmk, *.asm, *.cpp, *.obj, *.exe, *.lst *.lnk, ..)           |
//# 2) Edit the path to all sourcefile (fully qualified pathnames) in the *.NMK control file. |
//# 3) Start menu -> Developer Command Prompt for VS 2010 WinXP                               |
//# 3a) New Tools: Start menu -> Visual C++ 2019 x86 Native Build Tools Command Prompt Win10  |
//# 4) Run the command: "NMAKE C:\Temp600\__\_\_\desbio.nmk"                                  |
//# 5) The NMAKE-project will be built correctly                                              |
//#                                                                                           |
//# Usage of Visual C++ 2019 x86 Native Build Tools Command Prompt for Windows10              |
//# 1) Define a folder where the source resides                                               |
//#     (e.g. c:\Temp600\__\_\_\*.nmk, *.asm, *.cpp, *.obj, *.exe, *.lst *.lnk, ..)           |
//# 2) Edit the path to all sourcefile (fully qualified pathnames) in the *.NMK control file. |
//# 3) Start menu -> Developer Command Prompt for VS 2019 (2)                                 |
//# 3a) Older Tools: Start menu -> Visual Studio 2010 x86 Tools Command Prompt (WinXP SP3)    |     
//# 4) Run the command: "NMAKE C:\Temp600\__\_\_\desbio.nmk"                                  |  
//# 5) The NMAKE-project will be built correctly                                              |
//#                                                                                           |
//#-------------------------------------------------------------------------------------------
//
//PROJ = DESbio   # The PARADIGM ASM module
//#PROJ =DESquick   # The C++ module
//#PROJ = DESfast   # The ASM & C++ modules
//
//FOLDER = C:\Temp600\__\     # Folder prefix to the project,
//        #  using 2010 MS Build-tools.
//
//# -------------------
//# GLOBAL TOOL OPTIONS
//# -------------------
//AFLAGS=/nologo /c /Sn /Sg /Sp84 /Fl
//#CFLAGS=/c /nologo /Gs /O2 /MT /Zi /Fades.as
//CFLAGS=/c /nologo /Gs /O2 /MT 
//LFLAGS=
//
//# --------------------------------------------------
//# MACRO DEFINITIONS OF THE OBJECT MODULE DEPEDENCIES
//# --------------------------------------------------
//OBJECTS= $(FOLDER)$(PROJ)main.obj $(FOLDER)$(PROJ).obj
//
//# --------------
//# INFERENCE RULE
//# --------------
//.asm.obj:
//  @ML $(AFLAGS) /Fo$(FOLDER)$(@B).obj /Fl$(FOLDER)$(@B).lst $(FOLDER)$(@B).asm
//
//.cpp.obj:
//  @CL $(CFLAGS) /Fo$(FOLDER)$(@B).obj $(FOLDER)$(@B).cpp
//
//# ------------------------------------------
//# PSEUDO TARGET POINTING TO THE REAL TARGETS
//# ------------------------------------------
//_all: $(FOLDER)$(PROJ).exe
//
//# ---------------
//# PROJECT TARGETS
//# ---------------
//##$(PROJ)DOS.obj:          $(@B).c              # Main program (DOS bio interface)
//
//$(FOLDER)$(PROJ)main.obj:  $(FOLDER)$(@B).cpp   # Main program (Win XP standard user interface)
//
//$(FOLDER)$(PROJ).obj:      $(FOLDER)$(@B).asm   # Additionaly the .ASM module
//
//#-----------------------------------------------------------------------------
//#     $(PROJ) TARGET BUILD
//#-----------------------------------------------------------------------------
//$(FOLDER)$(PROJ).exe:      $(OBJECTS)
//  LINK $(LFLAGS)  /OUT:$@ $(OBJECTS) >$(FOLDER)$(@B).link
//
//   ##########################  END OF MAKEFILE  ##############################
//
//******************************************************************************

#include <io.h>        // File open, close, access, etc.
#include <conio.h>     // For _putch(), _getch() ..
#include <string>      // printf, etc.

#include<sys/stat.h>   // For filesize
#include<iostream>     // I/O control
#include<fstream>      // File control
      
#include <windows.h>   // For console specific functions
      
using namespace std;

//-----------------------------------------------------------------------------
//
#define UCHAR unsigned char
#define UINT unsigned int
#define ULONG unsigned long int

#define FALSE  0
#define TRUE   1
#define ERR   -1

#define ISOPAD 0x80
#define PAD    0x00

#define ENCRYPT             0
#define DECIPHER            1
#define BUILD_ENCRYPT_KEY   2
#define BUILD_DECIPHER_KEY  3
#define PERMUTE_KEY         4
#define FEED_KEY            5

#define DES_ENCRYPT  15
#define DES_DECIPHER 16
#define DES_MAC      17
#define DES_CBCE     18
#define DES_CBCD     19
#define DES_ECBE     20
#define DES_ECBD     21
#define DES_ECBDECIPHER 22
#define DES_ECBENCRYPT  23

#define KEY_LENGTH 8
#define BLOCK_SIZE 8

#define COUNT_RATE 100000L

//----------------------------------------------------------------------------
//
//                          External declarations
//
extern "C" void desAlgorithm (char* p1, char* p2);  // Assembler Module Interface
extern "C" void kinit(char* p, int);                // Assembler Module Interface

//----------------------------------------------------------------------------
//
//                          Global declarations
//
char signon[]      = "DES Crypto Utility, V2.00 (c)1997-2021 by ha\n";
char open_failed[] = "ERROR %s: FILE OPEN FAILED.\n";
char file_exists[] = "ERROR %s: FILE ALREADY EXISTS.\n";//[] vs * ??!
char error_fsize[]      = "ERROR %s: FILE SIZE <> %d?\n";
char error_keysize[]    = "ERROR %s: KEY SIZE <> %d?\n";
char bytes_deciphered[] = "%lu bytes deciphered.\n";
char bytes_encrypted[]  = "%lu bytes encrypted.\n";

char icvblock[BLOCK_SIZE];
char inblock[BLOCK_SIZE], outblock[BLOCK_SIZE], lastblock[2*BLOCK_SIZE];
char keybuf[KEY_LENGTH] = {
  PAD, PAD, PAD, PAD, PAD, PAD, PAD, PAD
  }; // Provide space for key size of 64bits

char inbuf1[BLOCK_SIZE], inbuf2[BLOCK_SIZE];
char outbuf1[BLOCK_SIZE];

UCHAR mode;
int i, j, bytesrd;
ULONG ln, li, lj, ls;
long int srcFileSize;

UINT length;
ofstream outfile; 
streampos pos;                    // for seek test only

//-----------------------------------------------------------------------------
//
//                              DesDoAlgorithmStealECB
//
//  ENCRYPT/DECIPHER - Electronic Code Book (ciphertext stealing)
//
void DesDoAlgorithmStealECB(ifstream &infile, ofstream &outfile)
  {
  li = COUNT_RATE;  ls = srcFileSize;

  bytesrd = BLOCK_SIZE; // init bytesrd, filesize is at least 8 bytes
  while (ln < ls)
    {
    if ((ln+BLOCK_SIZE) > ls) bytesrd = (int)(ls % BLOCK_SIZE);
    ln += (ULONG)bytesrd;

    infile.read(inblock, bytesrd);

    if (bytesrd == BLOCK_SIZE)
      {
      desAlgorithm(inblock, outblock);
      outfile.write(outblock, bytesrd);
      }

    //
    // CIPHERTEXT STEALING:
    // We do not want to change filesizes, so we dont use padding.
    // The following special handling of the last block implements
    // "Ciphertext Stealing" if the last block is less than BLOCK_SIZE.
    // For the last 2 blocks: Des(Pn-1) = Cn||C' and Des(Pn||C') = Cn-1
    //  Note: Pn-1 = Plaintext of BLOCK_SIZE
    //        Pn = Last plaintext < BLOCK_SIZE
    //        C' = Ciphertext padded to Pn, stolen from previous block
    //        Cn-1 = New Ciphertext of BLOCK_SIZE for previous block
    //        Cn = Ciphertext < BLOCKSIZE from previous block, used last.
    //
    // Example: Encrypt Key = 12345678
    //          Pn-1 = 0A 0D 0A 0D 0A 0D 0A 0D   (EF 29 7C 97 61 5B 80 9E)
    //          Pn   = 0A 0D 0A 0D 0A
    //          C'   = 5B 80 9E
    //          Cn-1 = 91 03 D1 32 FA 54 C2 17
    //          Cn   = EF 29 7C 97 61
    //
    //  before: lastblock[] = 00 00 00 00 00 00 00 00 EF 29 7C 97 61 00 00 00
    //          inblock[]   = 0A 0D 0A 0D 0A 5B 80 9E
    //
    //  after:  lastblock[] = 91 03 D1 32 FA 54 C2 17 EF 29 7C 97 61
    //
    else
      {
      for (i = 0; i < bytesrd; i++) lastblock[BLOCK_SIZE + i] = outblock[i];
      for (i = bytesrd; i < BLOCK_SIZE; i++) inblock[i] = outblock[i];

      desAlgorithm (inblock, lastblock);       //@Am0001
      outfile.seekp(0, ios::end); // seek to the end of the file
      outfile.seekp(-BLOCK_SIZE, ios::cur); // back up 8 bytes
      outfile.write(lastblock, bytesrd + BLOCK_SIZE);
      }

//      pos = infile.tellg();
//      cout << "infile: The file pointer is now at location " << pos << endl;
//      pos = outfile.tellp();
//      cout << "outfile: The file pointer is now at location " << pos << ;

    if (ln / li)
      {
      printf("%lu KB\r", ln / 1024L);  // Echo per COUNT_RATE
      li += COUNT_RATE;
      }
    } // end while

  } // DesDoAlgorithmStealECB


//-----------------------------------------------------------------------------
//
//                              DesDoAlgorithmIsoECB
//
//  ENCRYPT/DECIPHER - Electronic Code Book (ISO Padding)
//
void DesDoAlgorithmIsoECB(ifstream &infile, ofstream &outfile)
  {
  int isoPad = 0; j = 0;

  li = COUNT_RATE;  ls = srcFileSize;

  bytesrd = BLOCK_SIZE; // init
  while (ln < ls)
    {

    if ((ln+BLOCK_SIZE) > ls) bytesrd = (int)(ls % BLOCK_SIZE);
    ln += (ULONG)bytesrd;

    infile.read(inblock, bytesrd);

    if (bytesrd == BLOCK_SIZE)
      {
      desAlgorithm(inblock, outblock);

      if (mode == DES_ECBE) outfile.write(outblock, BLOCK_SIZE); // Write all blocks
      else if ((mode == DES_ECBD) && (ln != ls))
        {
        outfile.write(outblock, BLOCK_SIZE);     // Write all blocks, except the last block
        }

      else if ((mode == DES_ECBD) && (ln == ls)) // Last block requires special handling
        {                                        // Either a whole block of padding
        j=BLOCK_SIZE;                            //  or a partly padded block
                                                 
//printf("--DES_ECBD: %02X %02X %02X %02X %02X %02X %02X %02X \n",
//       (UCHAR)outblock[0], (UCHAR)outblock[1], (UCHAR)outblock[2], (UCHAR)outblock[3],
//       (UCHAR)outblock[4], (UCHAR)outblock[5], (UCHAR)outblock[6], (UCHAR)outblock[7]);
//printf("[bytesrd=%d, ln=%ld, ls=%ld, j=%ld]\n", bytesrd,ln,ls,j);

        for (i=0; i<BLOCK_SIZE; i++)
          {
          j--;
//printf("--DES_ECBD: %02X\n", outblock[j]);
          if (outblock[j] == 0xFFFFFF80)       // ISOPAD rendered as long int ????
            {  
            break;
            }
          }

//printf("--DES_ECBD: %02X j=%d\n", outblock[j], j);
        outfile.write(outblock, j);     // Write until ISOPAD
        ln += ((ULONG)j - BLOCK_SIZE);           // Adjust (decipher) filesize count
        break; // Stop while loop if ISOPAD
        }
      }

    //
    // ISO PADDING:
    // Using ISO padding we always increase the filesize.
    // The following handling of the last block implements ISO Padding.
    // For the last block: Des(Pn) = Cn||PB
    //  Note: Pn = Plaintext of <=BLOCK_SIZE
    //        Cn = Ciphertext > Pn, padded to BLOCKSIZE or appended with BLOCKSIZE.
    //
    // Example1: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A
    //           Pn||PB  = 0A 0D 0A 0D 0A 80 00 00
    //           Cn      = xx xx xx xx xx xx xx xx
    //
    // Example2: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A 12 34 45
    //           Pn||PB  = 0A 0D 0A 0D 0A 12 34 45 80 00 00 00 00 00 00 00    
    //           Cn      = xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
    //
    else // bytesrd < BLOCK_SIZE
      {
      //
      // The last block is padded.
      //
      inblock[bytesrd] = ISOPAD;
      for (i=bytesrd+1; i<BLOCK_SIZE; i++) inblock[i] = PAD;

//printf("DES_ECBin: %02X %02X %02X %02X %02X %02X %02X %02X \n",
//       (UCHAR)inblock[0], (UCHAR)inblock[1], (UCHAR)inblock[2], (UCHAR)inblock[3],
//       (UCHAR)inblock[4], (UCHAR)inblock[5], (UCHAR)inblock[6], (UCHAR)inblock[7]);
//printf("[bytesrd=%d, ln=%ld, ls=%ld]\n", bytesrd,ln,ls);

      desAlgorithm (inblock, outblock);

//printf("DES_ECBout: %02X %02X %02X %02X %02X %02X %02X %02X \n",
//       (UCHAR)outblock[0], (UCHAR)outblock[1], (UCHAR)outblock[2], (UCHAR)outblock[3],
//       (UCHAR)outblock[4], (UCHAR)outblock[5], (UCHAR)outblock[6], (UCHAR)outblock[7]);
//printf("[bytesrd=%d, ln=%ld, ls=%ld]\n", bytesrd,ln,ls);

      outfile.write(outblock, BLOCK_SIZE);
      ln += BLOCK_SIZE-bytesrd;
      isoPad = 1;
      }

    if (ln / li)
      {
      printf("%lu KB\r", ln / 1024L);  // Echo per COUNT_RATE
      li += COUNT_RATE;
      }
    } // end while

  if ((mode == DES_ECBE) && (isoPad == 0)) // Need to add a whole padding block
    {                                      // Does not apply to encrypted text
    inblock[0]=ISOPAD;                     //  which is always padded MOD(8)
    for (i=1; i<BLOCK_SIZE; i++) inblock[i] = PAD;

//printf("++DES_ECBin: mode=%d, isoPad=%d, %02X %02X %02X %02X %02X %02X %02X %02X \n", mode, isoPad,
//       (UCHAR)inblock[0], (UCHAR)inblock[1], (UCHAR)inblock[2], (UCHAR)inblock[3],
//       (UCHAR)inblock[4], (UCHAR)inblock[5], (UCHAR)inblock[6], (UCHAR)inblock[7]);
//printf("[bytesrd=%d, ln=%ld, ls=%ld]\n", bytesrd,ln,ls);

    desAlgorithm (inblock, outblock);

//printf("++DES_ECBout: %02X %02X %02X %02X %02X %02X %02X %02X \n",
//       (UCHAR)outblock[0], (UCHAR)outblock[1], (UCHAR)outblock[2], (UCHAR)outblock[3],
//       (UCHAR)outblock[4], (UCHAR)outblock[5], (UCHAR)outblock[6], (UCHAR)outblock[7]);
//printf("[bytesrd=%d, ln=%ld, ls=%ld]\n", bytesrd,ln,ls);

    outfile.write(outblock, BLOCK_SIZE);
    ln += BLOCK_SIZE;                      // Adjust (decipher) filesize count
    }
  } // DesDoAlgorithmIsoECB


//------------------------------------------------------------------------------
//
//                              DesDoAlgorithmStealCBCE
//
//  ENCRYPT - Cipher Block Chaining (Ciphertext Stealing)
//               
void DesDoAlgorithmStealCBCE(ifstream &infile, ofstream &outfile)
  {
  int ciphStealing = FALSE;

  li = COUNT_RATE; ln = 0; lj = srcFileSize;
  do
    {
    if (ciphStealing == TRUE) break;                   // ciphStealing -break

    if ((lj - ln) >= BLOCK_SIZE) bytesrd = BLOCK_SIZE; // Keep track of bytesrd,    
    else bytesrd = lj - ln;                            //  ifstream won't tell us   
    infile.read(inblock, bytesrd);                     // Read from input file

    if (bytesrd >= BLOCK_SIZE)
      for (i = 0; i < BLOCK_SIZE; i++) inblock[i] ^= icvblock[i]; // CBC: inbuf XOR ICV

    else if (bytesrd < BLOCK_SIZE)                                // Ciphertext stealing
      {
      for (i = 0; i < BLOCK_SIZE-bytesrd; i++) inblock[i+bytesrd] = PAD; // Pn* = Pn||0s (zero-padded) 
      for (i = 0; i < BLOCK_SIZE; i++) inblock[i] ^= outblock[i];        // Pn* XOR Cn-1*
      for (i = 0; i < BLOCK_SIZE; i++) outbuf1[i] = outblock[i];         // save Cn-1

      // CIPHERTEXT STEALING CBC ENCRYPT:
    // We do not want to change filesizes, so we dont use padding.
    // The following special handling of the last block implements
    // "Ciphertext Stealing" if the last block is less than BLOCK_SIZE.
      // For the last 2 blocks: Des(Pn-1) = Cn||C' and Des(Pn||C') = Cn-1
      //  Note: Pn-1      = Previous Plaintext of BLOCK_SIZE
    //        Pn = Last plaintext < BLOCK_SIZE
      //        Pn*       = Last plaintext padded with zeros
      //        Cn-1      = Previous Ciphertext of Pn-1
      //        Cn-1*     = Ciphertext padded to Pn, stolen from previous block
      //        Cn-1(new) = New Ciphertext of BLOCK_SIZE for previous block
      //        Cn-1**    = Ciphertext < BLOCKSIZE from previous block, used last.
    //
    // Example: Encrypt Key = 12345678
      //          Pn-1   = 0A 0D 0A 0D 0A 0D 0A 0D
      //          Cn-1   = F5 AC DD BE 5F 21 C0 2B
    //          Pn   = 0A 0D 0A 0D 0A
      //          Cn-1*  = 21 C0 2B
      //          Cn-1** = F5 AC DD BE 5F
    //
      // Steps:   Pn* = Pn||0s = 0A 0D 0A 0D 0A 00 00 00  (zero-padded)
      //          Pn* ^ Cn-1   = FF A1 D7 B3 55 21 C0 2B  (inblock to be encrypted
      //          Cn-1(new)    = 72 F6 82 BA DA D8 88 91    yields a new previous Block)
      //          Cn-1**       = F5 AC DD BE 5F           (lastblock < BLOCK_SIZE)
    //
      //  before: lastblock[] = 00 00 00 00 00 00 00 00 F5 AC DD BE 5F 00 00 00
      //          inblock[]   = FF A1 D7 B3 55 21 C0 2B
    //
      //  after:  lastblock[] = 72 F6 82 BA DA D8 88 91 F5 AC DD BE 5F [Cn-1(new) || Cn-1**]
      //
      ciphStealing = TRUE;
      } // end else if

    // ---------------------------------------------
    // Performing the DES (i.e., Standard Algorithm)
    // ---------------------------------------------
    desAlgorithm(inblock, outblock);                                    // 1st step
    if (ciphStealing == TRUE)
      {
      // Build the last block(s) [Cn-1(new) || Cn-1**],
      //  where Cn-1(new) consists of the encrypted incomplete block of Pn
      //  and the stolen chunk Cn-1* which has been encrypted twice.
      //
      for (i = 0; i < BLOCK_SIZE; i++) lastblock[i] = outblock[i];          // Cn-1(new)
      for (i = 0; i < bytesrd; i++) lastblock[BLOCK_SIZE + i] = outbuf1[i]; // Cn-1**
      }

    ln += (ULONG)bytesrd;                            // Update counter total bytes read

    // ------------------------------------------------
    // Special processing after applying the TDES steps
    // ------------------------------------------------
    if (ciphStealing == FALSE)
      {
      outfile.write(outblock, bytesrd);                       // Write Ci..Cn
      for (i=0; i<BLOCK_SIZE; i++) icvblock[i] = outblock[i]; // Update ICV
      }
    else if (ciphStealing == TRUE)                     
      {
      outfile.seekp(0, ios::end);                     // seek to end of the file
      outfile.seekp(-BLOCK_SIZE, ios::cur);           // back up 8 bytes
      outfile.write(lastblock, bytesrd + BLOCK_SIZE); // Write [Cn-1 || Cn]
      break;
      }

    if (ln / li)
      {
      printf("%lu KB\r", ln / 1024L);  // Echo per COUNT_RATE
      li += COUNT_RATE;
      }
    } // end do while
  while (ln < lj);
  } // DesDoAlgorithmStealCBCE


//------------------------------------------------------------------------------
//
//                              DesDoAlgorithmStealCBCD
//
//  DECIPHER - Cipher Block Chaining (Ciphertext Stealing)
//
void DesDoAlgorithmStealCBCD(ifstream &infile, ofstream &outfile)
  {
  int ciphStealing = FALSE;

  li = COUNT_RATE; ln = 0; lj = srcFileSize;
  do
    {
    if (ciphStealing == TRUE) break;                   // ciphStealing - break

    if ((lj - ln) >= BLOCK_SIZE) bytesrd = BLOCK_SIZE; // Keep track of bytesrd,    
    else bytesrd = lj - ln;                            //  ifstream won't tell us   
    infile.read(inblock, bytesrd);                     // Read from input file

    if ((lj-ln) > 2*BLOCK_SIZE && (lj % BLOCK_SIZE) != 0) 
      for (i=0; i<BLOCK_SIZE; i++) inbuf2[i] = inblock[i]; // CBC save Cn-2 block

    if (bytesrd == BLOCK_SIZE)
      for (i=0; i<BLOCK_SIZE; i++) inbuf1[i] = inblock[i]; // CBC save 1st block

    else if (bytesrd < BLOCK_SIZE)
      {
      // CIPHERTEXT STEALING CBC DECIPHER:
    // We do not want to change filesizes, so we dont use padding.
    // The following special handling of the last block implements
    // "Ciphertext Stealing" if the last block is less than BLOCK_SIZE.
    // For the last 2 blocks: Des(Pn-1) = Cn||C' and Des(Pn||C') = Cn-1
      //  Note: Pn-1      = Previous Plaintext of BLOCK_SIZE
    //        Pn = Last plaintext < BLOCK_SIZE
      //        Pn*       = Last plaintext padded with zeros
      //        Cn-1      = Previous Ciphertext of Pn-1
      //        Cn-1*     = Ciphertext padded to Pn, stolen from previous block
      //        Cn-1(new) = New Ciphertext of BLOCK_SIZE for previous block
      //        Cn-1**    = Ciphertext < BLOCKSIZE from previous block, used last.
    //
      // Example: Decipher Key = 12345678
      //          Cn-1(new) = 72 F6 82 BA DA D8 88 91  (Previous block)
      //          Cn-1*     = 21 C0 2B
      //          Cn-1**    = F5 AC DD BE 5F           (Last block)
    //
      // Steps:   Cn-1(new)                = 72 F6 82 BA DA D8 88 91  (partly encrypted twice)
      //          Pn* ^ Cn-1               = FF A1 D7 B3 55 21 C0 2B  (deciphered once)
      //          Cn-1 = Cn-1** || Cn-1*   = F5 AC DD BE 5F 21 C0 2B
      //          Must save Cn-1           =[F5 AC DD BE 5F 21 C0 2B]
      //          Pn-1                     = 0A 0D 0A 0D 0A 0D 0A 0D  (Pn-1 deciphered)
      //          Pn = (Pn* ^ Cn-1) ^ Cn-1 = 0A 0D 0A 0D 0A           (Pn lastblock deciphered)
    //
      //  before: lastblock[] = F5 AC DD BE 5F 21 C0 2B F5 AC DD BE 5F 21 C0 2B
      //  after:  outblock[]  = 0A 0D 0A 0D 0A 0D 0A 0D                          (Decipher)
    //
      //  before: lastblock[] = FF A1 D7 B3 55 21 C0 2B F5 AC DD BE 5F 21 C0 2B
      //  after:  lastblock[] = 0A 0D 0A 0D 0A 00 00 00 F5 AC DD BE 5F 21 C0 2B  (XOR)
      //
      for (i = 0; i < BLOCK_SIZE; i++) lastblock[i] = lastblock[BLOCK_SIZE + i];
      for (i = 0; i < bytesrd; i++)    lastblock[i] = inblock[i];

      desAlgorithm(lastblock, outblock);                      // 1st step

      for (i = 0; i < BLOCK_SIZE; i++) outblock[i]  ^= inbuf2[i];
      for (i = 0; i < BLOCK_SIZE; i++) lastblock[i] ^= lastblock[BLOCK_SIZE + i];

      for (i = 0; i < BLOCK_SIZE; i++) lastblock[i+BLOCK_SIZE] = lastblock[i];  // swap Pn-1
      for (i = 0; i < BLOCK_SIZE; i++) lastblock[i] = outblock[i];              // concatenate Pn chunk

      ciphStealing = TRUE;
      } // end else if                                                                

    // ---------------------------------------------
    // Performing the DES (i.e., Standard Algorithm)
    // ---------------------------------------------
    if (ciphStealing == FALSE)
      {
      desAlgorithm(inblock, outblock);             // 1st step
      if (bytesrd == BLOCK_SIZE && ciphStealing == FALSE)
        for (i=0; i<BLOCK_SIZE; i++) inblock[i] = outblock[i];
      }

    ln += (ULONG)bytesrd;                             // Update counter total bytes read
    
    // ------------------------------------------------
    // Special processing after applying the TDES steps
    // ------------------------------------------------
    if (ciphStealing == FALSE)
      {
      for (i=0; i<BLOCK_SIZE; i++) lastblock[BLOCK_SIZE+i] = outblock[i];  // Save Cn-1
      for (i=0; i<BLOCK_SIZE; i++) outblock[i] ^= icvblock[i]; // CBC specific XOR function
      for (i=0; i<BLOCK_SIZE; i++) icvblock[i]  = inbuf1[i];   // CBC copy 1st block
      outfile.write(outblock, bytesrd);
      }
    else
      {
      outfile.seekp(0, ios::end);                     // seek to end of the file
      outfile.seekp(-BLOCK_SIZE, ios::cur);           // back up 8 bytes
      outfile.write(lastblock, bytesrd + BLOCK_SIZE); // Write [Pn-1 || Pn]
      break;
      }

    if (ln / li)
      {
      printf("%lu KB\r", ln / 1024L);  // Echo per COUNT_RATE
      li += COUNT_RATE;
      }
    } // end do while
  while (ln < lj);
  } // DesDoAlgorithmStealCBCD


//------------------------------------------------------------------------------
//
//                              DesDoAlgorithmIsoCBCE
//
//  ENCRYPT - Cipher Block Chaining (ISO Padding)
//
void DesDoAlgorithmIsoCBCE(ifstream &infile, ofstream &outfile)
  {
  li = COUNT_RATE;  ls = srcFileSize; ln = 0;
  int isoPad = PAD;

  //
  // CBC specific initial chaining vector init function
  //
  for (i=0; i<BLOCK_SIZE; i++) outblock[i] = 0;       // CBC Init ICV

  bytesrd = BLOCK_SIZE; // init
  while (ln < ls)
    {
    if ((ln+BLOCK_SIZE) > ls) bytesrd = (int)(ls % BLOCK_SIZE);
    ln += (ULONG)bytesrd;

    infile.read(inblock, bytesrd);

    if (bytesrd == BLOCK_SIZE)
      {
      //
      // CBC specific XOR function
      //
      for (i=0; i<BLOCK_SIZE; i++) inblock[i] ^= icvblock[i]; // CBC; inbuf XOR ICV

      desAlgorithm(inblock, outblock);
      outfile.write(outblock, bytesrd);

      for (i=0; i<BLOCK_SIZE; i++) icvblock[i] = outblock[i]; // Update ICV
      }

    //
    // ISO PADDING:
    // Using ISO padding we always increase the filesize.
    // The following handling of the last block implements ISO Padding.
    // For the last block: Des(Pn) = Cn||PB
    //  Note: Pn = Plaintext of <=BLOCK_SIZE
    //        Cn = Ciphertext > Pn, padded to BLOCKSIZE or appended with BLOCKSIZE.
    //
    // Example1: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A
    //           Pn||PB  = 0A 0D 0A 0D 0A 80 00 00
    //           Cn      = xx xx xx xx xx xx xx xx
    //
    // Example2: Encrypt Key = 12345678
    //           Pn      = 0A 0D 0A 0D 0A 12 34 45
    //           Pn||PB  = 0A 0D 0A 0D 0A 12 34 45 80 00 00 00 00 00 00 00    
    //           Cn      = xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx
    //
    else
      {
      //
      // The last block is padded.
      //
      inblock[bytesrd] = ISOPAD;
      for (i=bytesrd+1; i<BLOCK_SIZE; i++) inblock[i] = PAD;

      //
      // CBC specific XOR function
      //
      for (i=0; i<BLOCK_SIZE; i++) inblock[i] ^= outblock[i]; // CBC XOR

      desAlgorithm (inblock, outblock);
      outfile.write(outblock, BLOCK_SIZE);
      ln += BLOCK_SIZE-bytesrd;
      isoPad = 1;
      }

    if (ln / li)
      {
      printf("%lu KB\r", ln / 1024L);  // Echo per COUNT_RATE
      li += COUNT_RATE;
      }
    } // end while

  //
  // Encrypt and decipher modes must be handled differently.
  // Encrypt: If the srcFileSize is a multiple of BLOCK_SIZE we must append
  //          a whole block of ISO padding.
  // Decipher: Nothing to do, no final check required.
  //
  if (isoPad == 0)                         // Need to add a whole padding block
    {
    inblock[0]=ISOPAD;
    for (i=1; i<BLOCK_SIZE; i++) inblock[i] = PAD;

    //
    // CBC specific XOR function
    //
    for (i=0; i<BLOCK_SIZE; i++) inblock[i] ^= outblock[i]; // CBC XOR

    desAlgorithm (inblock, outblock);
    outfile.write(outblock, BLOCK_SIZE);
    ln += BLOCK_SIZE;                      // Adjust filesize count
    }
  } // DesDoAlgorithmIsoCBCE

//-----------------------------------------------------------------------------
//
//                              DesDoAlgorithmIsoCBCD
//
//  DECIPHER - Cipher Block Chaining (ISO Padding)
//
void DesDoAlgorithmIsoCBCD(ifstream &infile, ofstream &outfile)
  {
  li = COUNT_RATE;  ls = srcFileSize;

  //
  // CBC specific initial chaining vector init function
  //
  bytesrd = BLOCK_SIZE; // init
  do
    {
    infile.read(inblock, bytesrd);
    ln += (ULONG)bytesrd;

    desAlgorithm(inblock, outblock);
    //
    // CBC specific XOR function
    //
    for (i=0; i<BLOCK_SIZE; i++) outblock[i] ^= icvblock[i]; // CBC XOR
    for (i=0; i<BLOCK_SIZE; i++) icvblock[i] = inblock[i];   // CBC copy

    //
    // Encrypt and decipher modes must be handled differently.
    // Encrypt: Since "bytesrd==BLOCK_SIZE" we just write outblock to dstfile.
    // Decipher: Since ISO padding was applied to the enrypted file, it is
    //           guaranteed that the srcFileSize is a multiple of BLOCK_SIZE.
    //           However, we should remove the ISO padding from the deciphered
    //           plaintext, which is done here.
    //
    if (ln != srcFileSize) outfile.write(outblock, BLOCK_SIZE);

    else                      // (ln == srcFileSize)
      {                       // Remove ISO padding from plaintext before fwrite
      j = BLOCK_SIZE;         // Assume a whole block of padding

//printf("--DES_CBCD: %02X %02X %02X %02X %02X %02X %02X %02X \n",
//       (UCHAR)outblock[0], (UCHAR)outblock[1], (UCHAR)outblock[2], (UCHAR)outblock[3],
//       (UCHAR)outblock[4], (UCHAR)outblock[5], (UCHAR)outblock[6], (UCHAR)outblock[7]);
//printf("[bytesrd=%d, ln=%ld, ls=%ld, j=%ld]\n", bytesrd,ln,ls,j);

      for (i=0; i<BLOCK_SIZE; i++)
        {
        j--;

//printf("--DES_CBCD: %02X\n", outblock[j]);

        if (outblock[j] == 0xFFFFFF80)  // Stop at ISOPAD (rendered as long int ????)
          {
          break;
          }
        }

//printf("--DES_CBCD: %02X j=%d\n", outblock[j], j);

        outfile.write(outblock, j);     // Write until ISOPAD
        break; // Stop while loop if ISOPAD
      }                               // (discard ISOPAD)

    if (ln / li)
      {
      printf("%lu KB\r", ln / 1024L);  // Echo per COUNT_RATE
      li += COUNT_RATE;
      }
    }
  while (ln < ls);  // end do while

  ln -= bytesrd; ln += (ULONG)j;  // Adjust (decipher) filesize count
  } // DesDoAlgorithmIsoCBCD


//-----------------------------------------------------------------------------
//
//                              OutfileXorInfile
//
//  For use in CBC Test-Batchfiles:  Outfile ^= infile
//  For simplicity no Error-checking  on file streams is done here!
//
void OutfileXorInfile(char *_outfile, char *_infile)
    {
    char inbuf[BLOCK_SIZE], outbuf[BLOCK_SIZE];

    ifstream tmpfile(_outfile, ios::binary | ios::in); // Open input binary file
    tmpfile.read(outbuf, BLOCK_SIZE);  //Fill the outbuffer from file and display it

    ifstream infile(_infile, ios::binary | ios::in); // Open input binary file
    infile.read(inbuf, BLOCK_SIZE);  //Fill the inbuffer from file and display it

//ha///DebugPrintBuffer(inbuf, BLOCK_SIZE);
    for (i=0; i<BLOCK_SIZE; i++) outbuf[i] ^= inbuf[i]; // CBC XOR
//ha//DebugPrintBuffer(outbuf, BLOCK_SIZE);

    ofstream outfile(_outfile, ios::binary | ios::out); //Open output binary file
    outfile.write(outbuf, BLOCK_SIZE);

    tmpfile.close();
    infile.close();
    outfile.close();
    exit(0);
    }  // OutfileXorInfile


//----------------------------------------------------------------------------
//
//                                DisplayIcvblock
//
void DisplayIcvblock()
  {
  printf("iv-block: ");
  for (i=0; i<BLOCK_SIZE; i++) printf("%02X ", (UCHAR)icvblock[i]);
  printf("\n");
  } // DisplayIcvblock

//----------------------------------------------------------------------------
//
//                                ClearScreen
//
void ClearScreen()
  {
  system("cls");
  } //ClearScreen


//----------------------------------------------------------------------------
//
//                                 AnyKey
//
void AnyKey()
  {
  // This console program could be run by typing its name at the command prompt,
  // or it could be run by the user double-clicking it from Explorer.
  // And you want to know which case you’re in.

  // Check if invoked via Desktop
  DWORD procId = GetCurrentProcessId();
  DWORD count = GetConsoleProcessList(&procId, 1);
  if (count < 2)
    {
    printf("\nConsole application: DES.EXE\n");
    system("cmd");                   // Keep the Console window
    exit(0);
    }

  // Invoked via Console
  while (_kbhit() != 0) _getch();    // Flush key-buffer 
  printf("-- press any key --\n");
  _getch();
  } // AnyKey


//----------------------------------------------------------------------------
//
//                                 More
//
void More()
  {
  while (_kbhit() != 0) _getch();    // flush key-buffer 
  printf("-- more --\r");
  _getch();
  ClearScreen();
  } // More


//-----------------------------------------------------------------------------
//
//                              DesDisplayHelp
//
void DesDisplayHelp()
  {
  printf(signon);                   // Display signon message

  printf("Performs encryption and decryption using the Data Encryption Standard.\n\n"
         "Usage: DES srcfile destfile <key> <options> [ivfile]\n"
         "  srcfile    Input file (plain text or encrypted text >= 8 bytes).\n"
         "  destfile   Output file (after the algorithm has been applied).\n"
         "  ivfile     Input iv-file (Init Vector, optional for CBC modes).\n\n");

  printf("<key>        keyfile | /keystring\n");
  printf("  keyfile    Input file containing the secret key.\n"
         "             The key can be 8 bytes max. The effective key length is\n"
         "             56 bits, i.e., parity bits of the 'key' are ignored.\n"
         "  /keystring To avoid a keyfile the key may be directly given as\n"
         "             a string of up to 32  ascii characters: e.g. /12345678.\n");
  printf("<options>\n");
  printf("  /ENCRYPT   Encrypts a file. The plaintext is DES encrypted.\n"
         "             Mode: CBC with ciphertext stealing.\n\n");

  printf("  /DECIPHER  Deciphers an encrypted file. The DES ciphertext is converted\n"
         "             into plaintext. Mode: CBC with ciphertext stealing.\n\n");

  printf("  /MAC       A Message Authentication Code (MAC) is calculated from srcfile.\n"
         "             The cryptographic signature is written to destfile, that can be\n"
         "             appended to the plaintext as a cryptographic signature.\n"
         "             Mode: CBC with ISO padding.\n");
  More();    // Press any key to continue
  
  printf("  /ECBENCRYPT  Encrypts a file. The plaintext is DES encrypted.\n"
         "               Mode: ECB with ciphertext stealing.\n\n");

  printf("  /ECBDECIPHER Deciphers an encrypted file. The DES ciphertext is converted\n"
         "               into plaintext. Mode: ECB with ciphertext stealing.\n\n");

  printf("  /CBCE     Encrypts a file. Mode: CBC with ISO/IEC 7816-4 padding.\n\n");

  printf("  /CBCD     Deciphers an encrypted file. Mode: CBC with ISO padding.\n\n");

  printf("  /ECBE     Encrypts a file. Mode: ECB with ISO/IEC 7816-4 padding.\n\n");

  printf("  /ECBD     Deciphers an encrypted file. Mode: ECB with ISO padding.\n\n");

  printf("  /XOR  Additional option. Usage: 'DES outfile infile /XOR'\n"
         "        May be used in batches to perform 'outfile ^= infile'\n\n");

  printf("This utility is very fast! When encrypting files, always be careful\n"
         "about keeping your keys privately at a secure place.\n"
         "Never send an encrypted file and its secret key through the same channel.\n"
         "For example, if you sent the encrypted file and this utility via e-mail\n"
         " to a certain person, you should communicate the secret key via\n"
         " telephone or surface mail, addressing the entitled person.\n");
  
  AnyKey();    // Press any key for exit
  } // DesDisplayHelp

//-----------------------------------------------------------------------------
//
//                              main
//
int main(int argc, char **argv)
  {
  int i;
  struct stat _stat;

  if ((argc == 4) && _stricmp(argv[3], "/XOR") == 0)  // XOR files requested
    {
    stat(argv[1], &_stat);                           // Input file status
    if (_stat.st_size != BLOCK_SIZE) ;
    OutfileXorInfile(argv[1], argv[2]);
    }

  for (i=0; i<BLOCK_SIZE; i++) icvblock[i] = 0x00;  // CBC Clear-Init ICV
  if (argc == 6)                                    // ICV file is present
    {
    argc--;
    stat(argv[5], &_stat);                          // Key provided by file
    if (_stat.st_size > BLOCK_SIZE)
      {
      printf(error_fsize, argv[5], BLOCK_SIZE);     // File length error, or non-existance
      exit(1);
      }
    //
    // Read the key and initialize the DES ICV for CBCE /CBCD modes.
    //
    ifstream Icvfile(argv[5], ios::binary | ios::in); //Open input binary file
    if (!Icvfile)
      {
      printf(open_failed, argv[5]);
      exit(1);
      }
    Icvfile.read(icvblock, _stat.st_size);   // Copy the icv from file and display it
//ha//    printf("iv-block: ");
//ha//    for (i=0; i<BLOCK_SIZE; i++) printf("%02X ", (UCHAR)icvblock[i]);
//ha//    printf("\n");
    } // ReadFileIcv

  if (argc < 5)                         // Illegal parameter
    {
    DesDisplayHelp();                   // Illegal parameter
    exit(0);
    }
  else if (_stricmp(argv[4], "/DECIPHER") == 0) mode = DES_DECIPHER;
  else if (_stricmp(argv[4], "/ENCRYPT") == 0) mode = DES_ENCRYPT;
  else if (_stricmp(argv[4], "/MAC") == 0) mode = DES_MAC;
  else if (_stricmp(argv[4], "/CBCD") == 0) mode = DES_CBCD;
  else if (_stricmp(argv[4], "/CBCE") == 0) mode = DES_CBCE;
  else if (_stricmp(argv[4], "/ECBD") == 0) mode = DES_ECBD;
  else if (_stricmp(argv[4], "/ECBE") == 0) mode = DES_ECBE;
  else if (_stricmp(argv[4], "/ECBDECIPHER") == 0) mode = DES_ECBDECIPHER;
  else if (_stricmp(argv[4], "/ECBENCRYPT") == 0) mode = DES_ECBENCRYPT;
  else
    {
    DesDisplayHelp();                   // Illegal parameter
    exit(0);
    }

  //
  // Determine the key mode
  //
  if (strncmp(&argv[3][0], "/", 1) == 0)           // Key via command line
    {
    if (strlen(&argv[3][1]) > KEY_LENGTH)                 
      {
      printf("ERROR: KEYSIZE > %d!\n", KEY_LENGTH);
      exit(1);
      }
    for (i=0; (UINT)i<strlen(&argv[3][1]); i++)    // Copy the key from command line
      {
      if ((UINT)i >= strlen(&argv[3][1])) break;   // Pad all short keys
      keybuf[i] = (argv[3][i+1] & 0xFF);
      if (keybuf[i] == 0xFFFFFFA0) keybuf[i] = 0xFF; // WIN10: **argv will return wrong chars if typed
      }                                              //  on keypad (eg. Alt+"1 2 8" thru "2 5 5"  

    }

  else
    {
    stat(argv[3], &_stat);                          // Key provided by file
    if (_stat.st_size >  KEY_LENGTH)
      {
      printf(error_keysize, argv[3], KEY_LENGTH);
      exit(1);
      }

    //
    // Read the key and initialize the DES key schedule.
    //
    ifstream keyfile(argv[3], ios::binary | ios::in); //Open input binary file
    if (!keyfile)
      {
      printf(open_failed, argv[3]);
      exit(1);
      }
    keyfile.read(keybuf, _stat.st_size);   // Copy the key from file
    }

//ha//printf("keylength: %dbits\n", _keylength);
//ha//printf("keybuf: ");
//ha//for (i=0; i<BLOCK_SIZE; i++) printf("%02X ", (UCHAR)keybuf[i]);
//ha//printf("\n");

  // ---------------------------------
  // Open source and destination files
  // ---------------------------------
  stat(argv[1], &_stat);                          // Check source file size
  srcFileSize = _stat.st_size;                    // Init source file size

  if (srcFileSize < BLOCK_SIZE)                           // Must be at least one block
    {
    printf(error_fsize, argv[1], BLOCK_SIZE);     // File length error, or non-existance
    exit(1);
    }

  ifstream infile(argv[1], ios::binary | ios::in); //Open input binary file
  if (!infile)
    {
    printf(open_failed, argv[1]);
    exit(1);
    }
  
  if (_access(argv[2], 0) == 0)     // Check if outfile already exists
    {                               
    printf(file_exists, argv[2]);   
    exit(1);
    }                               

  ofstream outfile(argv[2], ios::binary | ios::out); //Open output binary file
  if (!outfile)
    {
    printf(open_failed, argv[2]);
    exit(1);
    }

  printf(signon);                   // Display signon message

  // -------------------------
  // Perform the DES algorithm
  // -------------------------
  ln = 0L; li = COUNT_RATE;
  switch(mode)
    {
    case DES_ENCRYPT:
      DisplayIcvblock();
      kinit(keybuf, ENCRYPT);
      DesDoAlgorithmStealCBCE(infile, outfile);
      printf(bytes_encrypted, ln);
      break;

    case DES_DECIPHER:
      DisplayIcvblock();
      kinit(keybuf, DECIPHER);
      DesDoAlgorithmStealCBCD(infile, outfile);
      printf(bytes_deciphered, ln);
      break;

    case DES_ECBENCRYPT:
      kinit(keybuf, ENCRYPT);
      DesDoAlgorithmStealECB(infile, outfile);
      printf(bytes_encrypted, ln);
      break;

    case DES_ECBDECIPHER:
      kinit(keybuf, DECIPHER);
      DesDoAlgorithmStealECB(infile, outfile);
      printf(bytes_deciphered, ln);
      break;

    case DES_CBCE:
      DisplayIcvblock();
      kinit(keybuf, ENCRYPT);
      DesDoAlgorithmIsoCBCE(infile, outfile);
      printf(bytes_encrypted, ln);
      break;

    case DES_CBCD:
      DisplayIcvblock();
      kinit(keybuf, DECIPHER);
      DesDoAlgorithmIsoCBCD(infile, outfile);
      printf(bytes_deciphered, ln);
      break;

    case DES_ECBE:
      kinit(keybuf, ENCRYPT);
      DesDoAlgorithmIsoECB(infile, outfile);
      printf(bytes_encrypted, ln);
      break;

    case DES_ECBD:
      kinit(keybuf, DECIPHER);
      DesDoAlgorithmIsoECB(infile, outfile);
      printf(bytes_deciphered, ln);
      break;

    case DES_MAC:
      DisplayIcvblock();
      kinit(keybuf, ENCRYPT);
      for (i=0; i<BLOCK_SIZE; i++) outblock[i]=0;       // Init ICV

      li = 1; ls = srcFileSize;
      bytesrd = BLOCK_SIZE; // init
      while (ln < ls)
        {
        if ((ln+BLOCK_SIZE) > ls) bytesrd = (int)(ls % BLOCK_SIZE);
        ln += (ULONG)bytesrd;

        infile.read(inblock, bytesrd);
        if (bytesrd < BLOCK_SIZE)
          {
          //
          // For simplification: The last block is padded.
          //
          for (i=bytesrd; i<BLOCK_SIZE; i++) inblock[i] = PAD;
          }

        for (i=0; i<BLOCK_SIZE; i++) inblock[i] ^= outblock[i]; // dest XOR plain
        desAlgorithm(inblock, outblock);

        if (ln / li)
          {
          printf("%lu KB\r", ln / 1024L);  // Echo per COUNT_RATE
          li += COUNT_RATE;
          }
        } // end while

      outfile.write(outblock, BLOCK_SIZE);            // Emit the MAC to file
      printf("%lu bytes processed. MAC = [", ln);        // Display the MAC
      for (i=0; i<BLOCK_SIZE; i++) printf("%02X", (UCHAR)outblock[i]);
      printf("]\n%s: %d Bytes have been written.\n", argv[2], BLOCK_SIZE );
      break;

    default:
      printf("Illegal option.\n");
      break;
    } // end switch

  infile.close();
  outfile.close();
  if(!outfile.good())
    {
    cout << "Error occurred at writing time!" << endl;
    exit(1);
    }
  exit(0);
  } // main

//-------------------------- end of main module -------------------------------
