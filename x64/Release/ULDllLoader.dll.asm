Microsoft (R) COFF/PE Dumper Version 14.29.30139.0
Copyright (C) Microsoft Corporation.  All rights reserved.


Dump of file ULDllLoader.dll

File Type: DLL

DllMain:
  0000000180001000: B8 01 00 00 00     mov         eax,1
  0000000180001005: C3                 ret
  0000000180001006: CC CC CC CC CC CC CC CC CC CC                    IIIIIIIIII
ULLoadLibraryA:
  0000000180001010: 48 89 5C 24 18     mov         qword ptr [rsp+18h],rbx
  0000000180001015: 48 89 74 24 20     mov         qword ptr [rsp+20h],rsi
  000000018000101A: 55                 push        rbp
  000000018000101B: 57                 push        rdi
  000000018000101C: 41 54              push        r12
  000000018000101E: 41 55              push        r13
  0000000180001020: 41 56              push        r14
  0000000180001022: 48 8D AC 24 80 D0  lea         rbp,[rsp-2F80h]
                    FF FF
  000000018000102A: B8 80 30 00 00     mov         eax,3080h
  000000018000102F: E8 7C 17 00 00     call        __chkstk
  0000000180001034: 48 2B E0           sub         rsp,rax
  0000000180001037: 48 8B 05 CA 2F 00  mov         rax,qword ptr [__security_cookie]
                    00
  000000018000103E: 48 33 C4           xor         rax,rsp
  0000000180001041: 48 89 85 70 2F 00  mov         qword ptr [rbp+2F70h],rax
                    00
  0000000180001048: 33 FF              xor         edi,edi
  000000018000104A: 48 89 4C 24 60     mov         qword ptr [rsp+60h],rcx
  000000018000104F: 48 89 7C 24 30     mov         qword ptr [rsp+30h],rdi
  0000000180001054: 45 33 C9           xor         r9d,r9d
  0000000180001057: C7 44 24 28 80 00  mov         dword ptr [rsp+28h],80h
                    00 00
  000000018000105F: BA 00 00 00 80     mov         edx,80000000h
  0000000180001064: 44 8B EF           mov         r13d,edi
  0000000180001067: 48 89 7C 24 50     mov         qword ptr [rsp+50h],rdi
  000000018000106C: 44 8D 47 03        lea         r8d,[rdi+3]
  0000000180001070: 48 89 7C 24 58     mov         qword ptr [rsp+58h],rdi
  0000000180001075: C7 44 24 20 03 00  mov         dword ptr [rsp+20h],3
                    00 00
  000000018000107D: FF 15 7D 1F 00 00  call        qword ptr [__imp_CreateFileA]
  0000000180001083: 48 89 44 24 48     mov         qword ptr [rsp+48h],rax
  0000000180001088: 48 8B D8           mov         rbx,rax
  000000018000108B: 48 85 C0           test        rax,rax
  000000018000108E: 0F 84 F6 07 00 00  je          000000018000188A
  0000000180001094: 4C 8D 4C 24 68     lea         r9,[rsp+68h]
  0000000180001099: 48 89 7C 24 20     mov         qword ptr [rsp+20h],rdi
  000000018000109E: 41 B8 00 02 00 00  mov         r8d,200h
  00000001800010A4: 48 8D 54 24 70     lea         rdx,[rsp+70h]
  00000001800010A9: 48 8B C8           mov         rcx,rax
  00000001800010AC: FF 15 56 1F 00 00  call        qword ptr [__imp_ReadFile]
  00000001800010B2: 8B 55 AC           mov         edx,dword ptr [rbp-54h]
  00000001800010B5: 45 33 C9           xor         r9d,r9d
  00000001800010B8: 45 33 C0           xor         r8d,r8d
  00000001800010BB: 48 8B CB           mov         rcx,rbx
  00000001800010BE: FF 15 4C 1F 00 00  call        qword ptr [__imp_SetFilePointer]
  00000001800010C4: 4C 8D 4C 24 68     lea         r9,[rsp+68h]
  00000001800010C9: 48 89 7C 24 20     mov         qword ptr [rsp+20h],rdi
  00000001800010CE: 41 B8 00 10 00 00  mov         r8d,1000h
  00000001800010D4: 48 8D 54 24 70     lea         rdx,[rsp+70h]
  00000001800010D9: 48 8B CB           mov         rcx,rbx
  00000001800010DC: FF 15 26 1F 00 00  call        qword ptr [__imp_ReadFile]
  00000001800010E2: 45 33 C9           xor         r9d,r9d
  00000001800010E5: 45 33 C0           xor         r8d,r8d
  00000001800010E8: 33 D2              xor         edx,edx
  00000001800010EA: 48 8B CB           mov         rcx,rbx
  00000001800010ED: FF 15 1D 1F 00 00  call        qword ptr [__imp_SetFilePointer]
  00000001800010F3: 0F B7 45 88        movzx       eax,word ptr [rbp-78h]
  00000001800010F7: 41 BE 0B 01 00 00  mov         r14d,10Bh
  00000001800010FD: BE 0B 02 00 00     mov         esi,20Bh
  0000000180001102: 66 41 3B C6        cmp         ax,r14w
  0000000180001106: 75 06              jne         000000018000110E
  0000000180001108: 44 8B 65 A4        mov         r12d,dword ptr [rbp-5Ch]
  000000018000110C: EB 0B              jmp         0000000180001119
  000000018000110E: 66 3B C6           cmp         ax,si
  0000000180001111: 4C 8B E7           mov         r12,rdi
  0000000180001114: 4C 0F 44 65 A0     cmove       r12,qword ptr [rbp-60h]
  0000000180001119: 8B 55 C0           mov         edx,dword ptr [rbp-40h]
  000000018000111C: 41 B9 40 00 00 00  mov         r9d,40h
  0000000180001122: 81 C2 00 10 00 00  add         edx,1000h
  0000000180001128: 41 B8 00 30 00 00  mov         r8d,3000h
  000000018000112E: 49 8B CC           mov         rcx,r12
  0000000180001131: FF 15 E1 1E 00 00  call        qword ptr [__imp_VirtualAlloc]
  0000000180001137: 48 8B D8           mov         rbx,rax
  000000018000113A: 48 85 C0           test        rax,rax
  000000018000113D: 75 27              jne         0000000180001166
  000000018000113F: 8B 55 C0           mov         edx,dword ptr [rbp-40h]
  0000000180001142: 44 8D 48 40        lea         r9d,[rax+40h]
  0000000180001146: 81 C2 00 10 00 00  add         edx,1000h
  000000018000114C: 33 C9              xor         ecx,ecx
  000000018000114E: 41 B8 00 30 00 00  mov         r8d,3000h
  0000000180001154: FF 15 BE 1E 00 00  call        qword ptr [__imp_VirtualAlloc]
  000000018000115A: 48 8B D8           mov         rbx,rax
  000000018000115D: 48 85 C0           test        rax,rax
  0000000180001160: 0F 84 24 07 00 00  je          000000018000188A
  0000000180001166: 41 B8 00 10 00 00  mov         r8d,1000h
  000000018000116C: 4C 89 BC 24 B8 30  mov         qword ptr [rsp+30B8h],r15
                    00 00
  0000000180001174: 48 8D 54 24 70     lea         rdx,[rsp+70h]
  0000000180001179: 48 8B CB           mov         rcx,rbx
  000000018000117C: E8 7D 16 00 00     call        memcpy
  0000000180001181: 0F B7 45 88        movzx       eax,word ptr [rbp-78h]
  0000000180001185: 45 33 C9           xor         r9d,r9d
  0000000180001188: 66 41 3B C6        cmp         ax,r14w
  000000018000118C: 0F 85 D5 00 00 00  jne         0000000180001267
  0000000180001192: 45 8B F9           mov         r15d,r9d
  0000000180001195: 44 8B 65 A4        mov         r12d,dword ptr [rbp-5Ch]
  0000000180001199: 4C 89 64 24 40     mov         qword ptr [rsp+40h],r12
  000000018000119E: 66 44 3B 4C 24 76  cmp         r9w,word ptr [rsp+76h]
  00000001800011A4: 0F 83 9D 01 00 00  jae         0000000180001347
  00000001800011AA: 4C 8B 64 24 48     mov         r12,qword ptr [rsp+48h]
  00000001800011AF: 48 8D 7D 68        lea         rdi,[rbp+68h]
  00000001800011B3: 48 8D 35 36 20 00  lea         rsi,[??_C@_06JGICMKHF@?4reloc@]
                    00
  00000001800011BA: 4C 8D 35 37 20 00  lea         r14,[??_C@_05GCIAPODO@?4text@]
                    00
  00000001800011C1: 8B 57 14           mov         edx,dword ptr [rdi+14h]
  00000001800011C4: 45 33 C9           xor         r9d,r9d
  00000001800011C7: 45 33 C0           xor         r8d,r8d
  00000001800011CA: 49 8B CC           mov         rcx,r12
  00000001800011CD: FF 15 3D 1E 00 00  call        qword ptr [__imp_SetFilePointer]
  00000001800011D3: 8B 57 0C           mov         edx,dword ptr [rdi+0Ch]
  00000001800011D6: 4C 8D 4C 24 68     lea         r9,[rsp+68h]
  00000001800011DB: 44 8B 47 10        mov         r8d,dword ptr [rdi+10h]
  00000001800011DF: 33 C0              xor         eax,eax
  00000001800011E1: 48 03 D3           add         rdx,rbx
  00000001800011E4: 48 89 44 24 20     mov         qword ptr [rsp+20h],rax
  00000001800011E9: 49 8B CC           mov         rcx,r12
  00000001800011EC: FF 15 16 1E 00 00  call        qword ptr [__imp_ReadFile]
  00000001800011F2: 45 33 C9           xor         r9d,r9d
  00000001800011F5: 41 8B C9           mov         ecx,r9d
  00000001800011F8: 0F 1F 84 00 00 00  nop         dword ptr [rax+rax]
                    00 00
  0000000180001200: 0F B6 04 0F        movzx       eax,byte ptr [rdi+rcx]
  0000000180001204: 48 FF C1           inc         rcx
  0000000180001207: 3A 44 0E FF        cmp         al,byte ptr [rsi+rcx-1]
  000000018000120B: 75 0D              jne         000000018000121A
  000000018000120D: 48 83 F9 07        cmp         rcx,7
  0000000180001211: 75 ED              jne         0000000180001200
  0000000180001213: 44 8B 6F 0C        mov         r13d,dword ptr [rdi+0Ch]
  0000000180001217: 4C 03 EB           add         r13,rbx
  000000018000121A: 49 8B C9           mov         rcx,r9
  000000018000121D: 0F 1F 00           nop         dword ptr [rax]
  0000000180001220: 0F B6 04 0F        movzx       eax,byte ptr [rdi+rcx]
  0000000180001224: 48 FF C1           inc         rcx
  0000000180001227: 41 3A 44 0E FF     cmp         al,byte ptr [r14+rcx-1]
  000000018000122C: 75 1F              jne         000000018000124D
  000000018000122E: 48 83 F9 06        cmp         rcx,6
  0000000180001232: 75 EC              jne         0000000180001220
  0000000180001234: 44 8B 67 0C        mov         r12d,dword ptr [rdi+0Ch]
  0000000180001238: 8B 47 08           mov         eax,dword ptr [rdi+8]
  000000018000123B: 4C 03 E3           add         r12,rbx
  000000018000123E: 4C 89 64 24 50     mov         qword ptr [rsp+50h],r12
  0000000180001243: 4C 8B 64 24 48     mov         r12,qword ptr [rsp+48h]
  0000000180001248: 48 89 44 24 58     mov         qword ptr [rsp+58h],rax
  000000018000124D: 0F B7 44 24 76     movzx       eax,word ptr [rsp+76h]
  0000000180001252: 49 FF C7           inc         r15
  0000000180001255: 48 83 C7 28        add         rdi,28h
  0000000180001259: 4C 3B F8           cmp         r15,rax
  000000018000125C: 0F 82 5F FF FF FF  jb          00000001800011C1
  0000000180001262: E9 DB 00 00 00     jmp         0000000180001342
  0000000180001267: 66 3B C6           cmp         ax,si
  000000018000126A: 0F 85 D7 00 00 00  jne         0000000180001347
  0000000180001270: 4D 8B F9           mov         r15,r9
  0000000180001273: 4C 8B 65 A0        mov         r12,qword ptr [rbp-60h]
  0000000180001277: 4C 89 64 24 40     mov         qword ptr [rsp+40h],r12
  000000018000127C: 66 44 3B 4C 24 76  cmp         r9w,word ptr [rsp+76h]
  0000000180001282: 0F 83 BF 00 00 00  jae         0000000180001347
  0000000180001288: 4C 8B 64 24 48     mov         r12,qword ptr [rsp+48h]
  000000018000128D: 48 8D 7D 78        lea         rdi,[rbp+78h]
  0000000180001291: 48 8D 35 58 1F 00  lea         rsi,[??_C@_06JGICMKHF@?4reloc@]
                    00
  0000000180001298: 4C 8D 35 59 1F 00  lea         r14,[??_C@_05GCIAPODO@?4text@]
                    00
  000000018000129F: 90                 nop
  00000001800012A0: 8B 57 14           mov         edx,dword ptr [rdi+14h]
  00000001800012A3: 45 33 C9           xor         r9d,r9d
  00000001800012A6: 45 33 C0           xor         r8d,r8d
  00000001800012A9: 49 8B CC           mov         rcx,r12
  00000001800012AC: FF 15 5E 1D 00 00  call        qword ptr [__imp_SetFilePointer]
  00000001800012B2: 8B 57 0C           mov         edx,dword ptr [rdi+0Ch]
  00000001800012B5: 4C 8D 4C 24 68     lea         r9,[rsp+68h]
  00000001800012BA: 44 8B 47 10        mov         r8d,dword ptr [rdi+10h]
  00000001800012BE: 33 C0              xor         eax,eax
  00000001800012C0: 48 03 D3           add         rdx,rbx
  00000001800012C3: 48 89 44 24 20     mov         qword ptr [rsp+20h],rax
  00000001800012C8: 49 8B CC           mov         rcx,r12
  00000001800012CB: FF 15 37 1D 00 00  call        qword ptr [__imp_ReadFile]
  00000001800012D1: 45 33 C9           xor         r9d,r9d
  00000001800012D4: 41 8B C9           mov         ecx,r9d
  00000001800012D7: 66 0F 1F 84 00 00  nop         word ptr [rax+rax]
                    00 00 00
  00000001800012E0: 0F B6 04 0F        movzx       eax,byte ptr [rdi+rcx]
  00000001800012E4: 48 FF C1           inc         rcx
  00000001800012E7: 3A 44 0E FF        cmp         al,byte ptr [rsi+rcx-1]
  00000001800012EB: 75 0D              jne         00000001800012FA
  00000001800012ED: 48 83 F9 07        cmp         rcx,7
  00000001800012F1: 75 ED              jne         00000001800012E0
  00000001800012F3: 44 8B 6F 0C        mov         r13d,dword ptr [rdi+0Ch]
  00000001800012F7: 4C 03 EB           add         r13,rbx
  00000001800012FA: 49 8B C9           mov         rcx,r9
  00000001800012FD: 0F 1F 00           nop         dword ptr [rax]
  0000000180001300: 0F B6 04 0F        movzx       eax,byte ptr [rdi+rcx]
  0000000180001304: 48 FF C1           inc         rcx
  0000000180001307: 41 3A 44 0E FF     cmp         al,byte ptr [r14+rcx-1]
  000000018000130C: 75 1F              jne         000000018000132D
  000000018000130E: 48 83 F9 06        cmp         rcx,6
  0000000180001312: 75 EC              jne         0000000180001300
  0000000180001314: 44 8B 67 0C        mov         r12d,dword ptr [rdi+0Ch]
  0000000180001318: 8B 47 08           mov         eax,dword ptr [rdi+8]
  000000018000131B: 4C 03 E3           add         r12,rbx
  000000018000131E: 4C 89 64 24 50     mov         qword ptr [rsp+50h],r12
  0000000180001323: 4C 8B 64 24 48     mov         r12,qword ptr [rsp+48h]
  0000000180001328: 48 89 44 24 58     mov         qword ptr [rsp+58h],rax
  000000018000132D: 0F B7 44 24 76     movzx       eax,word ptr [rsp+76h]
  0000000180001332: 49 FF C7           inc         r15
  0000000180001335: 48 83 C7 28        add         rdi,28h
  0000000180001339: 4C 3B F8           cmp         r15,rax
  000000018000133C: 0F 82 5E FF FF FF  jb          00000001800012A0
  0000000180001342: 4C 8B 64 24 40     mov         r12,qword ptr [rsp+40h]
  0000000180001347: 41 8B 55 04        mov         edx,dword ptr [r13+4]
  000000018000134B: 49 8D 7D 08        lea         rdi,[r13+8]
  000000018000134F: 4C 8B F3           mov         r14,rbx
  0000000180001352: 41 B8 08 00 00 00  mov         r8d,8
  0000000180001358: 4D 2B F4           sub         r14,r12
  000000018000135B: 4C 89 44 24 40     mov         qword ptr [rsp+40h],r8
  0000000180001360: 49 8B F1           mov         rsi,r9
  0000000180001363: 8D 4A F8           lea         ecx,[rdx-8]
  0000000180001366: 4D 8B E1           mov         r12,r9
  0000000180001369: 48 F7 C1 FE FF FF  test        rcx,0FFFFFFFFFFFFFFFEh
                    FF
  0000000180001370: 0F 86 90 01 00 00  jbe         0000000180001506
  0000000180001376: 4C 8B FF           mov         r15,rdi
  0000000180001379: 0F 1F 80 00 00 00  nop         dword ptr [rax]
                    00
  0000000180001380: 41 0F B7 0F        movzx       ecx,word ptr [r15]
  0000000180001384: 8B D1              mov         edx,ecx
  0000000180001386: C1 EA 0C           shr         edx,0Ch
  0000000180001389: 83 EA 01           sub         edx,1
  000000018000138C: 0F 84 3D 01 00 00  je          00000001800014CF
  0000000180001392: 83 EA 01           sub         edx,1
  0000000180001395: 0F 84 2E 01 00 00  je          00000001800014C9
  000000018000139B: 83 EA 01           sub         edx,1
  000000018000139E: 0F 84 14 01 00 00  je          00000001800014B8
  00000001800013A4: 83 EA 04           sub         edx,4
  00000001800013A7: 74 1B              je          00000001800013C4
  00000001800013A9: 83 FA 03           cmp         edx,3
  00000001800013AC: 0F 85 33 01 00 00  jne         00000001800014E5
  00000001800013B2: 81 E1 FF 0F 00 00  and         ecx,0FFFh
  00000001800013B8: 03 4F F8           add         ecx,dword ptr [rdi-8]
  00000001800013BB: 4C 01 34 19        add         qword ptr [rcx+rbx],r14
  00000001800013BF: E9 21 01 00 00     jmp         00000001800014E5
  00000001800013C4: 81 E1 FF 0F 00 00  and         ecx,0FFFh
  00000001800013CA: 03 4F F8           add         ecx,dword ptr [rdi-8]
  00000001800013CD: 44 8B D1           mov         r10d,ecx
  00000001800013D0: 44 8B 0C 19        mov         r9d,dword ptr [rcx+rbx]
  00000001800013D4: 41 8B C1           mov         eax,r9d
  00000001800013D7: 44 8B 5C 19 04     mov         r11d,dword ptr [rcx+rbx+4]
  00000001800013DC: 25 00 04 00 00     and         eax,400h
  00000001800013E1: 41 8B C9           mov         ecx,r9d
  00000001800013E4: C1 E1 0B           shl         ecx,0Bh
  00000001800013E7: 03 C8              add         ecx,eax
  00000001800013E9: 41 8B C1           mov         eax,r9d
  00000001800013EC: C1 E8 14           shr         eax,14h
  00000001800013EF: 25 00 07 00 00     and         eax,700h
  00000001800013F4: 8D 0C 48           lea         ecx,[rax+rcx*2]
  00000001800013F7: 41 8B C1           mov         eax,r9d
  00000001800013FA: C1 E8 10           shr         eax,10h
  00000001800013FD: 41 81 E1 F0 FB 00  and         r9d,8F00FBF0h
                    8F
  0000000180001404: 0F B6 C0           movzx       eax,al
  0000000180001407: 03 C8              add         ecx,eax
  0000000180001409: 41 8B C3           mov         eax,r11d
  000000018000140C: 0F B7 D1           movzx       edx,cx
  000000018000140F: 25 00 04 00 00     and         eax,400h
  0000000180001414: 41 8B CB           mov         ecx,r11d
  0000000180001417: C1 E1 0B           shl         ecx,0Bh
  000000018000141A: 03 C8              add         ecx,eax
  000000018000141C: 41 8B C3           mov         eax,r11d
  000000018000141F: C1 E1 11           shl         ecx,11h
  0000000180001422: C1 E8 04           shr         eax,4
  0000000180001425: 25 00 00 00 07     and         eax,7000000h
  000000018000142A: 03 C8              add         ecx,eax
  000000018000142C: 41 8B C3           mov         eax,r11d
  000000018000142F: 25 00 00 FF 00     and         eax,0FF0000h
  0000000180001434: 41 81 E3 F0 FB 00  and         r11d,8F00FBF0h
                    8F
  000000018000143B: 03 C1              add         eax,ecx
  000000018000143D: 48 0B D0           or          rdx,rax
  0000000180001440: 49 03 D6           add         rdx,r14
  0000000180001443: 0F B6 C2           movzx       eax,dl
  0000000180001446: 8B CA              mov         ecx,edx
  0000000180001448: 81 E1 00 07 00 00  and         ecx,700h
  000000018000144E: 4C 8B C2           mov         r8,rdx
  0000000180001451: C1 E1 04           shl         ecx,4
  0000000180001454: 03 C8              add         ecx,eax
  0000000180001456: 49 C1 E8 10        shr         r8,10h
  000000018000145A: C1 E1 10           shl         ecx,10h
  000000018000145D: 8B C2              mov         eax,edx
  000000018000145F: D1 E8              shr         eax,1
  0000000180001461: 25 00 04 00 00     and         eax,400h
  0000000180001466: C1 EA 0C           shr         edx,0Ch
  0000000180001469: 03 C8              add         ecx,eax
  000000018000146B: 83 E2 0F           and         edx,0Fh
  000000018000146E: 03 CA              add         ecx,edx
  0000000180001470: 41 0F B6 C0        movzx       eax,r8b
  0000000180001474: 41 03 C9           add         ecx,r9d
  0000000180001477: 41 89 0C 1A        mov         dword ptr [r10+rbx],ecx
  000000018000147B: 41 8B C8           mov         ecx,r8d
  000000018000147E: 81 E1 00 07 00 00  and         ecx,700h
  0000000180001484: C1 E1 04           shl         ecx,4
  0000000180001487: 03 C8              add         ecx,eax
  0000000180001489: 41 8B C0           mov         eax,r8d
  000000018000148C: D1 E8              shr         eax,1
  000000018000148E: 25 00 04 00 00     and         eax,400h
  0000000180001493: C1 E1 10           shl         ecx,10h
  0000000180001496: 03 C8              add         ecx,eax
  0000000180001498: 41 C1 E8 0C        shr         r8d,0Ch
  000000018000149C: 41 0F B7 07        movzx       eax,word ptr [r15]
  00000001800014A0: 41 83 E0 0F        and         r8d,0Fh
  00000001800014A4: 41 03 C8           add         ecx,r8d
  00000001800014A7: 25 FF 0F 00 00     and         eax,0FFFh
  00000001800014AC: 41 03 CB           add         ecx,r11d
  00000001800014AF: 03 47 F8           add         eax,dword ptr [rdi-8]
  00000001800014B2: 89 4C 18 04        mov         dword ptr [rax+rbx+4],ecx
  00000001800014B6: EB 2D              jmp         00000001800014E5
  00000001800014B8: 8B 47 F8           mov         eax,dword ptr [rdi-8]
  00000001800014BB: 81 E1 FF 0F 00 00  and         ecx,0FFFh
  00000001800014C1: 03 C1              add         eax,ecx
  00000001800014C3: 44 01 34 18        add         dword ptr [rax+rbx],r14d
  00000001800014C7: EB 1C              jmp         00000001800014E5
  00000001800014C9: 41 0F B7 C6        movzx       eax,r14w
  00000001800014CD: EB 0A              jmp         00000001800014D9
  00000001800014CF: 49 8B C6           mov         rax,r14
  00000001800014D2: 48 C1 E8 10        shr         rax,10h
  00000001800014D6: 0F B7 C0           movzx       eax,ax
  00000001800014D9: 81 E1 FF 0F 00 00  and         ecx,0FFFh
  00000001800014DF: 03 4F F8           add         ecx,dword ptr [rdi-8]
  00000001800014E2: 01 04 19           add         dword ptr [rcx+rbx],eax
  00000001800014E5: 8B 57 FC           mov         edx,dword ptr [rdi-4]
  00000001800014E8: 49 FF C4           inc         r12
  00000001800014EB: 49 83 C7 02        add         r15,2
  00000001800014EF: 8D 4A F8           lea         ecx,[rdx-8]
  00000001800014F2: 48 D1 E9           shr         rcx,1
  00000001800014F5: 4C 3B E1           cmp         r12,rcx
  00000001800014F8: 0F 82 82 FE FF FF  jb          0000000180001380
  00000001800014FE: 4C 8B 44 24 40     mov         r8,qword ptr [rsp+40h]
  0000000180001503: 45 33 C9           xor         r9d,r9d
  0000000180001506: 8B C2              mov         eax,edx
  0000000180001508: 4C 03 C0           add         r8,rax
  000000018000150B: 43 8B 54 28 FC     mov         edx,dword ptr [r8+r13-4]
  0000000180001510: 4B 8D 3C 28        lea         rdi,[r8+r13]
  0000000180001514: 4C 89 44 24 40     mov         qword ptr [rsp+40h],r8
  0000000180001519: 85 D2              test        edx,edx
  000000018000151B: 0F 85 42 FE FF FF  jne         0000000180001363
  0000000180001521: 0F B7 45 88        movzx       eax,word ptr [rbp-78h]
  0000000180001525: B9 0B 01 00 00     mov         ecx,10Bh
  000000018000152A: 4D 8B E1           mov         r12,r9
  000000018000152D: 66 3B C1           cmp         ax,cx
  0000000180001530: 0F 85 6B 01 00 00  jne         00000001800016A1
  0000000180001536: 8B 55 F0           mov         edx,dword ptr [rbp-10h]
  0000000180001539: 8B CA              mov         ecx,edx
  000000018000153B: 83 3C 1A 00        cmp         dword ptr [rdx+rbx],0
  000000018000153F: 0F 84 F3 02 00 00  je          0000000180001838
  0000000180001545: 4D 8B F1           mov         r14,r9
  0000000180001548: 0F 1F 84 00 00 00  nop         dword ptr [rax+rax]
                    00 00
  0000000180001550: 49 8D 04 0E        lea         rax,[r14+rcx]
  0000000180001554: 4D 8B F9           mov         r15,r9
  0000000180001557: 83 7C 18 0C 00     cmp         dword ptr [rax+rbx+0Ch],0
  000000018000155C: 0F 84 A3 00 00 00  je          0000000180001605
  0000000180001562: 48 8B 4C 24 60     mov         rcx,qword ptr [rsp+60h]
  0000000180001567: 48 8D 95 70 0F 00  lea         rdx,[rbp+0F70h]
                    00
  000000018000156E: 48 2B D1           sub         rdx,rcx
  0000000180001571: 0F B6 01           movzx       eax,byte ptr [rcx]
  0000000180001574: 88 04 0A           mov         byte ptr [rdx+rcx],al
  0000000180001577: 48 8D 49 01        lea         rcx,[rcx+1]
  000000018000157B: 84 C0              test        al,al
  000000018000157D: 75 F2              jne         0000000180001571
  000000018000157F: BA 5C 00 00 00     mov         edx,5Ch
  0000000180001584: 48 8D 8D 70 0F 00  lea         rcx,[rbp+0F70h]
                    00
  000000018000158B: FF 15 47 1B 00 00  call        qword ptr [__imp_strrchr]
  0000000180001591: 48 8D 8D 70 0F 00  lea         rcx,[rbp+0F70h]
                    00
  0000000180001598: 48 3B C1           cmp         rax,rcx
  000000018000159B: 77 4A              ja          00000001800015E7
  000000018000159D: 48 85 C0           test        rax,rax
  00000001800015A0: 74 45              je          00000001800015E7
  00000001800015A2: C6 40 01 00        mov         byte ptr [rax+1],0
  00000001800015A6: 49 C7 C0 FF FF FF  mov         r8,0FFFFFFFFFFFFFFFFh
                    FF
  00000001800015AD: 8B 45 F0           mov         eax,dword ptr [rbp-10h]
  00000001800015B0: 49 03 C6           add         rax,r14
  00000001800015B3: 8B 54 18 0C        mov         edx,dword ptr [rax+rbx+0Ch]
  00000001800015B7: 48 03 D3           add         rdx,rbx
  00000001800015BA: 66 0F 1F 44 00 00  nop         word ptr [rax+rax]
  00000001800015C0: 49 FF C0           inc         r8
  00000001800015C3: 42 80 3C 02 00     cmp         byte ptr [rdx+r8],0
  00000001800015C8: 75 F6              jne         00000001800015C0
  00000001800015CA: 48 8D 8D 70 0F 00  lea         rcx,[rbp+0F70h]
                    00
  00000001800015D1: FF 15 69 1B 00 00  call        qword ptr [__imp_strncat]
  00000001800015D7: 48 8D 8D 70 0F 00  lea         rcx,[rbp+0F70h]
                    00
  00000001800015DE: FF 15 3C 1A 00 00  call        qword ptr [__imp_LoadLibraryA]
  00000001800015E4: 48 8B F0           mov         rsi,rax
  00000001800015E7: 48 85 F6           test        rsi,rsi
  00000001800015EA: 75 45              jne         0000000180001631
  00000001800015EC: 8B 45 F0           mov         eax,dword ptr [rbp-10h]
  00000001800015EF: 49 03 C6           add         rax,r14
  00000001800015F2: 8B 4C 18 0C        mov         ecx,dword ptr [rax+rbx+0Ch]
  00000001800015F6: 48 03 CB           add         rcx,rbx
  00000001800015F9: FF 15 21 1A 00 00  call        qword ptr [__imp_LoadLibraryA]
  00000001800015FF: 8B 55 F0           mov         edx,dword ptr [rbp-10h]
  0000000180001602: 48 8B F0           mov         rsi,rax
  0000000180001605: 48 85 F6           test        rsi,rsi
  0000000180001608: 74 6D              je          0000000180001677
  000000018000160A: 8B CA              mov         ecx,edx
  000000018000160C: 49 03 CE           add         rcx,r14
  000000018000160F: 48 03 CB           add         rcx,rbx
  0000000180001612: 8B 41 10           mov         eax,dword ptr [rcx+10h]
  0000000180001615: 83 3C 18 00        cmp         dword ptr [rax+rbx],0
  0000000180001619: 74 5C              je          0000000180001677
  000000018000161B: 33 C0              xor         eax,eax
  000000018000161D: 8B F8              mov         edi,eax
  000000018000161F: 90                 nop
  0000000180001620: 8B 01              mov         eax,dword ptr [rcx]
  0000000180001622: 48 03 C7           add         rax,rdi
  0000000180001625: 8B 0C 18           mov         ecx,dword ptr [rax+rbx]
  0000000180001628: 85 C9              test        ecx,ecx
  000000018000162A: 79 0A              jns         0000000180001636
  000000018000162C: 0F B7 D1           movzx       edx,cx
  000000018000162F: EB 0C              jmp         000000018000163D
  0000000180001631: 8B 55 F0           mov         edx,dword ptr [rbp-10h]
  0000000180001634: EB D4              jmp         000000018000160A
  0000000180001636: 48 8D 51 02        lea         rdx,[rcx+2]
  000000018000163A: 48 03 D3           add         rdx,rbx
  000000018000163D: 48 8B CE           mov         rcx,rsi
  0000000180001640: FF 15 E2 19 00 00  call        qword ptr [__imp_GetProcAddress]
  0000000180001646: 8B 4D F0           mov         ecx,dword ptr [rbp-10h]
  0000000180001649: 49 FF C7           inc         r15
  000000018000164C: 49 03 CE           add         rcx,r14
  000000018000164F: 8B 54 19 10        mov         edx,dword ptr [rcx+rbx+10h]
  0000000180001653: 48 03 D7           add         rdx,rdi
  0000000180001656: 4A 8D 3C BD 00 00  lea         rdi,[r15*4]
                    00 00
  000000018000165E: 89 04 1A           mov         dword ptr [rdx+rbx],eax
  0000000180001661: 8B 55 F0           mov         edx,dword ptr [rbp-10h]
  0000000180001664: 49 8D 0C 16        lea         rcx,[r14+rdx]
  0000000180001668: 48 03 CB           add         rcx,rbx
  000000018000166B: 8B 41 10           mov         eax,dword ptr [rcx+10h]
  000000018000166E: 48 03 C7           add         rax,rdi
  0000000180001671: 83 3C 18 00        cmp         dword ptr [rax+rbx],0
  0000000180001675: 75 A9              jne         0000000180001620
  0000000180001677: 49 FF C4           inc         r12
  000000018000167A: 8B CA              mov         ecx,edx
  000000018000167C: 41 B9 00 00 00 00  mov         r9d,0
  0000000180001682: 4B 8D 04 A4        lea         rax,[r12+r12*4]
  0000000180001686: 4C 8D 34 85 00 00  lea         r14,[rax*4]
                    00 00
  000000018000168E: 49 8D 04 0E        lea         rax,[r14+rcx]
  0000000180001692: 83 3C 18 00        cmp         dword ptr [rax+rbx],0
  0000000180001696: 0F 85 B4 FE FF FF  jne         0000000180001550
  000000018000169C: E9 97 01 00 00     jmp         0000000180001838
  00000001800016A1: B9 0B 02 00 00     mov         ecx,20Bh
  00000001800016A6: 66 3B C1           cmp         ax,cx
  00000001800016A9: 0F 85 89 01 00 00  jne         0000000180001838
  00000001800016AF: 8B 55 00           mov         edx,dword ptr [rbp]
  00000001800016B2: 8B CA              mov         ecx,edx
  00000001800016B4: 83 3C 1A 00        cmp         dword ptr [rdx+rbx],0
  00000001800016B8: 0F 84 7A 01 00 00  je          0000000180001838
  00000001800016BE: 49 8B F9           mov         rdi,r9
  00000001800016C1: 48 8D 04 39        lea         rax,[rcx+rdi]
  00000001800016C5: 4D 8B F9           mov         r15,r9
  00000001800016C8: 83 7C 18 0C 00     cmp         dword ptr [rax+rbx+0Ch],0
  00000001800016CD: 0F 84 A7 00 00 00  je          000000018000177A
  00000001800016D3: 48 8B 4C 24 60     mov         rcx,qword ptr [rsp+60h]
  00000001800016D8: 48 8D 95 70 1F 00  lea         rdx,[rbp+1F70h]
                    00
  00000001800016DF: 48 2B D1           sub         rdx,rcx
  00000001800016E2: 0F B6 01           movzx       eax,byte ptr [rcx]
  00000001800016E5: 88 04 11           mov         byte ptr [rcx+rdx],al
  00000001800016E8: 48 8D 49 01        lea         rcx,[rcx+1]
  00000001800016EC: 84 C0              test        al,al
  00000001800016EE: 75 F2              jne         00000001800016E2
  00000001800016F0: BA 5C 00 00 00     mov         edx,5Ch
  00000001800016F5: 48 8D 8D 70 1F 00  lea         rcx,[rbp+1F70h]
                    00
  00000001800016FC: FF 15 D6 19 00 00  call        qword ptr [__imp_strrchr]
  0000000180001702: 48 8D 8D 70 1F 00  lea         rcx,[rbp+1F70h]
                    00
  0000000180001709: 48 3B C1           cmp         rax,rcx
  000000018000170C: 77 53              ja          0000000180001761
  000000018000170E: 48 85 C0           test        rax,rax
  0000000180001711: 74 4E              je          0000000180001761
  0000000180001713: C6 40 01 00        mov         byte ptr [rax+1],0
  0000000180001717: 49 C7 C0 FF FF FF  mov         r8,0FFFFFFFFFFFFFFFFh
                    FF
  000000018000171E: 8B 45 00           mov         eax,dword ptr [rbp]
  0000000180001721: 48 03 C7           add         rax,rdi
  0000000180001724: 8B 54 18 0C        mov         edx,dword ptr [rax+rbx+0Ch]
  0000000180001728: 48 03 D3           add         rdx,rbx
  000000018000172B: 0F 1F 44 00 00     nop         dword ptr [rax+rax]
  0000000180001730: 49 FF C0           inc         r8
  0000000180001733: 42 80 3C 02 00     cmp         byte ptr [rdx+r8],0
  0000000180001738: 75 F6              jne         0000000180001730
  000000018000173A: 48 8D 8D 70 1F 00  lea         rcx,[rbp+1F70h]
                    00
  0000000180001741: FF 15 F9 19 00 00  call        qword ptr [__imp_strncat]
  0000000180001747: 48 8D 8D 70 1F 00  lea         rcx,[rbp+1F70h]
                    00
  000000018000174E: FF 15 CC 18 00 00  call        qword ptr [__imp_LoadLibraryA]
  0000000180001754: 48 8B F0           mov         rsi,rax
  0000000180001757: 48 85 C0           test        rax,rax
  000000018000175A: 74 05              je          0000000180001761
  000000018000175C: 8B 55 00           mov         edx,dword ptr [rbp]
  000000018000175F: EB 22              jmp         0000000180001783
  0000000180001761: 8B 45 00           mov         eax,dword ptr [rbp]
  0000000180001764: 48 03 C7           add         rax,rdi
  0000000180001767: 8B 4C 18 0C        mov         ecx,dword ptr [rax+rbx+0Ch]
  000000018000176B: 48 03 CB           add         rcx,rbx
  000000018000176E: FF 15 AC 18 00 00  call        qword ptr [__imp_LoadLibraryA]
  0000000180001774: 8B 55 00           mov         edx,dword ptr [rbp]
  0000000180001777: 48 8B F0           mov         rsi,rax
  000000018000177A: 48 85 F6           test        rsi,rsi
  000000018000177D: 0F 84 90 00 00 00  je          0000000180001813
  0000000180001783: 8B CA              mov         ecx,edx
  0000000180001785: 48 03 CF           add         rcx,rdi
  0000000180001788: 48 03 CB           add         rcx,rbx
  000000018000178B: 8B 41 10           mov         eax,dword ptr [rcx+10h]
  000000018000178E: 83 3C 18 00        cmp         dword ptr [rax+rbx],0
  0000000180001792: 0F 84 7B 00 00 00  je          0000000180001813
  0000000180001798: 33 C0              xor         eax,eax
  000000018000179A: 44 8B F0           mov         r14d,eax
  000000018000179D: 0F 1F 00           nop         dword ptr [rax]
  00000001800017A0: 8B 01              mov         eax,dword ptr [rcx]
  00000001800017A2: 49 03 C6           add         rax,r14
  00000001800017A5: 8B 0C 18           mov         ecx,dword ptr [rax+rbx]
  00000001800017A8: 85 C9              test        ecx,ecx
  00000001800017AA: 74 67              je          0000000180001813
  00000001800017AC: 48 83 3C 18 00     cmp         qword ptr [rax+rbx],0
  00000001800017B1: 8B D1              mov         edx,ecx
  00000001800017B3: 48 8B CE           mov         rcx,rsi
  00000001800017B6: 7D 1C              jge         00000001800017D4
  00000001800017B8: 0F B7 D2           movzx       edx,dx
  00000001800017BB: FF 15 67 18 00 00  call        qword ptr [__imp_GetProcAddress]
  00000001800017C1: 8B 4D 00           mov         ecx,dword ptr [rbp]
  00000001800017C4: 48 03 CF           add         rcx,rdi
  00000001800017C7: 8B 54 19 10        mov         edx,dword ptr [rcx+rbx+10h]
  00000001800017CB: 49 03 D6           add         rdx,r14
  00000001800017CE: 48 89 04 1A        mov         qword ptr [rdx+rbx],rax
  00000001800017D2: EB 1E              jmp         00000001800017F2
  00000001800017D4: 48 83 C2 02        add         rdx,2
  00000001800017D8: 48 03 D3           add         rdx,rbx
  00000001800017DB: FF 15 47 18 00 00  call        qword ptr [__imp_GetProcAddress]
  00000001800017E1: 8B 4D 00           mov         ecx,dword ptr [rbp]
  00000001800017E4: 48 03 CF           add         rcx,rdi
  00000001800017E7: 8B 54 19 10        mov         edx,dword ptr [rcx+rbx+10h]
  00000001800017EB: 48 03 D3           add         rdx,rbx
  00000001800017EE: 4A 89 04 FA        mov         qword ptr [rdx+r15*8],rax
  00000001800017F2: 8B 55 00           mov         edx,dword ptr [rbp]
  00000001800017F5: 49 FF C7           inc         r15
  00000001800017F8: 48 8D 0C 17        lea         rcx,[rdi+rdx]
  00000001800017FC: 48 03 CB           add         rcx,rbx
  00000001800017FF: 4E 8D 34 BD 00 00  lea         r14,[r15*4]
                    00 00
  0000000180001807: 8B 41 10           mov         eax,dword ptr [rcx+10h]
  000000018000180A: 49 03 C6           add         rax,r14
  000000018000180D: 83 3C 18 00        cmp         dword ptr [rax+rbx],0
  0000000180001811: 75 8D              jne         00000001800017A0
  0000000180001813: 49 FF C4           inc         r12
  0000000180001816: 8B CA              mov         ecx,edx
  0000000180001818: 41 B9 00 00 00 00  mov         r9d,0
  000000018000181E: 4B 8D 04 A4        lea         rax,[r12+r12*4]
  0000000180001822: 48 8D 3C 85 00 00  lea         rdi,[rax*4]
                    00 00
  000000018000182A: 48 8D 04 39        lea         rax,[rcx+rdi]
  000000018000182E: 83 3C 18 00        cmp         dword ptr [rax+rbx],0
  0000000180001832: 0F 85 89 FE FF FF  jne         00000001800016C1
  0000000180001838: 48 8B 7C 24 50     mov         rdi,qword ptr [rsp+50h]
  000000018000183D: 4C 8B BC 24 B8 30  mov         r15,qword ptr [rsp+30B8h]
                    00 00
  0000000180001845: 48 85 FF           test        rdi,rdi
  0000000180001848: 74 30              je          000000018000187A
  000000018000184A: 48 8B 54 24 58     mov         rdx,qword ptr [rsp+58h]
  000000018000184F: 4C 8D 4C 24 68     lea         r9,[rsp+68h]
  0000000180001854: 41 B8 40 00 00 00  mov         r8d,40h
  000000018000185A: 48 8B CF           mov         rcx,rdi
  000000018000185D: FF 15 CD 17 00 00  call        qword ptr [__imp_VirtualProtect]
  0000000180001863: FF 15 D7 17 00 00  call        qword ptr [__imp_GetCurrentProcess]
  0000000180001869: 4C 8B 44 24 58     mov         r8,qword ptr [rsp+58h]
  000000018000186E: 48 8B D7           mov         rdx,rdi
  0000000180001871: 48 8B C8           mov         rcx,rax
  0000000180001874: FF 15 BE 17 00 00  call        qword ptr [__imp_FlushInstructionCache]
  000000018000187A: 48 8B 4C 24 48     mov         rcx,qword ptr [rsp+48h]
  000000018000187F: FF 15 C3 17 00 00  call        qword ptr [__imp_CloseHandle]
  0000000180001885: 48 8B C3           mov         rax,rbx
  0000000180001888: EB 02              jmp         000000018000188C
  000000018000188A: 33 C0              xor         eax,eax
  000000018000188C: 48 8B 8D 70 2F 00  mov         rcx,qword ptr [rbp+2F70h]
                    00
  0000000180001893: 48 33 CC           xor         rcx,rsp
  0000000180001896: E8 85 01 00 00     call        __security_check_cookie
  000000018000189B: 4C 8D 9C 24 80 30  lea         r11,[rsp+3080h]
                    00 00
  00000001800018A3: 49 8B 5B 40        mov         rbx,qword ptr [r11+40h]
  00000001800018A7: 49 8B 73 48        mov         rsi,qword ptr [r11+48h]
  00000001800018AB: 49 8B E3           mov         rsp,r11
  00000001800018AE: 41 5E              pop         r14
  00000001800018B0: 41 5D              pop         r13
  00000001800018B2: 41 5C              pop         r12
  00000001800018B4: 5F                 pop         rdi
  00000001800018B5: 5D                 pop         rbp
  00000001800018B6: C3                 ret
  00000001800018B7: CC CC CC CC CC CC CC CC CC                       IIIIIIIII
ULExecDllMain:
  00000001800018C0: 8B 41 28           mov         eax,dword ptr [rcx+28h]
  00000001800018C3: 45 33 C0           xor         r8d,r8d
  00000001800018C6: 48 03 C1           add         rax,rcx
  00000001800018C9: 48 FF E0           jmp         rax
  00000001800018CC: CC CC CC CC                                      IIII
ULGetProcAddress:
  00000001800018D0: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  00000001800018D5: 48 89 6C 24 10     mov         qword ptr [rsp+10h],rbp
  00000001800018DA: 48 89 74 24 18     mov         qword ptr [rsp+18h],rsi
  00000001800018DF: 48 89 7C 24 20     mov         qword ptr [rsp+20h],rdi
  00000001800018E4: 0F B7 41 18        movzx       eax,word ptr [rcx+18h]
  00000001800018E8: 45 33 C0           xor         r8d,r8d
  00000001800018EB: 4C 8B D1           mov         r10,rcx
  00000001800018EE: 48 8B EA           mov         rbp,rdx
  00000001800018F1: B9 0B 01 00 00     mov         ecx,10Bh
  00000001800018F6: 41 8B D8           mov         ebx,r8d
  00000001800018F9: 66 3B C1           cmp         ax,cx
  00000001800018FC: 75 6E              jne         000000018000196C
  00000001800018FE: 41 8B 7A 78        mov         edi,dword ptr [r10+78h]
  0000000180001902: 49 03 FA           add         rdi,r10
  0000000180001905: 8B 77 18           mov         esi,dword ptr [rdi+18h]
  0000000180001908: 48 85 F6           test        rsi,rsi
  000000018000190B: 0F 84 C9 00 00 00  je          00000001800019DA
  0000000180001911: 44 8B 5F 20        mov         r11d,dword ptr [rdi+20h]
  0000000180001915: 4D 03 DA           add         r11,r10
  0000000180001918: 0F 1F 84 00 00 00  nop         dword ptr [rax+rax]
                    00 00
  0000000180001920: 41 8B 03           mov         eax,dword ptr [r11]
  0000000180001923: 4C 8B CD           mov         r9,rbp
  0000000180001926: 49 03 C2           add         rax,r10
  0000000180001929: 4C 2B C8           sub         r9,rax
  000000018000192C: 0F 1F 40 00        nop         dword ptr [rax]
  0000000180001930: 0F B6 10           movzx       edx,byte ptr [rax]
  0000000180001933: 42 0F B6 0C 08     movzx       ecx,byte ptr [rax+r9]
  0000000180001938: 2B D1              sub         edx,ecx
  000000018000193A: 75 07              jne         0000000180001943
  000000018000193C: 48 FF C0           inc         rax
  000000018000193F: 85 C9              test        ecx,ecx
  0000000180001941: 75 ED              jne         0000000180001930
  0000000180001943: 85 D2              test        edx,edx
  0000000180001945: 75 17              jne         000000018000195E
  0000000180001947: 8B 4F 24           mov         ecx,dword ptr [rdi+24h]
  000000018000194A: 49 03 CA           add         rcx,r10
  000000018000194D: 42 0F B7 14 41     movzx       edx,word ptr [rcx+r8*2]
  0000000180001952: 8B 4F 1C           mov         ecx,dword ptr [rdi+1Ch]
  0000000180001955: 49 03 CA           add         rcx,r10
  0000000180001958: 8B 1C 91           mov         ebx,dword ptr [rcx+rdx*4]
  000000018000195B: 49 03 DA           add         rbx,r10
  000000018000195E: 49 FF C0           inc         r8
  0000000180001961: 49 83 C3 04        add         r11,4
  0000000180001965: 4C 3B C6           cmp         r8,rsi
  0000000180001968: 72 B6              jb          0000000180001920
  000000018000196A: EB 6E              jmp         00000001800019DA
  000000018000196C: B9 0B 02 00 00     mov         ecx,20Bh
  0000000180001971: 66 3B C1           cmp         ax,cx
  0000000180001974: 75 64              jne         00000001800019DA
  0000000180001976: 41 8B BA 88 00 00  mov         edi,dword ptr [r10+88h]
                    00
  000000018000197D: 49 03 FA           add         rdi,r10
  0000000180001980: 8B 77 18           mov         esi,dword ptr [rdi+18h]
  0000000180001983: 48 85 F6           test        rsi,rsi
  0000000180001986: 74 52              je          00000001800019DA
  0000000180001988: 44 8B 5F 20        mov         r11d,dword ptr [rdi+20h]
  000000018000198C: 4D 03 DA           add         r11,r10
  000000018000198F: 90                 nop
  0000000180001990: 41 8B 03           mov         eax,dword ptr [r11]
  0000000180001993: 4C 8B CD           mov         r9,rbp
  0000000180001996: 49 03 C2           add         rax,r10
  0000000180001999: 4C 2B C8           sub         r9,rax
  000000018000199C: 0F 1F 40 00        nop         dword ptr [rax]
  00000001800019A0: 0F B6 10           movzx       edx,byte ptr [rax]
  00000001800019A3: 42 0F B6 0C 08     movzx       ecx,byte ptr [rax+r9]
  00000001800019A8: 2B D1              sub         edx,ecx
  00000001800019AA: 75 07              jne         00000001800019B3
  00000001800019AC: 48 FF C0           inc         rax
  00000001800019AF: 85 C9              test        ecx,ecx
  00000001800019B1: 75 ED              jne         00000001800019A0
  00000001800019B3: 85 D2              test        edx,edx
  00000001800019B5: 75 17              jne         00000001800019CE
  00000001800019B7: 8B 4F 24           mov         ecx,dword ptr [rdi+24h]
  00000001800019BA: 49 03 CA           add         rcx,r10
  00000001800019BD: 42 0F B7 14 41     movzx       edx,word ptr [rcx+r8*2]
  00000001800019C2: 8B 4F 1C           mov         ecx,dword ptr [rdi+1Ch]
  00000001800019C5: 49 03 CA           add         rcx,r10
  00000001800019C8: 8B 1C 91           mov         ebx,dword ptr [rcx+rdx*4]
  00000001800019CB: 49 03 DA           add         rbx,r10
  00000001800019CE: 49 FF C0           inc         r8
  00000001800019D1: 49 83 C3 04        add         r11,4
  00000001800019D5: 4C 3B C6           cmp         r8,rsi
  00000001800019D8: 72 B6              jb          0000000180001990
  00000001800019DA: 48 8B 6C 24 10     mov         rbp,qword ptr [rsp+10h]
  00000001800019DF: 48 8B C3           mov         rax,rbx
  00000001800019E2: 48 8B 5C 24 08     mov         rbx,qword ptr [rsp+8]
  00000001800019E7: 48 8B 74 24 18     mov         rsi,qword ptr [rsp+18h]
  00000001800019EC: 48 8B 7C 24 20     mov         rdi,qword ptr [rsp+20h]
  00000001800019F1: C3                 ret
  00000001800019F2: CC CC CC CC CC CC CC CC CC CC CC CC CC CC        IIIIIIIIIIIIII
ULFreeLibrary:
  0000000180001A00: 33 D2              xor         edx,edx
  0000000180001A02: 41 B8 00 80 00 00  mov         r8d,8000h
  0000000180001A08: 48 FF 25 41 16 00  jmp         qword ptr [__imp_VirtualFree]
                    00
  0000000180001A0F: CC                                               I
  0000000180001A10: CC                 int         3
  0000000180001A11: CC                 int         3
  0000000180001A12: CC                 int         3
  0000000180001A13: CC                 int         3
  0000000180001A14: CC                 int         3
  0000000180001A15: CC                 int         3
  0000000180001A16: 66 66 0F 1F 84 00  nop         word ptr [rax+rax]
                    00 00 00 00
__security_check_cookie:
  0000000180001A20: 48 3B 0D E1 25 00  cmp         rcx,qword ptr [__security_cookie]
                    00
  0000000180001A27: 75 10              jne         0000000180001A39
  0000000180001A29: 48 C1 C1 10        rol         rcx,10h
  0000000180001A2D: 66 F7 C1 FF FF     test        cx,0FFFFh
  0000000180001A32: 75 01              jne         0000000180001A35
  0000000180001A34: C3                 ret
  0000000180001A35: 48 C1 C9 10        ror         rcx,10h
  0000000180001A39: E9 96 03 00 00     jmp         __report_gsfailure
  0000000180001A3E: CC CC                                            II
dllmain_crt_dispatch:
  0000000180001A40: 48 83 EC 28        sub         rsp,28h
  0000000180001A44: 85 D2              test        edx,edx
  0000000180001A46: 74 39              je          0000000180001A81
  0000000180001A48: 83 EA 01           sub         edx,1
  0000000180001A4B: 74 28              je          0000000180001A75
  0000000180001A4D: 83 EA 01           sub         edx,1
  0000000180001A50: 74 16              je          0000000180001A68
  0000000180001A52: 83 FA 01           cmp         edx,1
  0000000180001A55: 74 0A              je          0000000180001A61
  0000000180001A57: B8 01 00 00 00     mov         eax,1
  0000000180001A5C: 48 83 C4 28        add         rsp,28h
  0000000180001A60: C3                 ret
  0000000180001A61: E8 5A 06 00 00     call        __scrt_dllmain_crt_thread_detach
  0000000180001A66: EB 05              jmp         0000000180001A6D
  0000000180001A68: E8 2B 06 00 00     call        __scrt_dllmain_crt_thread_attach
  0000000180001A6D: 0F B6 C0           movzx       eax,al
  0000000180001A70: 48 83 C4 28        add         rsp,28h
  0000000180001A74: C3                 ret
  0000000180001A75: 49 8B D0           mov         rdx,r8
  0000000180001A78: 48 83 C4 28        add         rsp,28h
  0000000180001A7C: E9 0F 00 00 00     jmp         0000000180001A90
  0000000180001A81: 4D 85 C0           test        r8,r8
  0000000180001A84: 0F 95 C1           setne       cl
  0000000180001A87: 48 83 C4 28        add         rsp,28h
  0000000180001A8B: E9 18 01 00 00     jmp         0000000180001BA8
dllmain_crt_process_attach:
  0000000180001A90: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  0000000180001A95: 48 89 74 24 10     mov         qword ptr [rsp+10h],rsi
  0000000180001A9A: 48 89 7C 24 20     mov         qword ptr [rsp+20h],rdi
  0000000180001A9F: 41 56              push        r14
  0000000180001AA1: 48 83 EC 20        sub         rsp,20h
  0000000180001AA5: 48 8B F2           mov         rsi,rdx
  0000000180001AA8: 4C 8B F1           mov         r14,rcx
  0000000180001AAB: 33 C9              xor         ecx,ecx
  0000000180001AAD: E8 CA 06 00 00     call        __scrt_initialize_crt
  0000000180001AB2: 84 C0              test        al,al
  0000000180001AB4: 0F 84 C8 00 00 00  je          0000000180001B82
  0000000180001ABA: E8 51 05 00 00     call        __scrt_acquire_startup_lock
  0000000180001ABF: 8A D8              mov         bl,al
  0000000180001AC1: 88 44 24 40        mov         byte ptr [rsp+40h],al
  0000000180001AC5: 40 B7 01           mov         dil,1
  0000000180001AC8: 83 3D 11 2B 00 00  cmp         dword ptr [__scrt_current_native_startup_state],0
                    00
  0000000180001ACF: 0F 85 C5 00 00 00  jne         0000000180001B9A
  0000000180001AD5: C7 05 01 2B 00 00  mov         dword ptr [__scrt_current_native_startup_state],1
                    01 00 00 00
  0000000180001ADF: E8 9C 05 00 00     call        __scrt_dllmain_before_initialize_c
  0000000180001AE4: 84 C0              test        al,al
  0000000180001AE6: 74 4F              je          0000000180001B37
  0000000180001AE8: E8 AB 09 00 00     call        _RTC_Initialize
  0000000180001AED: E8 D6 04 00 00     call        ?__scrt_initialize_type_info@@YAXXZ
  0000000180001AF2: E8 FD 04 00 00     call        __scrt_initialize_default_local_stdio_options
  0000000180001AF7: 48 8D 15 92 16 00  lea         rdx,[__xi_z]
                    00
  0000000180001AFE: 48 8D 0D 83 16 00  lea         rcx,[__xi_a]
                    00
  0000000180001B05: E8 DE 0B 00 00     call        _initterm_e
  0000000180001B0A: 85 C0              test        eax,eax
  0000000180001B0C: 75 29              jne         0000000180001B37
  0000000180001B0E: E8 39 05 00 00     call        __scrt_dllmain_after_initialize_c
  0000000180001B13: 84 C0              test        al,al
  0000000180001B15: 74 20              je          0000000180001B37
  0000000180001B17: 48 8D 15 62 16 00  lea         rdx,[__xc_z]
                    00
  0000000180001B1E: 48 8D 0D 53 16 00  lea         rcx,[__xc_a]
                    00
  0000000180001B25: E8 B8 0B 00 00     call        _initterm
  0000000180001B2A: C7 05 AC 2A 00 00  mov         dword ptr [__scrt_current_native_startup_state],2
                    02 00 00 00
  0000000180001B34: 40 32 FF           xor         dil,dil
  0000000180001B37: 8A CB              mov         cl,bl
  0000000180001B39: E8 AE 07 00 00     call        __scrt_release_startup_lock
  0000000180001B3E: 40 84 FF           test        dil,dil
  0000000180001B41: 75 3F              jne         0000000180001B82
  0000000180001B43: E8 F4 07 00 00     call        __scrt_get_dyn_tls_init_callback
  0000000180001B48: 48 8B D8           mov         rbx,rax
  0000000180001B4B: 48 83 38 00        cmp         qword ptr [rax],0
  0000000180001B4F: 74 24              je          0000000180001B75
  0000000180001B51: 48 8B C8           mov         rcx,rax
  0000000180001B54: E8 FB 06 00 00     call        __scrt_is_nonwritable_in_current_image
  0000000180001B59: 84 C0              test        al,al
  0000000180001B5B: 74 18              je          0000000180001B75
  0000000180001B5D: 4C 8B C6           mov         r8,rsi
  0000000180001B60: BA 02 00 00 00     mov         edx,2
  0000000180001B65: 49 8B CE           mov         rcx,r14
  0000000180001B68: 48 8B 03           mov         rax,qword ptr [rbx]
  0000000180001B6B: 4C 8B 0D EE 15 00  mov         r9,qword ptr [__guard_dispatch_icall_fptr]
                    00
  0000000180001B72: 41 FF D1           call        r9
  0000000180001B75: FF 05 C5 24 00 00  inc         dword ptr [180004040h]
  0000000180001B7B: B8 01 00 00 00     mov         eax,1
  0000000180001B80: EB 02              jmp         0000000180001B84
  0000000180001B82: 33 C0              xor         eax,eax
  0000000180001B84: 48 8B 5C 24 30     mov         rbx,qword ptr [rsp+30h]
  0000000180001B89: 48 8B 74 24 38     mov         rsi,qword ptr [rsp+38h]
  0000000180001B8E: 48 8B 7C 24 48     mov         rdi,qword ptr [rsp+48h]
  0000000180001B93: 48 83 C4 20        add         rsp,20h
  0000000180001B97: 41 5E              pop         r14
  0000000180001B99: C3                 ret
  0000000180001B9A: B9 07 00 00 00     mov         ecx,7
  0000000180001B9F: E8 A8 07 00 00     call        __scrt_fastfail
  0000000180001BA4: 90                 nop
  0000000180001BA5: CC                 int         3
  0000000180001BA6: CC CC                                            II
dllmain_crt_process_detach:
  0000000180001BA8: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  0000000180001BAD: 57                 push        rdi
  0000000180001BAE: 48 83 EC 30        sub         rsp,30h
  0000000180001BB2: 40 8A F9           mov         dil,cl
  0000000180001BB5: 8B 05 85 24 00 00  mov         eax,dword ptr [180004040h]
  0000000180001BBB: 85 C0              test        eax,eax
  0000000180001BBD: 7F 0D              jg          0000000180001BCC
  0000000180001BBF: 33 C0              xor         eax,eax
  0000000180001BC1: 48 8B 5C 24 40     mov         rbx,qword ptr [rsp+40h]
  0000000180001BC6: 48 83 C4 30        add         rsp,30h
  0000000180001BCA: 5F                 pop         rdi
  0000000180001BCB: C3                 ret
  0000000180001BCC: FF C8              dec         eax
  0000000180001BCE: 89 05 6C 24 00 00  mov         dword ptr [180004040h],eax
  0000000180001BD4: E8 37 04 00 00     call        __scrt_acquire_startup_lock
  0000000180001BD9: 8A D8              mov         bl,al
  0000000180001BDB: 88 44 24 20        mov         byte ptr [rsp+20h],al
  0000000180001BDF: 83 3D FA 29 00 00  cmp         dword ptr [__scrt_current_native_startup_state],2
                    02
  0000000180001BE6: 75 37              jne         0000000180001C1F
  0000000180001BE8: E8 4B 05 00 00     call        __scrt_dllmain_uninitialize_c
  0000000180001BED: E8 E6 03 00 00     call        ?__scrt_uninitialize_type_info@@YAXXZ
  0000000180001BF2: E8 DD 08 00 00     call        _RTC_Terminate
  0000000180001BF7: 83 25 E2 29 00 00  and         dword ptr [__scrt_current_native_startup_state],0
                    00
  0000000180001BFE: 8A CB              mov         cl,bl
  0000000180001C00: E8 E7 06 00 00     call        __scrt_release_startup_lock
  0000000180001C05: 33 D2              xor         edx,edx
  0000000180001C07: 40 8A CF           mov         cl,dil
  0000000180001C0A: E8 01 07 00 00     call        __scrt_uninitialize_crt
  0000000180001C0F: F6 D8              neg         al
  0000000180001C11: 1B DB              sbb         ebx,ebx
  0000000180001C13: 83 E3 01           and         ebx,1
  0000000180001C16: E8 4D 05 00 00     call        __scrt_dllmain_uninitialize_critical
  0000000180001C1B: 8B C3              mov         eax,ebx
  0000000180001C1D: EB A2              jmp         0000000180001BC1
  0000000180001C1F: B9 07 00 00 00     mov         ecx,7
  0000000180001C24: E8 23 07 00 00     call        __scrt_fastfail
  0000000180001C29: 90                 nop
  0000000180001C2A: 90                 nop
  0000000180001C2B: CC                 int         3
dllmain_dispatch:
  0000000180001C2C: 48 8B C4           mov         rax,rsp
  0000000180001C2F: 48 89 58 20        mov         qword ptr [rax+20h],rbx
  0000000180001C33: 4C 89 40 18        mov         qword ptr [rax+18h],r8
  0000000180001C37: 89 50 10           mov         dword ptr [rax+10h],edx
  0000000180001C3A: 48 89 48 08        mov         qword ptr [rax+8],rcx
  0000000180001C3E: 56                 push        rsi
  0000000180001C3F: 57                 push        rdi
  0000000180001C40: 41 56              push        r14
  0000000180001C42: 48 83 EC 40        sub         rsp,40h
  0000000180001C46: 49 8B F0           mov         rsi,r8
  0000000180001C49: 8B FA              mov         edi,edx
  0000000180001C4B: 4C 8B F1           mov         r14,rcx
  0000000180001C4E: 85 D2              test        edx,edx
  0000000180001C50: 75 0F              jne         0000000180001C61
  0000000180001C52: 39 15 E8 23 00 00  cmp         dword ptr [180004040h],edx
  0000000180001C58: 7F 07              jg          0000000180001C61
  0000000180001C5A: 33 C0              xor         eax,eax
  0000000180001C5C: E9 EE 00 00 00     jmp         0000000180001D4F
  0000000180001C61: 8D 42 FF           lea         eax,[rdx-1]
  0000000180001C64: 83 F8 01           cmp         eax,1
  0000000180001C67: 77 45              ja          0000000180001CAE
  0000000180001C69: 48 8B 05 50 15 00  mov         rax,qword ptr [_pDefaultRawDllMain]
                    00
  0000000180001C70: 48 85 C0           test        rax,rax
  0000000180001C73: 75 0A              jne         0000000180001C7F
  0000000180001C75: C7 44 24 30 01 00  mov         dword ptr [rsp+30h],1
                    00 00
  0000000180001C7D: EB 14              jmp         0000000180001C93
  0000000180001C7F: FF 15 DB 14 00 00  call        qword ptr [__guard_dispatch_icall_fptr]
  0000000180001C85: 8B D8              mov         ebx,eax
  0000000180001C87: 89 44 24 30        mov         dword ptr [rsp+30h],eax
  0000000180001C8B: 85 C0              test        eax,eax
  0000000180001C8D: 0F 84 B2 00 00 00  je          0000000180001D45
  0000000180001C93: 4C 8B C6           mov         r8,rsi
  0000000180001C96: 8B D7              mov         edx,edi
  0000000180001C98: 49 8B CE           mov         rcx,r14
  0000000180001C9B: E8 A0 FD FF FF     call        0000000180001A40
  0000000180001CA0: 8B D8              mov         ebx,eax
  0000000180001CA2: 89 44 24 30        mov         dword ptr [rsp+30h],eax
  0000000180001CA6: 85 C0              test        eax,eax
  0000000180001CA8: 0F 84 97 00 00 00  je          0000000180001D45
  0000000180001CAE: 4C 8B C6           mov         r8,rsi
  0000000180001CB1: 8B D7              mov         edx,edi
  0000000180001CB3: 49 8B CE           mov         rcx,r14
  0000000180001CB6: E8 45 F3 FF FF     call        DllMain
  0000000180001CBB: 8B D8              mov         ebx,eax
  0000000180001CBD: 89 44 24 30        mov         dword ptr [rsp+30h],eax
  0000000180001CC1: 83 FF 01           cmp         edi,1
  0000000180001CC4: 75 36              jne         0000000180001CFC
  0000000180001CC6: 85 C0              test        eax,eax
  0000000180001CC8: 75 32              jne         0000000180001CFC
  0000000180001CCA: 4C 8B C6           mov         r8,rsi
  0000000180001CCD: 33 D2              xor         edx,edx
  0000000180001CCF: 49 8B CE           mov         rcx,r14
  0000000180001CD2: E8 29 F3 FF FF     call        DllMain
  0000000180001CD7: 48 85 F6           test        rsi,rsi
  0000000180001CDA: 0F 95 C1           setne       cl
  0000000180001CDD: E8 C6 FE FF FF     call        0000000180001BA8
  0000000180001CE2: 48 8B 05 D7 14 00  mov         rax,qword ptr [_pDefaultRawDllMain]
                    00
  0000000180001CE9: 48 85 C0           test        rax,rax
  0000000180001CEC: 74 0E              je          0000000180001CFC
  0000000180001CEE: 4C 8B C6           mov         r8,rsi
  0000000180001CF1: 33 D2              xor         edx,edx
  0000000180001CF3: 49 8B CE           mov         rcx,r14
  0000000180001CF6: FF 15 64 14 00 00  call        qword ptr [__guard_dispatch_icall_fptr]
  0000000180001CFC: 85 FF              test        edi,edi
  0000000180001CFE: 74 05              je          0000000180001D05
  0000000180001D00: 83 FF 03           cmp         edi,3
  0000000180001D03: 75 40              jne         0000000180001D45
  0000000180001D05: 4C 8B C6           mov         r8,rsi
  0000000180001D08: 8B D7              mov         edx,edi
  0000000180001D0A: 49 8B CE           mov         rcx,r14
  0000000180001D0D: E8 2E FD FF FF     call        0000000180001A40
  0000000180001D12: 8B D8              mov         ebx,eax
  0000000180001D14: 89 44 24 30        mov         dword ptr [rsp+30h],eax
  0000000180001D18: 85 C0              test        eax,eax
  0000000180001D1A: 74 29              je          0000000180001D45
  0000000180001D1C: 48 8B 05 9D 14 00  mov         rax,qword ptr [_pDefaultRawDllMain]
                    00
  0000000180001D23: 48 85 C0           test        rax,rax
  0000000180001D26: 75 09              jne         0000000180001D31
  0000000180001D28: 8D 58 01           lea         ebx,[rax+1]
  0000000180001D2B: 89 5C 24 30        mov         dword ptr [rsp+30h],ebx
  0000000180001D2F: EB 14              jmp         0000000180001D45
  0000000180001D31: 4C 8B C6           mov         r8,rsi
  0000000180001D34: 8B D7              mov         edx,edi
  0000000180001D36: 49 8B CE           mov         rcx,r14
  0000000180001D39: FF 15 21 14 00 00  call        qword ptr [__guard_dispatch_icall_fptr]
  0000000180001D3F: 8B D8              mov         ebx,eax
  0000000180001D41: 89 44 24 30        mov         dword ptr [rsp+30h],eax
  0000000180001D45: EB 06              jmp         0000000180001D4D
  0000000180001D47: 33 DB              xor         ebx,ebx
  0000000180001D49: 89 5C 24 30        mov         dword ptr [rsp+30h],ebx
  0000000180001D4D: 8B C3              mov         eax,ebx
  0000000180001D4F: 48 8B 5C 24 78     mov         rbx,qword ptr [rsp+78h]
  0000000180001D54: 48 83 C4 40        add         rsp,40h
  0000000180001D58: 41 5E              pop         r14
  0000000180001D5A: 5F                 pop         rdi
  0000000180001D5B: 5E                 pop         rsi
  0000000180001D5C: C3                 ret
  0000000180001D5D: CC CC CC                                         III
_DllMainCRTStartup:
  0000000180001D60: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  0000000180001D65: 48 89 74 24 10     mov         qword ptr [rsp+10h],rsi
  0000000180001D6A: 57                 push        rdi
  0000000180001D6B: 48 83 EC 20        sub         rsp,20h
  0000000180001D6F: 49 8B F8           mov         rdi,r8
  0000000180001D72: 8B DA              mov         ebx,edx
  0000000180001D74: 48 8B F1           mov         rsi,rcx
  0000000180001D77: 83 FA 01           cmp         edx,1
  0000000180001D7A: 75 05              jne         0000000180001D81
  0000000180001D7C: E8 9B 01 00 00     call        __security_init_cookie
  0000000180001D81: 4C 8B C7           mov         r8,rdi
  0000000180001D84: 8B D3              mov         edx,ebx
  0000000180001D86: 48 8B CE           mov         rcx,rsi
  0000000180001D89: 48 8B 5C 24 30     mov         rbx,qword ptr [rsp+30h]
  0000000180001D8E: 48 8B 74 24 38     mov         rsi,qword ptr [rsp+38h]
  0000000180001D93: 48 83 C4 20        add         rsp,20h
  0000000180001D97: 5F                 pop         rdi
  0000000180001D98: E9 8F FE FF FF     jmp         0000000180001C2C
  0000000180001D9D: CC CC CC                                         III
__raise_securityfailure:
  0000000180001DA0: 40 53              push        rbx
  0000000180001DA2: 48 83 EC 20        sub         rsp,20h
  0000000180001DA6: 48 8B D9           mov         rbx,rcx
  0000000180001DA9: 33 C9              xor         ecx,ecx
  0000000180001DAB: FF 15 BF 12 00 00  call        qword ptr [__imp_SetUnhandledExceptionFilter]
  0000000180001DB1: 48 8B CB           mov         rcx,rbx
  0000000180001DB4: FF 15 AE 12 00 00  call        qword ptr [__imp_UnhandledExceptionFilter]
  0000000180001DBA: FF 15 80 12 00 00  call        qword ptr [__imp_GetCurrentProcess]
  0000000180001DC0: 48 8B C8           mov         rcx,rax
  0000000180001DC3: BA 09 04 00 C0     mov         edx,0C0000409h
  0000000180001DC8: 48 83 C4 20        add         rsp,20h
  0000000180001DCC: 5B                 pop         rbx
  0000000180001DCD: 48 FF 25 A4 12 00  jmp         qword ptr [__imp_TerminateProcess]
                    00
__report_gsfailure:
  0000000180001DD4: 48 89 4C 24 08     mov         qword ptr [rsp+8],rcx
  0000000180001DD9: 48 83 EC 38        sub         rsp,38h
  0000000180001DDD: B9 17 00 00 00     mov         ecx,17h
  0000000180001DE2: FF 15 98 12 00 00  call        qword ptr [__imp_IsProcessorFeaturePresent]
  0000000180001DE8: 85 C0              test        eax,eax
  0000000180001DEA: 74 07              je          0000000180001DF3
  0000000180001DEC: B9 02 00 00 00     mov         ecx,2
  0000000180001DF1: CD 29              int         29h
  0000000180001DF3: 48 8D 0D F6 22 00  lea         rcx,[1800040F0h]
                    00
  0000000180001DFA: E8 A9 00 00 00     call        0000000180001EA8
  0000000180001DFF: 48 8B 44 24 38     mov         rax,qword ptr [rsp+38h]
  0000000180001E04: 48 89 05 DD 23 00  mov         qword ptr [1800041E8h],rax
                    00
  0000000180001E0B: 48 8D 44 24 38     lea         rax,[rsp+38h]
  0000000180001E10: 48 83 C0 08        add         rax,8
  0000000180001E14: 48 89 05 6D 23 00  mov         qword ptr [180004188h],rax
                    00
  0000000180001E1B: 48 8B 05 C6 23 00  mov         rax,qword ptr [1800041E8h]
                    00
  0000000180001E22: 48 89 05 37 22 00  mov         qword ptr [180004060h],rax
                    00
  0000000180001E29: 48 8B 44 24 40     mov         rax,qword ptr [rsp+40h]
  0000000180001E2E: 48 89 05 3B 23 00  mov         qword ptr [180004170h],rax
                    00
  0000000180001E35: C7 05 11 22 00 00  mov         dword ptr [180004050h],0C0000409h
                    09 04 00 C0
  0000000180001E3F: C7 05 0B 22 00 00  mov         dword ptr [180004054h],1
                    01 00 00 00
  0000000180001E49: C7 05 15 22 00 00  mov         dword ptr [180004068h],1
                    01 00 00 00
  0000000180001E53: B8 08 00 00 00     mov         eax,8
  0000000180001E58: 48 6B C0 00        imul        rax,rax,0
  0000000180001E5C: 48 8D 0D 0D 22 00  lea         rcx,[180004070h]
                    00
  0000000180001E63: 48 C7 04 01 02 00  mov         qword ptr [rcx+rax],2
                    00 00
  0000000180001E6B: B8 08 00 00 00     mov         eax,8
  0000000180001E70: 48 6B C0 00        imul        rax,rax,0
  0000000180001E74: 48 8B 0D 8D 21 00  mov         rcx,qword ptr [__security_cookie]
                    00
  0000000180001E7B: 48 89 4C 04 20     mov         qword ptr [rsp+rax+20h],rcx
  0000000180001E80: B8 08 00 00 00     mov         eax,8
  0000000180001E85: 48 6B C0 01        imul        rax,rax,1
  0000000180001E89: 48 8B 0D 70 21 00  mov         rcx,qword ptr [__security_cookie_complement]
                    00
  0000000180001E90: 48 89 4C 04 20     mov         qword ptr [rsp+rax+20h],rcx
  0000000180001E95: 48 8D 0D 2C 13 00  lea         rcx,[1800031C8h]
                    00
  0000000180001E9C: E8 FF FE FF FF     call        __raise_securityfailure
  0000000180001EA1: 48 83 C4 38        add         rsp,38h
  0000000180001EA5: C3                 ret
  0000000180001EA6: CC CC                                            II
capture_previous_context:
  0000000180001EA8: 40 53              push        rbx
  0000000180001EAA: 56                 push        rsi
  0000000180001EAB: 57                 push        rdi
  0000000180001EAC: 48 83 EC 40        sub         rsp,40h
  0000000180001EB0: 48 8B D9           mov         rbx,rcx
  0000000180001EB3: FF 15 CF 11 00 00  call        qword ptr [__imp_RtlCaptureContext]
  0000000180001EB9: 48 8B B3 F8 00 00  mov         rsi,qword ptr [rbx+0F8h]
                    00
  0000000180001EC0: 33 FF              xor         edi,edi
  0000000180001EC2: 45 33 C0           xor         r8d,r8d
  0000000180001EC5: 48 8D 54 24 60     lea         rdx,[rsp+60h]
  0000000180001ECA: 48 8B CE           mov         rcx,rsi
  0000000180001ECD: FF 15 85 11 00 00  call        qword ptr [__imp_RtlLookupFunctionEntry]
  0000000180001ED3: 48 85 C0           test        rax,rax
  0000000180001ED6: 74 39              je          0000000180001F11
  0000000180001ED8: 48 83 64 24 38 00  and         qword ptr [rsp+38h],0
  0000000180001EDE: 48 8D 4C 24 68     lea         rcx,[rsp+68h]
  0000000180001EE3: 48 8B 54 24 60     mov         rdx,qword ptr [rsp+60h]
  0000000180001EE8: 4C 8B C8           mov         r9,rax
  0000000180001EEB: 48 89 4C 24 30     mov         qword ptr [rsp+30h],rcx
  0000000180001EF0: 4C 8B C6           mov         r8,rsi
  0000000180001EF3: 48 8D 4C 24 70     lea         rcx,[rsp+70h]
  0000000180001EF8: 48 89 4C 24 28     mov         qword ptr [rsp+28h],rcx
  0000000180001EFD: 33 C9              xor         ecx,ecx
  0000000180001EFF: 48 89 5C 24 20     mov         qword ptr [rsp+20h],rbx
  0000000180001F04: FF 15 56 11 00 00  call        qword ptr [__imp_RtlVirtualUnwind]
  0000000180001F0A: FF C7              inc         edi
  0000000180001F0C: 83 FF 02           cmp         edi,2
  0000000180001F0F: 7C B1              jl          0000000180001EC2
  0000000180001F11: 48 83 C4 40        add         rsp,40h
  0000000180001F15: 5F                 pop         rdi
  0000000180001F16: 5E                 pop         rsi
  0000000180001F17: 5B                 pop         rbx
  0000000180001F18: C3                 ret
  0000000180001F19: CC CC CC                                         III
__security_init_cookie:
  0000000180001F1C: 48 89 5C 24 20     mov         qword ptr [rsp+20h],rbx
  0000000180001F21: 55                 push        rbp
  0000000180001F22: 48 8B EC           mov         rbp,rsp
  0000000180001F25: 48 83 EC 20        sub         rsp,20h
  0000000180001F29: 48 8B 05 D8 20 00  mov         rax,qword ptr [__security_cookie]
                    00
  0000000180001F30: 48 BB 32 A2 DF 2D  mov         rbx,2B992DDFA232h
                    99 2B 00 00
  0000000180001F3A: 48 3B C3           cmp         rax,rbx
  0000000180001F3D: 75 74              jne         0000000180001FB3
  0000000180001F3F: 48 83 65 18 00     and         qword ptr [rbp+18h],0
  0000000180001F44: 48 8D 4D 18        lea         rcx,[rbp+18h]
  0000000180001F48: FF 15 52 11 00 00  call        qword ptr [__imp_GetSystemTimeAsFileTime]
  0000000180001F4E: 48 8B 45 18        mov         rax,qword ptr [rbp+18h]
  0000000180001F52: 48 89 45 10        mov         qword ptr [rbp+10h],rax
  0000000180001F56: FF 15 4C 11 00 00  call        qword ptr [__imp_GetCurrentThreadId]
  0000000180001F5C: 8B C0              mov         eax,eax
  0000000180001F5E: 48 31 45 10        xor         qword ptr [rbp+10h],rax
  0000000180001F62: FF 15 48 11 00 00  call        qword ptr [__imp_GetCurrentProcessId]
  0000000180001F68: 8B C0              mov         eax,eax
  0000000180001F6A: 48 8D 4D 20        lea         rcx,[rbp+20h]
  0000000180001F6E: 48 31 45 10        xor         qword ptr [rbp+10h],rax
  0000000180001F72: FF 15 40 11 00 00  call        qword ptr [__imp_QueryPerformanceCounter]
  0000000180001F78: 8B 45 20           mov         eax,dword ptr [rbp+20h]
  0000000180001F7B: 48 8D 4D 10        lea         rcx,[rbp+10h]
  0000000180001F7F: 48 C1 E0 20        shl         rax,20h
  0000000180001F83: 48 33 45 20        xor         rax,qword ptr [rbp+20h]
  0000000180001F87: 48 33 45 10        xor         rax,qword ptr [rbp+10h]
  0000000180001F8B: 48 33 C1           xor         rax,rcx
  0000000180001F8E: 48 B9 FF FF FF FF  mov         rcx,0FFFFFFFFFFFFh
                    FF FF 00 00
  0000000180001F98: 48 23 C1           and         rax,rcx
  0000000180001F9B: 48 B9 33 A2 DF 2D  mov         rcx,2B992DDFA233h
                    99 2B 00 00
  0000000180001FA5: 48 3B C3           cmp         rax,rbx
  0000000180001FA8: 48 0F 44 C1        cmove       rax,rcx
  0000000180001FAC: 48 89 05 55 20 00  mov         qword ptr [__security_cookie],rax
                    00
  0000000180001FB3: 48 8B 5C 24 48     mov         rbx,qword ptr [rsp+48h]
  0000000180001FB8: 48 F7 D0           not         rax
  0000000180001FBB: 48 89 05 3E 20 00  mov         qword ptr [__security_cookie_complement],rax
                    00
  0000000180001FC2: 48 83 C4 20        add         rsp,20h
  0000000180001FC6: 5D                 pop         rbp
  0000000180001FC7: C3                 ret
?__scrt_initialize_type_info@@YAXXZ:
  0000000180001FC8: 48 8D 0D F1 25 00  lea         rcx,[?__type_info_root_node@@3U__type_info_node@@A]
                    00
  0000000180001FCF: 48 FF 25 C2 10 00  jmp         qword ptr [__imp_InitializeSListHead]
                    00
  0000000180001FD6: CC CC                                            II
?__scrt_uninitialize_type_info@@YAXXZ:
  0000000180001FD8: 48 8D 0D E1 25 00  lea         rcx,[?__type_info_root_node@@3U__type_info_node@@A]
                    00
  0000000180001FDF: E9 F2 06 00 00     jmp         __std_type_info_destroy_list
__local_stdio_printf_options:
  0000000180001FE4: 48 8D 05 E5 25 00  lea         rax,[?_OptionsStorage@?1??__local_stdio_printf_options@@9@4_KA]
                    00
  0000000180001FEB: C3                 ret
__local_stdio_scanf_options:
  0000000180001FEC: 48 8D 05 E5 25 00  lea         rax,[?_OptionsStorage@?1??__local_stdio_scanf_options@@9@4_KA]
                    00
  0000000180001FF3: C3                 ret
__scrt_initialize_default_local_stdio_options:
  0000000180001FF4: 48 83 EC 28        sub         rsp,28h
  0000000180001FF8: E8 E7 FF FF FF     call        __local_stdio_printf_options
  0000000180001FFD: 48 83 08 24        or          qword ptr [rax],24h
  0000000180002001: E8 E6 FF FF FF     call        __local_stdio_scanf_options
  0000000180002006: 48 83 08 02        or          qword ptr [rax],2
  000000018000200A: 48 83 C4 28        add         rsp,28h
  000000018000200E: C3                 ret
  000000018000200F: CC                                               I
__scrt_acquire_startup_lock:
  0000000180002010: 48 83 EC 28        sub         rsp,28h
  0000000180002014: E8 9F 06 00 00     call        __scrt_is_ucrt_dll_in_use
  0000000180002019: 85 C0              test        eax,eax
  000000018000201B: 74 21              je          000000018000203E
  000000018000201D: 65 48 8B 04 25 30  mov         rax,qword ptr gs:[30h]
                    00 00 00
  0000000180002026: 48 8B 48 08        mov         rcx,qword ptr [rax+8]
  000000018000202A: EB 05              jmp         0000000180002031
  000000018000202C: 48 3B C8           cmp         rcx,rax
  000000018000202F: 74 14              je          0000000180002045
  0000000180002031: 33 C0              xor         eax,eax
  0000000180002033: F0 48 0F B1 0D AC  lock cmpxchg qword ptr [__scrt_native_startup_lock],rcx
                    25 00 00
  000000018000203C: 75 EE              jne         000000018000202C
  000000018000203E: 32 C0              xor         al,al
  0000000180002040: 48 83 C4 28        add         rsp,28h
  0000000180002044: C3                 ret
  0000000180002045: B0 01              mov         al,1
  0000000180002047: EB F7              jmp         0000000180002040
  0000000180002049: CC CC CC                                         III
__scrt_dllmain_after_initialize_c:
  000000018000204C: 48 83 EC 28        sub         rsp,28h
  0000000180002050: E8 63 06 00 00     call        __scrt_is_ucrt_dll_in_use
  0000000180002055: 85 C0              test        eax,eax
  0000000180002057: 74 07              je          0000000180002060
  0000000180002059: E8 B6 04 00 00     call        __isa_available_init
  000000018000205E: EB 19              jmp         0000000180002079
  0000000180002060: E8 9B EF FF FF     call        DllMain
  0000000180002065: 8B C8              mov         ecx,eax
  0000000180002067: E8 88 06 00 00     call        _configure_narrow_argv
  000000018000206C: 85 C0              test        eax,eax
  000000018000206E: 74 04              je          0000000180002074
  0000000180002070: 32 C0              xor         al,al
  0000000180002072: EB 07              jmp         000000018000207B
  0000000180002074: E8 81 06 00 00     call        _initialize_narrow_environment
  0000000180002079: B0 01              mov         al,1
  000000018000207B: 48 83 C4 28        add         rsp,28h
  000000018000207F: C3                 ret
__scrt_dllmain_before_initialize_c:
  0000000180002080: 48 83 EC 28        sub         rsp,28h
  0000000180002084: 33 C9              xor         ecx,ecx
  0000000180002086: E8 3D 01 00 00     call        __scrt_initialize_onexit_tables
  000000018000208B: 84 C0              test        al,al
  000000018000208D: 0F 95 C0           setne       al
  0000000180002090: 48 83 C4 28        add         rsp,28h
  0000000180002094: C3                 ret
  0000000180002095: CC CC CC                                         III
__scrt_dllmain_crt_thread_attach:
  0000000180002098: 48 83 EC 28        sub         rsp,28h
  000000018000209C: E8 73 06 00 00     call        __acrt_initialize
  00000001800020A1: 84 C0              test        al,al
  00000001800020A3: 75 04              jne         00000001800020A9
  00000001800020A5: 32 C0              xor         al,al
  00000001800020A7: EB 12              jmp         00000001800020BB
  00000001800020A9: E8 66 06 00 00     call        __acrt_initialize
  00000001800020AE: 84 C0              test        al,al
  00000001800020B0: 75 07              jne         00000001800020B9
  00000001800020B2: E8 5D 06 00 00     call        __acrt_initialize
  00000001800020B7: EB EC              jmp         00000001800020A5
  00000001800020B9: B0 01              mov         al,1
  00000001800020BB: 48 83 C4 28        add         rsp,28h
  00000001800020BF: C3                 ret
__scrt_dllmain_crt_thread_detach:
  00000001800020C0: 48 83 EC 28        sub         rsp,28h
  00000001800020C4: E8 4B 06 00 00     call        __acrt_initialize
  00000001800020C9: E8 46 06 00 00     call        __acrt_initialize
  00000001800020CE: B0 01              mov         al,1
  00000001800020D0: 48 83 C4 28        add         rsp,28h
  00000001800020D4: C3                 ret
  00000001800020D5: CC CC CC                                         III
__scrt_dllmain_exception_filter:
  00000001800020D8: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  00000001800020DD: 48 89 6C 24 10     mov         qword ptr [rsp+10h],rbp
  00000001800020E2: 48 89 74 24 18     mov         qword ptr [rsp+18h],rsi
  00000001800020E7: 57                 push        rdi
  00000001800020E8: 48 83 EC 20        sub         rsp,20h
  00000001800020EC: 49 8B F9           mov         rdi,r9
  00000001800020EF: 49 8B F0           mov         rsi,r8
  00000001800020F2: 8B DA              mov         ebx,edx
  00000001800020F4: 48 8B E9           mov         rbp,rcx
  00000001800020F7: E8 BC 05 00 00     call        __scrt_is_ucrt_dll_in_use
  00000001800020FC: 85 C0              test        eax,eax
  00000001800020FE: 75 16              jne         0000000180002116
  0000000180002100: 83 FB 01           cmp         ebx,1
  0000000180002103: 75 11              jne         0000000180002116
  0000000180002105: 4C 8B C6           mov         r8,rsi
  0000000180002108: 33 D2              xor         edx,edx
  000000018000210A: 48 8B CD           mov         rcx,rbp
  000000018000210D: 48 8B C7           mov         rax,rdi
  0000000180002110: FF 15 4A 10 00 00  call        qword ptr [__guard_dispatch_icall_fptr]
  0000000180002116: 48 8B 54 24 58     mov         rdx,qword ptr [rsp+58h]
  000000018000211B: 8B 4C 24 50        mov         ecx,dword ptr [rsp+50h]
  000000018000211F: 48 8B 5C 24 30     mov         rbx,qword ptr [rsp+30h]
  0000000180002124: 48 8B 6C 24 38     mov         rbp,qword ptr [rsp+38h]
  0000000180002129: 48 8B 74 24 40     mov         rsi,qword ptr [rsp+40h]
  000000018000212E: 48 83 C4 20        add         rsp,20h
  0000000180002132: 5F                 pop         rdi
  0000000180002133: E9 B6 05 00 00     jmp         _seh_filter_dll
__scrt_dllmain_uninitialize_c:
  0000000180002138: 48 83 EC 28        sub         rsp,28h
  000000018000213C: E8 77 05 00 00     call        __scrt_is_ucrt_dll_in_use
  0000000180002141: 85 C0              test        eax,eax
  0000000180002143: 74 10              je          0000000180002155
  0000000180002145: 48 8D 0D AC 24 00  lea         rcx,[1800045F8h]
                    00
  000000018000214C: 48 83 C4 28        add         rsp,28h
  0000000180002150: E9 B1 05 00 00     jmp         _execute_onexit_table
  0000000180002155: E8 BE 05 00 00     call        __scrt_stub_for_is_c_termination_complete
  000000018000215A: 85 C0              test        eax,eax
  000000018000215C: 75 05              jne         0000000180002163
  000000018000215E: E8 A9 05 00 00     call        _cexit
  0000000180002163: 48 83 C4 28        add         rsp,28h
  0000000180002167: C3                 ret
__scrt_dllmain_uninitialize_critical:
  0000000180002168: 48 83 EC 28        sub         rsp,28h
  000000018000216C: 33 C9              xor         ecx,ecx
  000000018000216E: E8 A1 05 00 00     call        __acrt_initialize
  0000000180002173: 48 83 C4 28        add         rsp,28h
  0000000180002177: E9 98 05 00 00     jmp         __acrt_initialize
__scrt_initialize_crt:
  000000018000217C: 40 53              push        rbx
  000000018000217E: 48 83 EC 20        sub         rsp,20h
  0000000180002182: 0F B6 05 67 24 00  movzx       eax,byte ptr [1800045F0h]
                    00
  0000000180002189: 85 C9              test        ecx,ecx
  000000018000218B: BB 01 00 00 00     mov         ebx,1
  0000000180002190: 0F 44 C3           cmove       eax,ebx
  0000000180002193: 88 05 57 24 00 00  mov         byte ptr [1800045F0h],al
  0000000180002199: E8 76 03 00 00     call        __isa_available_init
  000000018000219E: E8 71 05 00 00     call        __acrt_initialize
  00000001800021A3: 84 C0              test        al,al
  00000001800021A5: 75 04              jne         00000001800021AB
  00000001800021A7: 32 C0              xor         al,al
  00000001800021A9: EB 14              jmp         00000001800021BF
  00000001800021AB: E8 64 05 00 00     call        __acrt_initialize
  00000001800021B0: 84 C0              test        al,al
  00000001800021B2: 75 09              jne         00000001800021BD
  00000001800021B4: 33 C9              xor         ecx,ecx
  00000001800021B6: E8 59 05 00 00     call        __acrt_initialize
  00000001800021BB: EB EA              jmp         00000001800021A7
  00000001800021BD: 8A C3              mov         al,bl
  00000001800021BF: 48 83 C4 20        add         rsp,20h
  00000001800021C3: 5B                 pop         rbx
  00000001800021C4: C3                 ret
  00000001800021C5: CC CC CC                                         III
__scrt_initialize_onexit_tables:
  00000001800021C8: 40 53              push        rbx
  00000001800021CA: 48 83 EC 20        sub         rsp,20h
  00000001800021CE: 80 3D 1C 24 00 00  cmp         byte ptr [1800045F1h],0
                    00
  00000001800021D5: 8B D9              mov         ebx,ecx
  00000001800021D7: 75 67              jne         0000000180002240
  00000001800021D9: 83 F9 01           cmp         ecx,1
  00000001800021DC: 77 6A              ja          0000000180002248
  00000001800021DE: E8 D5 04 00 00     call        __scrt_is_ucrt_dll_in_use
  00000001800021E3: 85 C0              test        eax,eax
  00000001800021E5: 74 28              je          000000018000220F
  00000001800021E7: 85 DB              test        ebx,ebx
  00000001800021E9: 75 24              jne         000000018000220F
  00000001800021EB: 48 8D 0D 06 24 00  lea         rcx,[1800045F8h]
                    00
  00000001800021F2: E8 09 05 00 00     call        _initialize_onexit_table
  00000001800021F7: 85 C0              test        eax,eax
  00000001800021F9: 75 10              jne         000000018000220B
  00000001800021FB: 48 8D 0D 0E 24 00  lea         rcx,[180004610h]
                    00
  0000000180002202: E8 F9 04 00 00     call        _initialize_onexit_table
  0000000180002207: 85 C0              test        eax,eax
  0000000180002209: 74 2E              je          0000000180002239
  000000018000220B: 32 C0              xor         al,al
  000000018000220D: EB 33              jmp         0000000180002242
  000000018000220F: 66 0F 6F 05 C9 0F  movdqa      xmm0,xmmword ptr [__xmm@ffffffffffffffffffffffffffffffff]
                    00 00
  0000000180002217: 48 83 C8 FF        or          rax,0FFFFFFFFFFFFFFFFh
  000000018000221B: F3 0F 7F 05 D5 23  movdqu      xmmword ptr [1800045F8h],xmm0
                    00 00
  0000000180002223: 48 89 05 DE 23 00  mov         qword ptr [180004608h],rax
                    00
  000000018000222A: F3 0F 7F 05 DE 23  movdqu      xmmword ptr [180004610h],xmm0
                    00 00
  0000000180002232: 48 89 05 E7 23 00  mov         qword ptr [180004620h],rax
                    00
  0000000180002239: C6 05 B1 23 00 00  mov         byte ptr [1800045F1h],1
                    01
  0000000180002240: B0 01              mov         al,1
  0000000180002242: 48 83 C4 20        add         rsp,20h
  0000000180002246: 5B                 pop         rbx
  0000000180002247: C3                 ret
  0000000180002248: B9 05 00 00 00     mov         ecx,5
  000000018000224D: E8 FA 00 00 00     call        __scrt_fastfail
  0000000180002252: CC                 int         3
  0000000180002253: CC                                               I
__scrt_is_nonwritable_in_current_image:
  0000000180002254: 48 83 EC 18        sub         rsp,18h
  0000000180002258: 4C 8B C1           mov         r8,rcx
  000000018000225B: B8 4D 5A 00 00     mov         eax,5A4Dh
  0000000180002260: 66 39 05 99 DD FF  cmp         word ptr [180000000h],ax
                    FF
  0000000180002267: 75 78              jne         00000001800022E1
  0000000180002269: 48 63 0D CC DD FF  movsxd      rcx,dword ptr [18000003Ch]
                    FF
  0000000180002270: 48 8D 15 89 DD FF  lea         rdx,[180000000h]
                    FF
  0000000180002277: 48 03 CA           add         rcx,rdx
  000000018000227A: 81 39 50 45 00 00  cmp         dword ptr [rcx],4550h
  0000000180002280: 75 5F              jne         00000001800022E1
  0000000180002282: B8 0B 02 00 00     mov         eax,20Bh
  0000000180002287: 66 39 41 18        cmp         word ptr [rcx+18h],ax
  000000018000228B: 75 54              jne         00000001800022E1
  000000018000228D: 4C 2B C2           sub         r8,rdx
  0000000180002290: 0F B7 41 14        movzx       eax,word ptr [rcx+14h]
  0000000180002294: 48 8D 51 18        lea         rdx,[rcx+18h]
  0000000180002298: 48 03 D0           add         rdx,rax
  000000018000229B: 0F B7 41 06        movzx       eax,word ptr [rcx+6]
  000000018000229F: 48 8D 0C 80        lea         rcx,[rax+rax*4]
  00000001800022A3: 4C 8D 0C CA        lea         r9,[rdx+rcx*8]
  00000001800022A7: 48 89 14 24        mov         qword ptr [rsp],rdx
  00000001800022AB: 49 3B D1           cmp         rdx,r9
  00000001800022AE: 74 18              je          00000001800022C8
  00000001800022B0: 8B 4A 0C           mov         ecx,dword ptr [rdx+0Ch]
  00000001800022B3: 4C 3B C1           cmp         r8,rcx
  00000001800022B6: 72 0A              jb          00000001800022C2
  00000001800022B8: 8B 42 08           mov         eax,dword ptr [rdx+8]
  00000001800022BB: 03 C1              add         eax,ecx
  00000001800022BD: 4C 3B C0           cmp         r8,rax
  00000001800022C0: 72 08              jb          00000001800022CA
  00000001800022C2: 48 83 C2 28        add         rdx,28h
  00000001800022C6: EB DF              jmp         00000001800022A7
  00000001800022C8: 33 D2              xor         edx,edx
  00000001800022CA: 48 85 D2           test        rdx,rdx
  00000001800022CD: 75 04              jne         00000001800022D3
  00000001800022CF: 32 C0              xor         al,al
  00000001800022D1: EB 14              jmp         00000001800022E7
  00000001800022D3: 83 7A 24 00        cmp         dword ptr [rdx+24h],0
  00000001800022D7: 7D 04              jge         00000001800022DD
  00000001800022D9: 32 C0              xor         al,al
  00000001800022DB: EB 0A              jmp         00000001800022E7
  00000001800022DD: B0 01              mov         al,1
  00000001800022DF: EB 06              jmp         00000001800022E7
  00000001800022E1: 32 C0              xor         al,al
  00000001800022E3: EB 02              jmp         00000001800022E7
  00000001800022E5: 32 C0              xor         al,al
  00000001800022E7: 48 83 C4 18        add         rsp,18h
  00000001800022EB: C3                 ret
__scrt_release_startup_lock:
  00000001800022EC: 40 53              push        rbx
  00000001800022EE: 48 83 EC 20        sub         rsp,20h
  00000001800022F2: 8A D9              mov         bl,cl
  00000001800022F4: E8 BF 03 00 00     call        __scrt_is_ucrt_dll_in_use
  00000001800022F9: 33 D2              xor         edx,edx
  00000001800022FB: 85 C0              test        eax,eax
  00000001800022FD: 74 0B              je          000000018000230A
  00000001800022FF: 84 DB              test        bl,bl
  0000000180002301: 75 07              jne         000000018000230A
  0000000180002303: 48 87 15 DE 22 00  xchg        rdx,qword ptr [__scrt_native_startup_lock]
                    00
  000000018000230A: 48 83 C4 20        add         rsp,20h
  000000018000230E: 5B                 pop         rbx
  000000018000230F: C3                 ret
__scrt_uninitialize_crt:
  0000000180002310: 40 53              push        rbx
  0000000180002312: 48 83 EC 20        sub         rsp,20h
  0000000180002316: 80 3D D3 22 00 00  cmp         byte ptr [1800045F0h],0
                    00
  000000018000231D: 8A D9              mov         bl,cl
  000000018000231F: 74 04              je          0000000180002325
  0000000180002321: 84 D2              test        dl,dl
  0000000180002323: 75 0C              jne         0000000180002331
  0000000180002325: E8 EA 03 00 00     call        __acrt_initialize
  000000018000232A: 8A CB              mov         cl,bl
  000000018000232C: E8 E3 03 00 00     call        __acrt_initialize
  0000000180002331: B0 01              mov         al,1
  0000000180002333: 48 83 C4 20        add         rsp,20h
  0000000180002337: 5B                 pop         rbx
  0000000180002338: C3                 ret
  0000000180002339: CC CC CC                                         III
__scrt_get_dyn_tls_init_callback:
  000000018000233C: 48 8D 05 FD 22 00  lea         rax,[__dyn_tls_init_callback]
                    00
  0000000180002343: C3                 ret
__crt_debugger_hook:
  0000000180002344: 83 25 DD 22 00 00  and         dword ptr [__scrt_debugger_hook_flag],0
                    00
  000000018000234B: C3                 ret
__scrt_fastfail:
  000000018000234C: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  0000000180002351: 55                 push        rbp
  0000000180002352: 48 8D AC 24 40 FB  lea         rbp,[rsp-4C0h]
                    FF FF
  000000018000235A: 48 81 EC C0 05 00  sub         rsp,5C0h
                    00
  0000000180002361: 8B D9              mov         ebx,ecx
  0000000180002363: B9 17 00 00 00     mov         ecx,17h
  0000000180002368: FF 15 12 0D 00 00  call        qword ptr [__imp_IsProcessorFeaturePresent]
  000000018000236E: 85 C0              test        eax,eax
  0000000180002370: 74 04              je          0000000180002376
  0000000180002372: 8B CB              mov         ecx,ebx
  0000000180002374: CD 29              int         29h
  0000000180002376: B9 03 00 00 00     mov         ecx,3
  000000018000237B: E8 C4 FF FF FF     call        __crt_debugger_hook
  0000000180002380: 33 D2              xor         edx,edx
  0000000180002382: 48 8D 4D F0        lea         rcx,[rbp-10h]
  0000000180002386: 41 B8 D0 04 00 00  mov         r8d,4D0h
  000000018000238C: E8 4B 03 00 00     call        memset
  0000000180002391: 48 8D 4D F0        lea         rcx,[rbp-10h]
  0000000180002395: FF 15 ED 0C 00 00  call        qword ptr [__imp_RtlCaptureContext]
  000000018000239B: 48 8B 9D E8 00 00  mov         rbx,qword ptr [rbp+0E8h]
                    00
  00000001800023A2: 48 8D 95 D8 04 00  lea         rdx,[rbp+4D8h]
                    00
  00000001800023A9: 48 8B CB           mov         rcx,rbx
  00000001800023AC: 45 33 C0           xor         r8d,r8d
  00000001800023AF: FF 15 A3 0C 00 00  call        qword ptr [__imp_RtlLookupFunctionEntry]
  00000001800023B5: 48 85 C0           test        rax,rax
  00000001800023B8: 74 3C              je          00000001800023F6
  00000001800023BA: 48 83 64 24 38 00  and         qword ptr [rsp+38h],0
  00000001800023C0: 48 8D 8D E0 04 00  lea         rcx,[rbp+4E0h]
                    00
  00000001800023C7: 48 8B 95 D8 04 00  mov         rdx,qword ptr [rbp+4D8h]
                    00
  00000001800023CE: 4C 8B C8           mov         r9,rax
  00000001800023D1: 48 89 4C 24 30     mov         qword ptr [rsp+30h],rcx
  00000001800023D6: 4C 8B C3           mov         r8,rbx
  00000001800023D9: 48 8D 8D E8 04 00  lea         rcx,[rbp+4E8h]
                    00
  00000001800023E0: 48 89 4C 24 28     mov         qword ptr [rsp+28h],rcx
  00000001800023E5: 48 8D 4D F0        lea         rcx,[rbp-10h]
  00000001800023E9: 48 89 4C 24 20     mov         qword ptr [rsp+20h],rcx
  00000001800023EE: 33 C9              xor         ecx,ecx
  00000001800023F0: FF 15 6A 0C 00 00  call        qword ptr [__imp_RtlVirtualUnwind]
  00000001800023F6: 48 8B 85 C8 04 00  mov         rax,qword ptr [rbp+4C8h]
                    00
  00000001800023FD: 48 8D 4C 24 50     lea         rcx,[rsp+50h]
  0000000180002402: 48 89 85 E8 00 00  mov         qword ptr [rbp+0E8h],rax
                    00
  0000000180002409: 33 D2              xor         edx,edx
  000000018000240B: 48 8D 85 C8 04 00  lea         rax,[rbp+4C8h]
                    00
  0000000180002412: 41 B8 98 00 00 00  mov         r8d,98h
  0000000180002418: 48 83 C0 08        add         rax,8
  000000018000241C: 48 89 85 88 00 00  mov         qword ptr [rbp+88h],rax
                    00
  0000000180002423: E8 B4 02 00 00     call        memset
  0000000180002428: 48 8B 85 C8 04 00  mov         rax,qword ptr [rbp+4C8h]
                    00
  000000018000242F: 48 89 44 24 60     mov         qword ptr [rsp+60h],rax
  0000000180002434: C7 44 24 50 15 00  mov         dword ptr [rsp+50h],40000015h
                    00 40
  000000018000243C: C7 44 24 54 01 00  mov         dword ptr [rsp+54h],1
                    00 00
  0000000180002444: FF 15 46 0C 00 00  call        qword ptr [__imp_IsDebuggerPresent]
  000000018000244A: 83 F8 01           cmp         eax,1
  000000018000244D: 48 8D 44 24 50     lea         rax,[rsp+50h]
  0000000180002452: 48 89 44 24 40     mov         qword ptr [rsp+40h],rax
  0000000180002457: 48 8D 45 F0        lea         rax,[rbp-10h]
  000000018000245B: 0F 94 C3           sete        bl
  000000018000245E: 48 89 44 24 48     mov         qword ptr [rsp+48h],rax
  0000000180002463: 33 C9              xor         ecx,ecx
  0000000180002465: FF 15 05 0C 00 00  call        qword ptr [__imp_SetUnhandledExceptionFilter]
  000000018000246B: 48 8D 4C 24 40     lea         rcx,[rsp+40h]
  0000000180002470: FF 15 F2 0B 00 00  call        qword ptr [__imp_UnhandledExceptionFilter]
  0000000180002476: 85 C0              test        eax,eax
  0000000180002478: 75 0C              jne         0000000180002486
  000000018000247A: 84 DB              test        bl,bl
  000000018000247C: 75 08              jne         0000000180002486
  000000018000247E: 8D 48 03           lea         ecx,[rax+3]
  0000000180002481: E8 BE FE FF FF     call        __crt_debugger_hook
  0000000180002486: 48 8B 9C 24 D0 05  mov         rbx,qword ptr [rsp+5D0h]
                    00 00
  000000018000248E: 48 81 C4 C0 05 00  add         rsp,5C0h
                    00
  0000000180002495: 5D                 pop         rbp
  0000000180002496: C3                 ret
  0000000180002497: CC                                               I
_RTC_Initialize:
  0000000180002498: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  000000018000249D: 57                 push        rdi
  000000018000249E: 48 83 EC 20        sub         rsp,20h
  00000001800024A2: 48 8D 1D 47 12 00  lea         rbx,[__rtc_izz]
                    00
  00000001800024A9: 48 8D 3D 40 12 00  lea         rdi,[__rtc_izz]
                    00
  00000001800024B0: EB 12              jmp         00000001800024C4
  00000001800024B2: 48 8B 03           mov         rax,qword ptr [rbx]
  00000001800024B5: 48 85 C0           test        rax,rax
  00000001800024B8: 74 06              je          00000001800024C0
  00000001800024BA: FF 15 A0 0C 00 00  call        qword ptr [__guard_dispatch_icall_fptr]
  00000001800024C0: 48 83 C3 08        add         rbx,8
  00000001800024C4: 48 3B DF           cmp         rbx,rdi
  00000001800024C7: 72 E9              jb          00000001800024B2
  00000001800024C9: 48 8B 5C 24 30     mov         rbx,qword ptr [rsp+30h]
  00000001800024CE: 48 83 C4 20        add         rsp,20h
  00000001800024D2: 5F                 pop         rdi
  00000001800024D3: C3                 ret
_RTC_Terminate:
  00000001800024D4: 48 89 5C 24 08     mov         qword ptr [rsp+8],rbx
  00000001800024D9: 57                 push        rdi
  00000001800024DA: 48 83 EC 20        sub         rsp,20h
  00000001800024DE: 48 8D 1D 1B 12 00  lea         rbx,[__rtc_tzz]
                    00
  00000001800024E5: 48 8D 3D 14 12 00  lea         rdi,[__rtc_tzz]
                    00
  00000001800024EC: EB 12              jmp         0000000180002500
  00000001800024EE: 48 8B 03           mov         rax,qword ptr [rbx]
  00000001800024F1: 48 85 C0           test        rax,rax
  00000001800024F4: 74 06              je          00000001800024FC
  00000001800024F6: FF 15 64 0C 00 00  call        qword ptr [__guard_dispatch_icall_fptr]
  00000001800024FC: 48 83 C3 08        add         rbx,8
  0000000180002500: 48 3B DF           cmp         rbx,rdi
  0000000180002503: 72 E9              jb          00000001800024EE
  0000000180002505: 48 8B 5C 24 30     mov         rbx,qword ptr [rsp+30h]
  000000018000250A: 48 83 C4 20        add         rsp,20h
  000000018000250E: 5F                 pop         rdi
  000000018000250F: C3                 ret
_guard_check_icall_nop:
  0000000180002510: C2 00 00           ret         0
  0000000180002513: CC                                               I
__isa_available_init:
  0000000180002514: 48 89 5C 24 10     mov         qword ptr [rsp+10h],rbx
  0000000180002519: 48 89 74 24 18     mov         qword ptr [rsp+18h],rsi
  000000018000251E: 57                 push        rdi
  000000018000251F: 48 83 EC 10        sub         rsp,10h
  0000000180002523: 33 C0              xor         eax,eax
  0000000180002525: 33 C9              xor         ecx,ecx
  0000000180002527: 0F A2              cpuid
  0000000180002529: 44 8B C1           mov         r8d,ecx
  000000018000252C: 45 33 DB           xor         r11d,r11d
  000000018000252F: 44 8B CB           mov         r9d,ebx
  0000000180002532: 41 81 F0 6E 74 65  xor         r8d,6C65746Eh
                    6C
  0000000180002539: 41 81 F1 47 65 6E  xor         r9d,756E6547h
                    75
  0000000180002540: 44 8B D2           mov         r10d,edx
  0000000180002543: 8B F0              mov         esi,eax
  0000000180002545: 33 C9              xor         ecx,ecx
  0000000180002547: 41 8D 43 01        lea         eax,[r11+1]
  000000018000254B: 45 0B C8           or          r9d,r8d
  000000018000254E: 0F A2              cpuid
  0000000180002550: 41 81 F2 69 6E 65  xor         r10d,49656E69h
                    49
  0000000180002557: 89 04 24           mov         dword ptr [rsp],eax
  000000018000255A: 45 0B CA           or          r9d,r10d
  000000018000255D: 89 5C 24 04        mov         dword ptr [rsp+4],ebx
  0000000180002561: 8B F9              mov         edi,ecx
  0000000180002563: 89 4C 24 08        mov         dword ptr [rsp+8],ecx
  0000000180002567: 89 54 24 0C        mov         dword ptr [rsp+0Ch],edx
  000000018000256B: 75 50              jne         00000001800025BD
  000000018000256D: 48 83 0D AB 1A 00  or          qword ptr [__memcpy_nt_iters],0FFFFFFFFFFFFFFFFh
                    00 FF
  0000000180002575: 25 F0 3F FF 0F     and         eax,0FFF3FF0h
  000000018000257A: 3D C0 06 01 00     cmp         eax,106C0h
  000000018000257F: 74 28              je          00000001800025A9
  0000000180002581: 3D 60 06 02 00     cmp         eax,20660h
  0000000180002586: 74 21              je          00000001800025A9
  0000000180002588: 3D 70 06 02 00     cmp         eax,20670h
  000000018000258D: 74 1A              je          00000001800025A9
  000000018000258F: 05 B0 F9 FC FF     add         eax,0FFFCF9B0h
  0000000180002594: 83 F8 20           cmp         eax,20h
  0000000180002597: 77 24              ja          00000001800025BD
  0000000180002599: 48 B9 01 00 01 00  mov         rcx,100010001h
                    01 00 00 00
  00000001800025A3: 48 0F A3 C1        bt          rcx,rax
  00000001800025A7: 73 14              jae         00000001800025BD
  00000001800025A9: 44 8B 05 88 20 00  mov         r8d,dword ptr [__favor]
                    00
  00000001800025B0: 41 83 C8 01        or          r8d,1
  00000001800025B4: 44 89 05 7D 20 00  mov         dword ptr [__favor],r8d
                    00
  00000001800025BB: EB 07              jmp         00000001800025C4
  00000001800025BD: 44 8B 05 74 20 00  mov         r8d,dword ptr [__favor]
                    00
  00000001800025C4: B8 07 00 00 00     mov         eax,7
  00000001800025C9: 44 8D 48 FB        lea         r9d,[rax-5]
  00000001800025CD: 3B F0              cmp         esi,eax
  00000001800025CF: 7C 26              jl          00000001800025F7
  00000001800025D1: 33 C9              xor         ecx,ecx
  00000001800025D3: 0F A2              cpuid
  00000001800025D5: 89 04 24           mov         dword ptr [rsp],eax
  00000001800025D8: 44 8B DB           mov         r11d,ebx
  00000001800025DB: 89 5C 24 04        mov         dword ptr [rsp+4],ebx
  00000001800025DF: 89 4C 24 08        mov         dword ptr [rsp+8],ecx
  00000001800025E3: 89 54 24 0C        mov         dword ptr [rsp+0Ch],edx
  00000001800025E7: 0F BA E3 09        bt          ebx,9
  00000001800025EB: 73 0A              jae         00000001800025F7
  00000001800025ED: 45 0B C1           or          r8d,r9d
  00000001800025F0: 44 89 05 41 20 00  mov         dword ptr [__favor],r8d
                    00
  00000001800025F7: C7 05 17 1A 00 00  mov         dword ptr [__isa_available],1
                    01 00 00 00
  0000000180002601: 44 89 0D 14 1A 00  mov         dword ptr [__isa_enabled],r9d
                    00
  0000000180002608: 0F BA E7 14        bt          edi,14h
  000000018000260C: 0F 83 91 00 00 00  jae         00000001800026A3
  0000000180002612: 44 89 0D FF 19 00  mov         dword ptr [__isa_available],r9d
                    00
  0000000180002619: BB 06 00 00 00     mov         ebx,6
  000000018000261E: 89 1D F8 19 00 00  mov         dword ptr [__isa_enabled],ebx
  0000000180002624: 0F BA E7 1B        bt          edi,1Bh
  0000000180002628: 73 79              jae         00000001800026A3
  000000018000262A: 0F BA E7 1C        bt          edi,1Ch
  000000018000262E: 73 73              jae         00000001800026A3
  0000000180002630: 33 C9              xor         ecx,ecx
  0000000180002632: 0F 01 D0           xgetbv
  0000000180002635: 48 C1 E2 20        shl         rdx,20h
  0000000180002639: 48 0B D0           or          rdx,rax
  000000018000263C: 48 89 54 24 20     mov         qword ptr [rsp+20h],rdx
  0000000180002641: 48 8B 44 24 20     mov         rax,qword ptr [rsp+20h]
  0000000180002646: 22 C3              and         al,bl
  0000000180002648: 3A C3              cmp         al,bl
  000000018000264A: 75 57              jne         00000001800026A3
  000000018000264C: 8B 05 CA 19 00 00  mov         eax,dword ptr [__isa_enabled]
  0000000180002652: 83 C8 08           or          eax,8
  0000000180002655: C7 05 B9 19 00 00  mov         dword ptr [__isa_available],3
                    03 00 00 00
  000000018000265F: 89 05 B7 19 00 00  mov         dword ptr [__isa_enabled],eax
  0000000180002665: 41 F6 C3 20        test        r11b,20h
  0000000180002669: 74 38              je          00000001800026A3
  000000018000266B: 83 C8 20           or          eax,20h
  000000018000266E: C7 05 A0 19 00 00  mov         dword ptr [__isa_available],5
                    05 00 00 00
  0000000180002678: 89 05 9E 19 00 00  mov         dword ptr [__isa_enabled],eax
  000000018000267E: B8 00 00 03 D0     mov         eax,0D0030000h
  0000000180002683: 44 23 D8           and         r11d,eax
  0000000180002686: 44 3B D8           cmp         r11d,eax
  0000000180002689: 75 18              jne         00000001800026A3
  000000018000268B: 48 8B 44 24 20     mov         rax,qword ptr [rsp+20h]
  0000000180002690: 24 E0              and         al,0E0h
  0000000180002692: 3C E0              cmp         al,0E0h
  0000000180002694: 75 0D              jne         00000001800026A3
  0000000180002696: 83 0D 7F 19 00 00  or          dword ptr [__isa_enabled],40h
                    40
  000000018000269D: 89 1D 75 19 00 00  mov         dword ptr [__isa_available],ebx
  00000001800026A3: 48 8B 5C 24 28     mov         rbx,qword ptr [rsp+28h]
  00000001800026A8: 33 C0              xor         eax,eax
  00000001800026AA: 48 8B 74 24 30     mov         rsi,qword ptr [rsp+30h]
  00000001800026AF: 48 83 C4 10        add         rsp,10h
  00000001800026B3: 5F                 pop         rdi
  00000001800026B4: C3                 ret
  00000001800026B5: CC CC CC                                         III
__scrt_is_ucrt_dll_in_use:
  00000001800026B8: 33 C0              xor         eax,eax
  00000001800026BA: 39 05 70 19 00 00  cmp         dword ptr [__scrt_ucrt_dll_is_in_use],eax
  00000001800026C0: 0F 95 C0           setne       al
  00000001800026C3: C3                 ret
  00000001800026C4: CC CC CC CC CC CC CC CC CC CC CC CC              IIIIIIIIIIII
__C_specific_handler:
  00000001800026D0: FF 25 FA 09 00 00  jmp         qword ptr [__imp___C_specific_handler]
__std_type_info_destroy_list:
  00000001800026D6: FF 25 EC 09 00 00  jmp         qword ptr [__imp___std_type_info_destroy_list]
memset:
  00000001800026DC: FF 25 FE 09 00 00  jmp         qword ptr [__imp_memset]
_initterm:
  00000001800026E2: FF 25 48 0A 00 00  jmp         qword ptr [__imp__initterm]
_initterm_e:
  00000001800026E8: FF 25 3A 0A 00 00  jmp         qword ptr [__imp__initterm_e]
_seh_filter_dll:
  00000001800026EE: FF 25 2C 0A 00 00  jmp         qword ptr [__imp__seh_filter_dll]
_configure_narrow_argv:
  00000001800026F4: FF 25 1E 0A 00 00  jmp         qword ptr [__imp__configure_narrow_argv]
_initialize_narrow_environment:
  00000001800026FA: FF 25 F8 09 00 00  jmp         qword ptr [__imp__initialize_narrow_environment]
_initialize_onexit_table:
  0000000180002700: FF 25 0A 0A 00 00  jmp         qword ptr [__imp__initialize_onexit_table]
_execute_onexit_table:
  0000000180002706: FF 25 FC 09 00 00  jmp         qword ptr [__imp__execute_onexit_table]
_cexit:
  000000018000270C: FF 25 EE 09 00 00  jmp         qword ptr [__imp__cexit]
  0000000180002712: CC CC                                            II
__acrt_initialize:
  0000000180002714: B0 01              mov         al,1
  0000000180002716: C3                 ret
  0000000180002717: CC                                               I
__scrt_stub_for_is_c_termination_complete:
  0000000180002718: 33 C0              xor         eax,eax
  000000018000271A: C3                 ret
  000000018000271B: CC                                               I
__GSHandlerCheck:
  000000018000271C: 48 83 EC 28        sub         rsp,28h
  0000000180002720: 4D 8B 41 38        mov         r8,qword ptr [r9+38h]
  0000000180002724: 48 8B CA           mov         rcx,rdx
  0000000180002727: 49 8B D1           mov         rdx,r9
  000000018000272A: E8 0D 00 00 00     call        __GSHandlerCheckCommon
  000000018000272F: B8 01 00 00 00     mov         eax,1
  0000000180002734: 48 83 C4 28        add         rsp,28h
  0000000180002738: C3                 ret
  0000000180002739: CC CC CC                                         III
__GSHandlerCheckCommon:
  000000018000273C: 40 53              push        rbx
  000000018000273E: 45 8B 18           mov         r11d,dword ptr [r8]
  0000000180002741: 48 8B DA           mov         rbx,rdx
  0000000180002744: 41 83 E3 F8        and         r11d,0FFFFFFF8h
  0000000180002748: 4C 8B C9           mov         r9,rcx
  000000018000274B: 41 F6 00 04        test        byte ptr [r8],4
  000000018000274F: 4C 8B D1           mov         r10,rcx
  0000000180002752: 74 13              je          0000000180002767
  0000000180002754: 41 8B 40 08        mov         eax,dword ptr [r8+8]
  0000000180002758: 4D 63 50 04        movsxd      r10,dword ptr [r8+4]
  000000018000275C: F7 D8              neg         eax
  000000018000275E: 4C 03 D1           add         r10,rcx
  0000000180002761: 48 63 C8           movsxd      rcx,eax
  0000000180002764: 4C 23 D1           and         r10,rcx
  0000000180002767: 49 63 C3           movsxd      rax,r11d
  000000018000276A: 4A 8B 14 10        mov         rdx,qword ptr [rax+r10]
  000000018000276E: 48 8B 43 10        mov         rax,qword ptr [rbx+10h]
  0000000180002772: 8B 48 08           mov         ecx,dword ptr [rax+8]
  0000000180002775: 48 8B 43 08        mov         rax,qword ptr [rbx+8]
  0000000180002779: F6 44 01 03 0F     test        byte ptr [rcx+rax+3],0Fh
  000000018000277E: 74 0B              je          000000018000278B
  0000000180002780: 0F B6 44 01 03     movzx       eax,byte ptr [rcx+rax+3]
  0000000180002785: 83 E0 F0           and         eax,0FFFFFFF0h
  0000000180002788: 4C 03 C8           add         r9,rax
  000000018000278B: 4C 33 CA           xor         r9,rdx
  000000018000278E: 49 8B C9           mov         rcx,r9
  0000000180002791: 5B                 pop         rbx
  0000000180002792: E9 89 F2 FF FF     jmp         __security_check_cookie
  0000000180002797: CC CC CC CC CC CC CC CC CC                       IIIIIIIII
  00000001800027A0: CC                 int         3
  00000001800027A1: CC                 int         3
  00000001800027A2: CC                 int         3
  00000001800027A3: CC                 int         3
  00000001800027A4: CC                 int         3
  00000001800027A5: CC                 int         3
  00000001800027A6: 66 66 0F 1F 84 00  nop         word ptr [rax+rax]
                    00 00 00 00
__chkstk:
  00000001800027B0: 48 83 EC 10        sub         rsp,10h
  00000001800027B4: 4C 89 14 24        mov         qword ptr [rsp],r10
  00000001800027B8: 4C 89 5C 24 08     mov         qword ptr [rsp+8],r11
  00000001800027BD: 4D 33 DB           xor         r11,r11
  00000001800027C0: 4C 8D 54 24 18     lea         r10,[rsp+18h]
  00000001800027C5: 4C 2B D0           sub         r10,rax
  00000001800027C8: 4D 0F 42 D3        cmovb       r10,r11
  00000001800027CC: 65 4C 8B 1C 25 10  mov         r11,qword ptr gs:[10h]
                    00 00 00
  00000001800027D5: 4D 3B D3           cmp         r10,r11
  00000001800027D8: 73 16              jae         00000001800027F0
  00000001800027DA: 66 41 81 E2 00 F0  and         r10w,0F000h
  00000001800027E0: 4D 8D 9B 00 F0 FF  lea         r11,[r11-1000h]
                    FF
  00000001800027E7: 41 C6 03 00        mov         byte ptr [r11],0
  00000001800027EB: 4D 3B D3           cmp         r10,r11
  00000001800027EE: 75 F0              jne         00000001800027E0
  00000001800027F0: 4C 8B 14 24        mov         r10,qword ptr [rsp]
  00000001800027F4: 4C 8B 5C 24 08     mov         r11,qword ptr [rsp+8]
  00000001800027F9: 48 83 C4 10        add         rsp,10h
  00000001800027FD: C3                 ret
memcpy:
  00000001800027FE: FF 25 E4 08 00 00  jmp         qword ptr [__imp_memcpy]
  0000000180002804: CC CC CC CC CC CC CC CC CC CC CC CC              IIIIIIIIIIII
  0000000180002810: CC                 int         3
  0000000180002811: CC                 int         3
  0000000180002812: CC                 int         3
  0000000180002813: CC                 int         3
  0000000180002814: CC                 int         3
  0000000180002815: CC                 int         3
  0000000180002816: 66 66 0F 1F 84 00  nop         word ptr [rax+rax]
                    00 00 00 00
_guard_dispatch_icall_nop:
  0000000180002820: FF E0              jmp         rax
  0000000180002822: CC CC CC CC CC CC CC CC CC CC CC CC CC CC        IIIIIIIIIIIIII
  0000000180002830: CC                 int         3
  0000000180002831: CC                 int         3
  0000000180002832: CC                 int         3
  0000000180002833: CC                 int         3
  0000000180002834: CC                 int         3
  0000000180002835: CC                 int         3
  0000000180002836: 66 66 0F 1F 84 00  nop         word ptr [rax+rax]
                    00 00 00 00
_guard_xfg_dispatch_icall_nop:
  0000000180002840: FF 25 1A 09 00 00  jmp         qword ptr [__guard_dispatch_icall_fptr]
`dllmain_crt_process_attach'::`1'::fin$0:
  0000000180002846: 40 55              push        rbp
  0000000180002848: 48 83 EC 20        sub         rsp,20h
  000000018000284C: 48 8B EA           mov         rbp,rdx
  000000018000284F: 8A 4D 40           mov         cl,byte ptr [rbp+40h]
  0000000180002852: 48 83 C4 20        add         rsp,20h
  0000000180002856: 5D                 pop         rbp
  0000000180002857: E9 90 FA FF FF     jmp         __scrt_release_startup_lock
  000000018000285C: CC                 int         3
`dllmain_crt_process_detach'::`1'::fin$0:
  000000018000285D: 40 55              push        rbp
  000000018000285F: 48 83 EC 20        sub         rsp,20h
  0000000180002863: 48 8B EA           mov         rbp,rdx
  0000000180002866: 8A 4D 20           mov         cl,byte ptr [rbp+20h]
  0000000180002869: E8 7E FA FF FF     call        __scrt_release_startup_lock
  000000018000286E: 90                 nop
  000000018000286F: 48 83 C4 20        add         rsp,20h
  0000000180002873: 5D                 pop         rbp
  0000000180002874: C3                 ret
  0000000180002875: CC                 int         3
`dllmain_crt_process_detach'::`1'::fin$1:
  0000000180002876: 40 55              push        rbp
  0000000180002878: 48 83 EC 20        sub         rsp,20h
  000000018000287C: 48 8B EA           mov         rbp,rdx
  000000018000287F: 48 83 C4 20        add         rsp,20h
  0000000180002883: 5D                 pop         rbp
  0000000180002884: E9 DF F8 FF FF     jmp         __scrt_dllmain_uninitialize_critical
  0000000180002889: CC                 int         3
`dllmain_dispatch'::`1'::filt$0:
  000000018000288A: 40 55              push        rbp
  000000018000288C: 48 83 EC 30        sub         rsp,30h
  0000000180002890: 48 8B EA           mov         rbp,rdx
  0000000180002893: 48 8B 01           mov         rax,qword ptr [rcx]
  0000000180002896: 8B 10              mov         edx,dword ptr [rax]
  0000000180002898: 48 89 4C 24 28     mov         qword ptr [rsp+28h],rcx
  000000018000289D: 89 54 24 20        mov         dword ptr [rsp+20h],edx
  00000001800028A1: 4C 8D 0D 98 F1 FF  lea         r9,[180001A40h]
                    FF
  00000001800028A8: 4C 8B 45 70        mov         r8,qword ptr [rbp+70h]
  00000001800028AC: 8B 55 68           mov         edx,dword ptr [rbp+68h]
  00000001800028AF: 48 8B 4D 60        mov         rcx,qword ptr [rbp+60h]
  00000001800028B3: E8 20 F8 FF FF     call        __scrt_dllmain_exception_filter
  00000001800028B8: 90                 nop
  00000001800028B9: 48 83 C4 30        add         rsp,30h
  00000001800028BD: 5D                 pop         rbp
  00000001800028BE: C3                 ret
  00000001800028BF: CC                 int         3
__scrt_is_nonwritable_in_current_image$filt$0:
  00000001800028C0: 40 55              push        rbp
  00000001800028C2: 48 8B EA           mov         rbp,rdx
  00000001800028C5: 48 8B 01           mov         rax,qword ptr [rcx]
  00000001800028C8: 33 C9              xor         ecx,ecx
  00000001800028CA: 81 38 05 00 00 C0  cmp         dword ptr [rax],0C0000005h
  00000001800028D0: 0F 94 C1           sete        cl
  00000001800028D3: 8B C1              mov         eax,ecx
  00000001800028D5: 5D                 pop         rbp
  00000001800028D6: C3                 ret
  00000001800028D7: CC                 int         3

  Summary

        1000 .data
        1000 .pdata
        1000 .rdata
        1000 .reloc
        1000 .rsrc
        2000 .text
