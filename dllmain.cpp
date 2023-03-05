// dllmain.cpp : DLL アプリケーションのエントリ ポイントを定義します。
#include "pch.h"
#include "windows.h"
#include "stdlib.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
#ifdef __cplusplus
extern "C" {
#endif

    __declspec(dllexport) void* ULLoadLibraryA(char* prm_0) {
        char buff0[4096];
        char* buff4pe;
        char* buff4pecl;
        char* dll4prevdll = (char*)"::/\\";
        HANDLE fh;
        UINT64 baseaddr = 0;
        UINT64 cnt = 0;
        UINT64 reloc = 0;
        UINT64 relocsize = 0;
        UINT64 textaddr = 0;
        UINT64 textaddrsize = 0;
        DWORD tmp;
        if (fh = CreateFileA(prm_0, GENERIC_READ, 3, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) {
            ReadFile(fh, buff0, 512, 0, 0);
            SetFilePointer(fh, (*(UINT32*)(&buff0[0x3c])), 0, 0);
            ReadFile(fh, buff0, 4096, 0, 0);
            SetFilePointer(fh, 0, 0, 0);
            buff4pe = (char*)malloc((*(UINT32*)(&buff0[0x1c])) + (*(UINT32*)(&buff0[0x20])) + (*(UINT32*)(&buff0[0x24])));
            memcpy(buff4pe, buff0, 4096);
            if ((*(UINT16*)(&buff0[0x18])) == 0x10b) {
                //32bit
                baseaddr = (*(UINT32*)(&buff0[0x34]));
                cnt = 0;
                while ((*(UINT64*)(&buff0[0xf8 + (0x28 * cnt)])) != 0) {
                    SetFilePointer(fh, (*(UINT32*)(&buff0[0xf8 + (0x28 * cnt) + 0x14])), 0, 0);
                    ReadFile(fh, (void*)((UINT64)(&buff4pe) + (*(UINT32*)(&buff0[0xf8 + (0x28 * cnt) + 0xc]))), (*(UINT32*)(&buff0[0xf8 + (0x28 * cnt) + 0x10])), 0, 0);
                    if ((*(char*)(&buff0[0xf8 + (0x28 * cnt)])) == *".reloc")
                        reloc = (UINT64)(&buff4pe) + (*(UINT32*)(&buff0[0xf8 + (0x28 * cnt) + 0xc])); relocsize = (*(UINT32*)(&buff0[0xf8 + (0x28 * cnt) + 0x8]));
                    if ((*(char*)(&buff0[0xf8 + (0x28 * cnt)])) == *".text")
                        textaddr = (UINT64)(&buff4pe) + (*(UINT32*)(&buff0[0xf8 + (0x28 * cnt) + 0xc])); textaddrsize = (*(UINT32*)(&buff0[0xf8 + (0x28 * cnt) + 0x8]));
                    cnt++;
                }
            }
            else if ((*(UINT16*)(&buff0[0x18])) == 0x20b) {
                //64bit
                baseaddr = (*(UINT64*)(&buff0[0x30]));
                cnt = 0;
                while ((*(UINT64*)(&buff0[0x108 + (0x28 * cnt)])) != 0) {
                    SetFilePointer(fh, (*(UINT32*)(&buff0[0x108 + (0x28 * cnt) + 0x14])), 0, 0);
                    ReadFile(fh, (void*)((UINT64)(&buff4pe) + (*(UINT32*)(&buff0[0x108 + (0x28 * cnt) + 0xc]))), (*(UINT32*)(&buff0[0x108 + (0x28 * cnt) + 0x10])), 0, 0);
                    if ((*(char*)(&buff0[0x108 + (0x28 * cnt)])) == *".reloc")
                        reloc = (UINT64)(&buff4pe) + (*(UINT32*)(&buff0[0x108 + (0x28 * cnt) + 0xc])); relocsize = (*(UINT32*)(&buff0[0x108 + (0x28 * cnt) + 0x8]));
                    if ((*(char*)(&buff0[0x108 + (0x28 * cnt)])) == *".text")
                        textaddr = (UINT64)(&buff4pe) + (*(UINT32*)(&buff0[0x108 + (0x28 * cnt) + 0xc])); textaddrsize = (*(UINT32*)(&buff0[0x108 + (0x28 * cnt) + 0x8]));
                    cnt++;
                }
            }
            UINT64 delta = ((UINT64)(buff4pe - baseaddr));
            UINT64 tmp4relocptx = 8;
            UINT32 armhi = 0;
            UINT32 armlo = 0;
            UINT32 armhi_ = 0;
            UINT32 armlo_ = 0;
            UINT64 deltatmp;
            HMODULE HM = 0;
            if (reloc == 0) { CloseHandle(fh); free(buff4pe); return 0; }

loop4relocate:
            cnt = 0;
            while (cnt < (((*(UINT32*)(&reloc + (tmp4relocptx - 4))) - 8) / 2)) {
                switch (((*(UINT16*)(&reloc + (tmp4relocptx))) >> 12) & 0xF) {
                case 1:
                    (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))))) = (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))))) + ((delta >> 16) & 0xFFFF);
                    break;
                case 2:
                    (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))))) = (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))))) + ((delta >> 0) & 0xFFFF);
                    break;
                case 3:
                    (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))))) = (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))))) + delta;
                    break;
                case 7:
                    armlo = (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8))))));
                    armlo_ = ((armlo << 1) & 0x0800) + ((armlo << 12) & 0xf000) + ((armlo >> 20) & 0x0700) + ((armlo >> 16) & 0x00ff);
                    armhi = (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))) + 2));
                    armhi_ = ((armhi << 1) & 0x0800) + ((armhi << 12) & 0xf000) + ((armhi >> 20) & 0x0700) + ((armhi >> 16) & 0x00ff);
                    deltatmp = (((armlo_ & 0xFFFF) << 0) | ((armhi_ & 0xFFFF) << 16)) + delta;
                    armlo_ = (deltatmp >> 0) & 0xFFFF;
                    armhi_ = (deltatmp >> 16) & 0xFFFF;
                    armlo = (armlo & 0x8f00fbf0) + ((armlo_ >> 1) & 0x0400) + ((armlo_ >> 12) & 0x000f) + ((armlo_ << 20) & 0x70000000) + ((armlo_ << 16) & 0xff0000);
                    armhi = (armhi & 0x8f00fbf0) + ((armhi_ >> 1) & 0x0400) + ((armhi_ >> 12) & 0x000f) + ((armhi_ << 20) & 0x70000000) + ((armhi_ << 16) & 0xff0000);
                    (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))))) = armlo;
                    (*(UINT32*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))) + 2)) = armhi;
                    break;
                case 10:
                    (*(UINT64*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))) + 4)) = (*(UINT64*)(&buff4pe + (((*(UINT16*)(&reloc + (tmp4relocptx))) & 0xFFF) + (*(UINT32*)(&reloc + (tmp4relocptx - 8)))) + 4)) + delta;
                    break;
                }
                cnt++;
            }
            tmp4relocptx += (*(UINT32*)(&reloc + (tmp4relocptx - 4)));
            if ((*(UINT32*)(&reloc + (tmp4relocptx - 4))) != 0)
                goto loop4relocate;
            cnt = 0;
            while (true) {
                if ((*(UINT16*)(&buff0[0x18])) == 0x10b) {
                    //32bit
                    if ((*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x80])) + (cnt * 20))) == 0)
                        break;
                    if (dll4prevdll != ((char*)(*(UINT64*)(&buff4pe + (*(UINT32*)(&buff0[0x80])) + (cnt * 20) + 12))))
                        HM = LoadLibraryA(((char*)(*(UINT64*)(&buff4pe + (*(UINT32*)(&buff0[0x80])) + (cnt * 20) + 12))));
                    dll4prevdll = ((char*)(*(UINT64*)(&buff4pe + (*(UINT32*)(&buff0[0x80])) + (cnt * 20) + 12)));
                    if (HM != 0) {
                        // + ((*(UINT16*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x80])) + (cnt * 20) + 4)))) * 4)
                        (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x80])) + (cnt * 20) + 16)))) = (UINT32)GetProcAddress(HM, ((char*)(*(UINT32*)(&buff4pe + 2 + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x80])) + (cnt * 20) + 4))))));
                        (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 0)))) = (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 0)))) | 0x80000000;
                    }
                }
                else if ((*(UINT16*)(&buff0[0x18])) == 0x20b) {
                    //64bit
                    if ((*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20))) == 0)
                        break;
                    if (dll4prevdll != ((char*)(*(UINT64*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 12))))
                        HM = LoadLibraryA(((char*)(*(UINT64*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 12))));
                    dll4prevdll = ((char*)(*(UINT64*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 12)));
                    if (HM != 0) {
                        // + ((*(UINT16*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 4)))) * 8)
                        (*(UINT64*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 16)))) = (UINT64)GetProcAddress(HM, ((char*)(*(UINT64*)(&buff4pe + 2 + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 4))))));
                        (*(UINT64*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 0)))) = (*(UINT64*)(&buff4pe + (*(UINT32*)(&buff4pe + (*(UINT32*)(&buff0[0x90])) + (cnt * 20) + 0)))) | 0x8000000000000000;
                    }
                }
                cnt++;
            }
            if (textaddr != 0) {
                VirtualProtect((void*)(textaddr), textaddrsize, PAGE_EXECUTE_READWRITE, &tmp);
                FlushInstructionCache(GetCurrentProcess(), (void*)(textaddr), textaddrsize);
            }
            CloseHandle(fh);
            return buff4pe;
        }
        return 0;
    }
    typedef BOOL APIENTRY typeofDllMain(HMODULE hModule,
        DWORD  ul_reason_for_call,
        LPVOID lpReserved
    );
    __declspec(dllexport) BOOL ULExecDllMain(char* prm_0,UINT32 prm_1) {
        return ((typeofDllMain*)(prm_0 + (*(UINT32*)(prm_0 + 0x28))))((HMODULE)prm_0, prm_1, NULL);
    }
    __declspec(dllexport) void* ULGetProcAddress(char* prm_0, char* prm_1) {
        UINT64 cnt = 0;
        UINT64 AddrOfFunction = 0;
        void* AddrOfFunctionaly = 0;
        while (true) {
            if ((*(UINT16*)(&prm_0[0x18])) == 0x10b) {
                //32bit
                if ((*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x78])))) == 0)
                    break;
                AddrOfFunction = (UINT64)(&prm_0 + (*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x78])) + 28)));
                if ((char*)(&prm_0 + (*(UINT32*)(&prm_0 + (4 * cnt) + (*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x78])) + 32))))) == prm_1) {
                    AddrOfFunctionaly = (prm_0 + (*(UINT32*)(AddrOfFunction + ((*(UINT16*)(&prm_0 + (2 * cnt) + (*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x78])) + 36)))) * 4))));
                }
            }
            else if ((*(UINT16*)(&prm_0[0x18])) == 0x20b) {
                //64bit
                if ((*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x88])))) == 0)
                    break;
                AddrOfFunction = (UINT64)(&prm_0 + (*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x88])) + 28)));
                if ((char*)(&prm_0 + (*(UINT32*)(&prm_0 + (4 * cnt) + (*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x88])) + 32))))) == prm_1) {
                    AddrOfFunctionaly = (prm_0 + (*(UINT32*)(AddrOfFunction + ((*(UINT16*)(&prm_0 + (2 * cnt) + (*(UINT32*)(&prm_0 + (*(UINT32*)(&prm_0[0x88])) + 36)))) * 4))));
                }
            }
            if (AddrOfFunctionaly != 0) { break; }
            cnt++;
        }
        return AddrOfFunctionaly;
    }
#ifdef __cplusplus
}
#endif
