#include "hooks.h"
#include "types.h"
#include "output.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

static std::string GetSystemModulePath(const std::string& moduleName) {
    char systemDir[MAX_PATH];
    if (!GetSystemDirectoryA(systemDir, MAX_PATH)) {
        return "C:\\Windows\\System32\\" + moduleName;
    }
    return std::string(systemDir) + "\\" + moduleName;
}

static std::string BytesToHexString(const BYTE* bytes, size_t length) {
    std::ostringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
        if (i + 1 < length) ss << " ";
    }
    return ss.str();
}

static ULONG_PTR ResolveJumpTarget(const BYTE* code, ULONG_PTR functionAddress) {
    // 1. E9 <rel32>: JMP rel32
    if (code[0] == 0xE9) {
        INT32 relOffset = *reinterpret_cast<const INT32*>(code + 1);
        return functionAddress + 5 + static_cast<INT_PTR>(relOffset);
    }

    // 2. EB <rel8>: JMP rel8 (Sometimes leads to a secondary E9 or FF 25 right before/after)
    if (code[0] == 0xEB) {
        INT8 relOffset = *reinterpret_cast<const INT8*>(code + 1);
        ULONG_PTR shortTarget = functionAddress + 2 + static_cast<INT_PTR>(relOffset);
        return shortTarget;
    }

    // 3. FF 25 <rel32>: JMP QWORD PTR [RIP + rel32] (x64) or [abs32] (x86)
    if (code[0] == 0xFF && code[1] == 0x25) {
        INT32 relOffset = *reinterpret_cast<const INT32*>(code + 2);
#ifdef _WIN64
        ULONG_PTR pointerAddress = functionAddress + 6 + static_cast<INT_PTR>(relOffset);
#else
        ULONG_PTR pointerAddress = static_cast<ULONG_PTR>(relOffset);
#endif
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<LPCVOID>(pointerAddress), &mbi, sizeof(mbi)) &&
            mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
            return *reinterpret_cast<const ULONG_PTR*>(pointerAddress);
        }
    }

#ifdef _WIN64
    // 4. 48 B8 <imm64> FF E0: MOV RAX, imm64; JMP RAX
    if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0) {
        return *reinterpret_cast<const ULONG_PTR*>(code + 2);
    }

    // 5. 49 BA <imm64> 41 FF E2: MOV R10, imm64; JMP R10
    if (code[0] == 0x49 && code[1] == 0xBA && code[10] == 0x41 && code[11] == 0xFF && code[12] == 0xE2) {
        return *reinterpret_cast<const ULONG_PTR*>(code + 2);
    }
#endif

    // 6. Check if hook starts after `MOV R10, RCX` (4C 8B D1) - very common in syscall stubs
    if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1) {
        if (code[3] == 0xE9) {
            INT32 relOffset = *reinterpret_cast<const INT32*>(code + 4);
            return (functionAddress + 3) + 5 + static_cast<INT_PTR>(relOffset);
        }
        if (code[3] == 0xFF && code[4] == 0x25) {
            INT32 relOffset = *reinterpret_cast<const INT32*>(code + 5);
#ifdef _WIN64
            ULONG_PTR pointerAddress = (functionAddress + 3) + 6 + static_cast<INT_PTR>(relOffset);
#else
            ULONG_PTR pointerAddress = static_cast<ULONG_PTR>(relOffset);
#endif
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(reinterpret_cast<LPCVOID>(pointerAddress), &mbi, sizeof(mbi)) &&
                mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                return *reinterpret_cast<const ULONG_PTR*>(pointerAddress);
            }
        }
    }

    return 0;
}

static std::string ResolveAddressOwner(ULONG_PTR targetAddress) {
    if (targetAddress == 0) {
        return "Unresolved (Unrecognized trampoline pattern)";
    }

    HMODULE hMod = NULL;
    if (GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(targetAddress),
        &hMod) && hMod != NULL) {

        char modPath[MAX_PATH] = { 0 };
        if (GetModuleFileNameA(hMod, modPath, MAX_PATH)) {
            ULONG_PTR offset = targetAddress - reinterpret_cast<ULONG_PTR>(hMod);
            std::ostringstream ss;
            ss << modPath << " + 0x" << std::hex << offset;
            return ss.str();
        }
    }

    // If not directly inside a registered PE module, check if it jumps to an intermediate trampoline page
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(targetAddress), &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT) {
        const BYTE* trampCode = reinterpret_cast<const BYTE*>(targetAddress);
        ULONG_PTR secondHop = ResolveJumpTarget(trampCode, targetAddress);
        if (secondHop != 0 && secondHop != targetAddress) {
            HMODULE hMod2 = NULL;
            if (GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(secondHop),
                &hMod2) && hMod2 != NULL) {
                char modPath[MAX_PATH] = { 0 };
                if (GetModuleFileNameA(hMod2, modPath, MAX_PATH)) {
                    ULONG_PTR offset = secondHop - reinterpret_cast<ULONG_PTR>(hMod2);
                    std::ostringstream ss;
                    ss << modPath << " + 0x" << std::hex << offset << " (via trampoline page)";
                    return ss.str();
                }
            }
        }

        std::ostringstream ss;
        ss << "Unbacked Memory Region (Base: 0x" << std::hex << reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) << ")";
        return ss.str();
    }

    return "Unknown Memory Region";
}

static PVOID ReadFileInMemory(const std::string& filePath) {
    HANDLE fileHandle = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] Failed to open file (" << filePath << ")\n";
            GetOutStream() << "[-] Error: " << GetLastError() << "\n";
        }
        return NULL;
    }

    DWORD fileSize = GetFileSize(fileHandle, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] Failed to get file size\n";
        }
        CloseHandle(fileHandle);
        return NULL;
    }

    PVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fileBuffer && !g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "[-] Can't allocate memory\n";
    }

    DWORD bytesRead;
    if (!ReadFile(fileHandle, fileBuffer, fileSize, &bytesRead, NULL)) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] ReadFile failed\n";
            GetOutStream() << "[-] Error: " << GetLastError() << "\n";
        }
        VirtualFree(fileBuffer, 0, MEM_RELEASE);
        CloseHandle(fileHandle);
        return NULL;
    }

    CloseHandle(fileHandle);

    if (!g_config.runSilent && !g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "[+] Loaded " << filePath << " in memory at 0x" << fileBuffer << "\n";
    }

    return fileBuffer;
}

static DWORD RvaToRawOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
        DWORD sectionSize = sectionHeader->Misc.VirtualSize;
        DWORD sectionAddress = sectionHeader->VirtualAddress;
        if (rva >= sectionAddress && rva < sectionAddress + sectionSize) {
            return rva - sectionAddress + sectionHeader->PointerToRawData;
        }
    }
    return 0;
}

static bool ShouldScanFunction(const std::string& moduleName, const char* functionName) {
    std::string lowerMod = moduleName;
    std::transform(lowerMod.begin(), lowerMod.end(), lowerMod.begin(), ::tolower);

    if (lowerMod == "ntdll.dll") {
        return (!strncmp(functionName, "Nt", 2) ||
            !strncmp(functionName, "Zw", 2) ||
            !strncmp(functionName, "Etw", 3) ||
            !strncmp(functionName, "Ldr", 3) ||
            !strncmp(functionName, "Rtl", 3) ||
            !strncmp(functionName, "Ki", 2) ||
            !strncmp(functionName, "RegNt", 5));
    }

    return true;
}

void ScanModule(const std::string& moduleName) {
    std::string diskPath = GetSystemModulePath(moduleName);

    if (!g_config.outputJson && !g_config.outputCsv && !g_config.runSilent) {
        GetOutStream() << "\n[*] Processing module: " << moduleName << "\n";
    }

    PVOID diskBuffer = ReadFileInMemory(diskPath);
    if (!diskBuffer) {
        return;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)diskBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        VirtualFree(diskBuffer, 0, MEM_RELEASE);
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)diskBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        VirtualFree(diskBuffer, 0, MEM_RELEASE);
        return;
    }

    DWORD exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exportSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exportRva) {
        VirtualFree(diskBuffer, 0, MEM_RELEASE);
        return;
    }

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)diskBuffer + RvaToRawOffset(ntHeaders, exportRva));

    HMODULE memoryBase = GetModuleHandleA(moduleName.c_str());
    bool loadedByUs = false;

    if (!memoryBase) {
        memoryBase = LoadLibraryA(moduleName.c_str());
        if (!memoryBase) {
            if (!g_config.outputJson && !g_config.outputCsv && !g_config.runSilent) {
                GetOutStream() << "[-] Module not loaded in memory and could not be loaded: " << moduleName << "\n";
            }
            VirtualFree(diskBuffer, 0, MEM_RELEASE);
            return;
        }
        loadedByUs = true;
    }

    PDWORD addressOfFunctions = (PDWORD)((ULONG_PTR)diskBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfFunctions));
    PDWORD addressOfNames = (PDWORD)((ULONG_PTR)diskBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNames));
    PWORD addressOfNameOrdinals = (PWORD)((ULONG_PTR)diskBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNameOrdinals));

    size_t initialHooks = g_results.hookedFunctions.size();

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        char* functionName = (char*)((ULONG_PTR)diskBuffer + RvaToRawOffset(ntHeaders, addressOfNames[i]));

        if (ShouldScanFunction(moduleName, functionName)) {
            DWORD functionRva = addressOfFunctions[addressOfNameOrdinals[i]];

            if (functionRva >= exportRva && functionRva < exportRva + exportSize) {
                continue;
            }

            DWORD rawOffset = RvaToRawOffset(ntHeaders, functionRva);
            if (!rawOffset) continue;

            const BYTE* diskFunctionBytes = (const BYTE*)((ULONG_PTR)diskBuffer + rawOffset);
            const BYTE* memoryFunctionBytes = (const BYTE*)((ULONG_PTR)memoryBase + functionRva);

            if (memcmp(diskFunctionBytes, memoryFunctionBytes, 16) != 0) {
                std::string diskHex = BytesToHexString(diskFunctionBytes, 16);
                std::string memHex = BytesToHexString(memoryFunctionBytes, 16);
                ULONG_PTR targetAddr = ResolveJumpTarget(memoryFunctionBytes, (ULONG_PTR)memoryFunctionBytes);
                std::string ownerModule = ResolveAddressOwner(targetAddr);

                g_results.hookedFunctions.push_back({
                    moduleName,
                    functionName,
                    diskHex,
                    memHex,
                    targetAddr,
                    ownerModule
                    });

                if (!g_config.outputJson && !g_config.outputCsv) {
                    GetOutStream() << "[*] HOOKED [" << moduleName << "]: " << functionName << "\n"
                        << "    Disk   : " << diskHex << "\n"
                        << "    Memory : " << memHex << "\n";
                    if (targetAddr != 0) {
                        GetOutStream() << "    Target : 0x" << std::hex << targetAddr << std::dec << " (" << ownerModule << ")\n";
                    }
                    else {
                        GetOutStream() << "    Target : " << ownerModule << "\n";
                    }
                }
            }
        }
    }

    if (loadedByUs) {
        FreeLibrary(memoryBase);
    }

    VirtualFree(diskBuffer, 0, MEM_RELEASE);

    if (!g_config.outputJson && !g_config.outputCsv && !g_config.runSilent) {
        size_t found = g_results.hookedFunctions.size() - initialHooks;
        GetOutStream() << "[+] Completed " << moduleName << " (" << found << " hooks detected)\n";
    }
}

void EnumerateHookedFunctions() {
    g_results.hookScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Enumerating Hooked Userland Functions -----\n";
    }

    for (const auto& moduleName : g_config.targetModules) {
        ScanModule(moduleName);
    }

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (g_results.hookedFunctions.empty()) {
            GetOutStream() << "\n[-] No hooks detected across scanned modules\n";
        }
        else {
            GetOutStream() << "\n[+] Total hooks found: " << g_results.hookedFunctions.size() << "\n";
        }
    }
}