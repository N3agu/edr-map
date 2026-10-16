#include "hooks.h"
#include "types.h"
#include "output.h"
#include <algorithm>

static std::string GetSystemModulePath(const std::string& moduleName) {
    char systemDir[MAX_PATH];
    if (!GetSystemDirectoryA(systemDir, MAX_PATH)) {
        return "C:\\Windows\\System32\\" + moduleName;
    }
    return std::string(systemDir) + "\\" + moduleName;
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

            PVOID diskFunctionAddress = (PVOID)((ULONG_PTR)diskBuffer + RvaToRawOffset(ntHeaders, functionRva));
            PVOID memoryFunctionAddress = (PVOID)((ULONG_PTR)memoryBase + functionRva);

            if (memcmp(diskFunctionAddress, memoryFunctionAddress, 16) != 0) {
                g_results.hookedFunctions.push_back({ moduleName, functionName });
                if (!g_config.outputJson && !g_config.outputCsv) {
                    GetOutStream() << "[*] HOOKED [" << moduleName << "]: " << functionName << "\n";
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