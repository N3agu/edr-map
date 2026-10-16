#include "hooks.h"
#include "types.h"
#include "output.h"

static const char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";

static PVOID ReadFileInMemory(const char* filePath) {
    HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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

    if (bytesRead != fileSize && !g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "[-] Failed to read file\n";
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

void EnumerateHookedFunctions() {
    g_results.hookScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Enumerating Hooked Userland Functions -----\n\n";
        if (!g_config.runSilent) GetOutStream() << "[!] Loading the clean NTDLL from Disk...\n";
    }

    PVOID diskNtdllBuffer = ReadFileInMemory(ntdllPath);
    if (!diskNtdllBuffer) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] Failed to load " << ntdllPath << " from Disk\n";
        }
        return;
    }

    if (!g_config.runSilent && !g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "\n[!] Parsing PE Headers to find Exports...\n";
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)diskNtdllBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        if (!g_config.outputJson && !g_config.outputCsv) GetOutStream() << "[-] DOS Signature != 'MZ'\n";
        VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
        return;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)diskNtdllBuffer + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        if (!g_config.outputJson && !g_config.outputCsv) GetOutStream() << "[-] NT Signature != 'PE\\0\\0'\n";
        VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
        return;
    }

    DWORD exportDirectoryRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportDirectoryRva) {
        if (!g_config.outputJson && !g_config.outputCsv) GetOutStream() << "[-] Can't find Export Directory\n";
        VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
        return;
    }

    DWORD exportDirectoryOffset = RvaToRawOffset(ntHeaders, exportDirectoryRva);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)diskNtdllBuffer + exportDirectoryOffset);

    if (!g_config.runSilent && !g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "[+] Export Directory found at RVA 0x" << std::hex << exportDirectoryRva << "\n";
        GetOutStream() << "[+] Found " << std::dec << exportDirectory->NumberOfNames << " Exported Functions\n";
        GetOutStream() << "\n[!] Getting handle to the NTDLL from Memory...\n";
    }

    HMODULE memoryNtdllBase = GetModuleHandleA("ntdll.dll");
    if (!memoryNtdllBase) {
        if (!g_config.outputJson && !g_config.outputCsv) GetOutStream() << "[-] Can't get handle to the NTDLL from Memory\n";
        VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
        return;
    }

    if (!g_config.runSilent && !g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "[+] Found Memory NTDLL base address at 0x" << memoryNtdllBase << "\n";
        GetOutStream() << "\n[!] Scanning for hooks in functions...\n";
    }

    PDWORD addressOfFunctions = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfFunctions));
    PDWORD addressOfNames = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNames));
    PWORD addressOfNameOrdinals = (PWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNameOrdinals));

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        char* functionName = (char*)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, addressOfNames[i]));

        if (!strncmp(functionName, "Nt", 2) ||
            !strncmp(functionName, "Zw", 2) ||
            !strncmp(functionName, "Etw", 3) ||
            !strncmp(functionName, "Ldr", 3) ||
            !strncmp(functionName, "Rtl", 3) ||
            !strncmp(functionName, "Ki", 2) ||
            !strncmp(functionName, "RegNt", 5)) {
            DWORD functionRva = addressOfFunctions[addressOfNameOrdinals[i]];
            PVOID diskFunctionAddress = (PVOID)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, functionRva));
            PVOID memoryFunctionAddress = (PVOID)((ULONG_PTR)memoryNtdllBase + functionRva);

            if (memcmp(diskFunctionAddress, memoryFunctionAddress, 16) != 0) {
                g_results.hookedFunctions.push_back(functionName);
                if (!g_config.outputJson && !g_config.outputCsv) {
                    GetOutStream() << "[*] HOOKED: " << functionName << "\n";
                }
            }
        }
    }

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (g_results.hookedFunctions.empty()) {
            GetOutStream() << "\n[-] No hooks detected in the functions";
        }
        else {
            GetOutStream() << "\n[+] Found " << g_results.hookedFunctions.size() << " hooks";
        }
    }

    VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
}