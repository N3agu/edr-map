#include "iat_audit.h"
#include "types.h"
#include "output.h"
#include <psapi.h>
#include <sstream>

#pragma comment(lib, "psapi.lib")

static std::string ResolvePointerOwner(ULONG_PTR address) {
    HMODULE hMod = NULL;
    if (GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(address),
        &hMod) && hMod != NULL) {
        char modPath[MAX_PATH] = { 0 };
        if (GetModuleFileNameA(hMod, modPath, MAX_PATH)) {
            ULONG_PTR offset = address - reinterpret_cast<ULONG_PTR>(hMod);
            std::ostringstream ss;
            ss << modPath << " + 0x" << std::hex << offset;
            return ss.str();
        }
    }
    return "Unbacked / Private Trampoline Memory";
}

static bool IsForwardedExport(HMODULE hTargetMod, ULONG_PTR funcAddress) {
    if (!hTargetMod) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hTargetMod;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)hTargetMod + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    HMODULE hActualOwner = NULL;
    if (GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(funcAddress),
        &hActualOwner) && hActualOwner != NULL) {

        char actualPath[MAX_PATH] = { 0 };
        char sysDir[MAX_PATH] = { 0 };
        if (GetModuleFileNameA(hActualOwner, actualPath, MAX_PATH) && GetSystemDirectoryA(sysDir, MAX_PATH)) {
            if (_strnicmp(actualPath, sysDir, strlen(sysDir)) == 0) {
                return true;
            }
        }
    }
    return false;
}

static void InspectModuleIat(const std::string& moduleLabel, HMODULE hModule) {
    if (!hModule) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD importRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!importRva) return;

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)hModule + importRva);

    for (; importDesc->Name != 0; ++importDesc) {
        const char* importedDllName = (const char*)((ULONG_PTR)hModule + importDesc->Name);
        if (!importedDllName) continue;

        if (_strnicmp(importedDllName, "api-ms-win-", 11) == 0 ||
            _strnicmp(importedDllName, "ext-ms-win-", 11) == 0) {
            continue;
        }

        HMODULE hImportedMod = GetModuleHandleA(importedDllName);
        if (!hImportedMod) continue;

        MODULEINFO modInfo = { 0 };
        if (!GetModuleInformation(GetCurrentProcess(), hImportedMod, &modInfo, sizeof(modInfo))) {
            continue;
        }

        ULONG_PTR modStart = reinterpret_cast<ULONG_PTR>(modInfo.lpBaseOfDll);
        ULONG_PTR modEnd = modStart + modInfo.SizeOfImage;

        PIMAGE_THUNK_DATA origThunk = importDesc->OriginalFirstThunk
            ? (PIMAGE_THUNK_DATA)((ULONG_PTR)hModule + importDesc->OriginalFirstThunk)
            : (PIMAGE_THUNK_DATA)((ULONG_PTR)hModule + importDesc->FirstThunk);

        PIMAGE_THUNK_DATA iatThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)hModule + importDesc->FirstThunk);

        for (; origThunk->u1.AddressOfData != 0; ++origThunk, ++iatThunk) {
            ULONG_PTR resolvedFuncAddr = (ULONG_PTR)iatThunk->u1.Function;

            if (resolvedFuncAddr < modStart || resolvedFuncAddr >= modEnd) {
                if (IsForwardedExport(hImportedMod, resolvedFuncAddr)) {
                    continue;
                }

                std::string funcName;
                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                    std::ostringstream ss;
                    ss << "Ordinal_" << IMAGE_ORDINAL(origThunk->u1.Ordinal);
                    funcName = ss.str();
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)hModule + origThunk->u1.AddressOfData);
                    funcName = importByName->Name;
                }

                std::string destMod = ResolvePointerOwner(resolvedFuncAddr);

                IatHookFinding finding = {
                    moduleLabel,
                    importedDllName,
                    funcName,
                    resolvedFuncAddr,
                    destMod
                };

                g_results.iatHooks.push_back(finding);

                if (!g_config.outputJson && !g_config.outputCsv) {
                    GetOutStream() << "[*] IAT HOOK [" << moduleLabel << " -> " << importedDllName << "!" << funcName << "]\n"
                        << "    Pointing To : 0x" << std::hex << resolvedFuncAddr << std::dec << "\n"
                        << "    Destination : " << destMod << "\n";
                }
            }
        }
    }
}

void EnumerateIatHooks() {
    g_results.iatScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Auditing Import Address Table (IAT) Integrity -----\n\n";
    }

    InspectModuleIat("MainExecutable", GetModuleHandleA(NULL));

    for (const auto& modName : g_config.targetModules) {
        HMODULE hMod = GetModuleHandleA(modName.c_str());
        if (hMod) {
            InspectModuleIat(modName, hMod);
        }
    }

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (g_results.iatHooks.empty()) {
            GetOutStream() << "[-] All inspected IAT entries point within expected module boundaries.\n";
        }
        else {
            GetOutStream() << "\n[!] Detected " << g_results.iatHooks.size() << " redirected IAT entry(s).\n";
        }
    }
}