#include "memory_audit.h"
#include "types.h"
#include "output.h"
#include <psapi.h>
#include <sstream>

#pragma comment(lib, "psapi.lib")

static bool IsExecutableProtection(DWORD protect) {
    if (protect & PAGE_GUARD || protect & PAGE_NOACCESS) {
        return false;
    }
    DWORD baseProtect = protect & 0xFF;
    return (baseProtect == PAGE_EXECUTE ||
        baseProtect == PAGE_EXECUTE_READ ||
        baseProtect == PAGE_EXECUTE_READWRITE ||
        baseProtect == PAGE_EXECUTE_WRITECOPY);
}

static std::string ProtectionToString(DWORD protect) {
    DWORD baseProtect = protect & 0xFF;
    switch (baseProtect) {
    case PAGE_EXECUTE:           return "PAGE_EXECUTE (X)";
    case PAGE_EXECUTE_READ:      return "PAGE_EXECUTE_READ (RX)";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE (RWX)";
    case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY (WCX)";
    default:                     return "Other";
    }
}

static std::string TypeToString(DWORD type) {
    switch (type) {
    case MEM_PRIVATE: return "MEM_PRIVATE";
    case MEM_MAPPED:  return "MEM_MAPPED";
    case MEM_IMAGE:   return "MEM_IMAGE";
    default:          return "UNKNOWN";
    }
}

void EnumerateExecutableMemory() {
    g_results.memoryScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Scanning Virtual Memory for Unbacked Executable Pages -----\n\n";
    }

    SYSTEM_INFO sysInfo = { 0 };
    GetSystemInfo(&sysInfo);

    LPBYTE currentAddr = (LPBYTE)sysInfo.lpMinimumApplicationAddress;
    LPBYTE maxAddr = (LPBYTE)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    HANDLE hProcess = GetCurrentProcess();

    while (currentAddr < maxAddr && VirtualQuery(currentAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && IsExecutableProtection(mbi.Protect)) {
            bool isUnbacked = (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED);
            bool isRwxImage = (mbi.Type == MEM_IMAGE && ((mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE));

            if (isUnbacked || isRwxImage) {
                char mappedName[MAX_PATH] = { 0 };
                std::string details = "Unbacked / Anonymous Allocation";

                if (GetMappedFileNameA(hProcess, mbi.BaseAddress, mappedName, MAX_PATH) > 0) {
                    details = mappedName;
                }

                ExecMemoryFinding finding = {
                    reinterpret_cast<ULONG_PTR>(mbi.BaseAddress),
                    mbi.RegionSize,
                    ProtectionToString(mbi.Protect),
                    TypeToString(mbi.Type),
                    details
                };

                g_results.execMemoryRegions.push_back(finding);

                if (!g_config.outputJson && !g_config.outputCsv) {
                    GetOutStream() << "[*] ANOMALOUS EXEC PAGE: 0x" << std::hex << finding.baseAddress
                        << " (Size: 0x" << finding.regionSize << std::dec << ")\n"
                        << "    Type       : " << finding.stateType << "\n"
                        << "    Protection : " << finding.protection << "\n"
                        << "    Backing    : " << finding.mappedInfo << "\n";
                }
            }
        }

        currentAddr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (g_results.execMemoryRegions.empty()) {
            GetOutStream() << "[-] No unbacked executable or RWX image pages found.\n";
        }
        else {
            GetOutStream() << "\n[!] Detected " << g_results.execMemoryRegions.size()
                << " anomalous executable memory region(s) (potential EDR trampolines or injected code).\n";
        }
    }
}