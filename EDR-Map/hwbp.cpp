#include "hwbp.h"
#include "types.h"
#include "output.h"
#include <sstream>

static std::string ResolveAddressToModule(ULONG_PTR address) {
    if (address == 0) return "None";

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
    return "Non-Module / Private Memory";
}

static std::string DecodeHwbpCondition(DWORD_PTR dr7, int index) {
    // In DR7, condition bits for Dr0-Dr3 start at bit 16:
    // Bits 16-17: Dr0, Bits 20-21: Dr1, Bits 24-25: Dr2, Bits 28-29: Dr3
    int shift = 16 + (index * 4);
    DWORD condition = (dr7 >> shift) & 0x3;

    switch (condition) {
    case 0: return "Execute";
    case 1: return "Data Write";
    case 2: return "I/O Read/Write (unused/legacy)";
    case 3: return "Data Read/Write";
    default: return "Unknown";
    }
}

void EnumerateHardwareBreakpoints() {
    g_results.hwbpScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Inspecting Hardware Breakpoints (Debug Registers) -----\n\n";
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE hThread = GetCurrentThread();
    if (!GetThreadContext(hThread, &ctx)) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] Failed to get thread context for hardware breakpoint scan.\n";
        }
        return;
    }

    ULONG_PTR drAddresses[4] = {
        ctx.Dr0,
        ctx.Dr1,
        ctx.Dr2,
        ctx.Dr3
    };

    DWORD_PTR dr7 = ctx.Dr7;
    int activeBpCount = 0;

    for (int i = 0; i < 4; ++i) {
        bool localEnable = (dr7 & (1ULL << (i * 2))) != 0;
        bool globalEnable = (dr7 & (1ULL << (i * 2 + 1))) != 0;
        bool isActive = (localEnable || globalEnable) || (drAddresses[i] != 0);

        if (isActive) {
            activeBpCount++;
            std::string condition = DecodeHwbpCondition(dr7, i);
            std::string symbol = ResolveAddressToModule(drAddresses[i]);

            HwBreakpointFinding finding = {
                i,
                drAddresses[i],
                condition,
                symbol,
                true
            };

            g_results.hwBreakpoints.push_back(finding);

            if (!g_config.outputJson && !g_config.outputCsv) {
                GetOutStream() << "[*] FLAGGED: Hardware Breakpoint active in DR" << i << "\n"
                    << "    Address   : 0x" << std::hex << drAddresses[i] << std::dec << "\n"
                    << "    Condition : " << condition << "\n"
                    << "    Location  : " << symbol << "\n";
            }
        }
    }

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (activeBpCount == 0) {
            GetOutStream() << "[-] No hardware breakpoints active (DR0-DR3 clear, DR7=0x"
                << std::hex << dr7 << std::dec << ").\n";
        }
        else {
            GetOutStream() << "\n[!] Alert: " << activeBpCount
                << " active debug breakpoint(s) detected. Possible hookless EDR telemetry or debugger attached.\n";
        }
    }
}