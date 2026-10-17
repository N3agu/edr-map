#include "output.h"
#include "types.h"
#include <fstream>
#include <sstream>

static std::ofstream g_fileStream;

std::ostream& GetOutStream() {
    if (g_fileStream.is_open()) {
        return g_fileStream;
    }
    return std::cout;
}

bool InitializeOutputStream() {
    if (g_config.outputFile.empty()) return true;
    g_fileStream.open(g_config.outputFile, std::ios::out | std::ios::trunc);
    return g_fileStream.is_open();
}

void CloseOutputStream() {
    if (g_fileStream.is_open()) {
        g_fileStream.close();
        if (!g_config.runSilent) {
            std::cout << "\n[+] Output successfully written to " << g_config.outputFile << "\n";
        }
    }
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &str[0], sizeNeeded, NULL, NULL);
    return str;
}

std::string EscapeJsonString(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        if (c == '"') ss << "\\\"";
        else if (c == '\\') ss << "\\\\";
        else if (c == '\b') ss << "\\b";
        else if (c == '\f') ss << "\\f";
        else if (c == '\n') ss << "\\n";
        else if (c == '\r') ss << "\\r";
        else if (c == '\t') ss << "\\t";
        else ss << c;
    }
    return ss.str();
}

std::string EscapeCsvString(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        if (c == '"') ss << "\"\"";
        else ss << c;
    }
    return ss.str();
}

void PrintBanner() {
    GetOutStream() << R"""( _____ ____  ____    __  __              
| ____|  _ \|  _ \  |  \/  | __ _ _ __  
|  _| | | | | |_) | | |\/| |/ _` | '_ \ 
| |___| |_| |  _ <  | |  | | (_| | |_) |
|_____|____/|_| \_\ |_|  |_|\__,_| .__/ 
                                 |_|    
        github.com/N3agu/EDR-Map)""";
}

void PrintHelp() {
    GetOutStream() << "\n\nA modular scanner for AV/EDR userland hooks, telemetry sensors, and process integrity.\n\n"
        << "Usage: EDR_Map.exe [SCAN FLAGS] [OPTIONS]\n\n"
        << "Scan Engines (Default: Runs ALL if none are specified; can be combined):\n"
        << "  --hooks                    Scan userland DLL exports for inline hooks.\n"
        << "  --iat                      Audit Import Address Tables (IAT) for pointer redirection.\n"
        << "  --mem                      Scan virtual memory for unbacked executable / RWX pages.\n"
        << "  --peb                      Walk PEB loader list to detect injected/non-system DLLs & check signatures.\n"
        << "  --etw                      Enumerate active ETW trace sessions.\n"
        << "  --minifilters              Enumerate filesystem minifilter drivers and altitudes (Admin).\n"
        << "  --amsi                     Enumerate registered AMSI providers in the registry.\n"
        << "  --hwbp                     Inspect thread debug registers (DR0-DR7) for hardware breakpoints.\n\n"
        << "Options:\n"
        << "  -h, --help                 Show this help message and exit.\n"
        << "  -s, --silent               Disable verbose output (alerts only).\n"
        << "  --modules <m1,m2,...>      Comma-separated list of DLLs for --hooks and --iat (default: ntdll.dll).\n"
        << "  --all-modules              Target high-value DLLs (ntdll, kernel32, kernelbase, ws2_32, amsi).\n"
        << "  --json                     Output results in JSON format.\n"
        << "  --csv                      Output results in CSV format.\n"
        << "  -o, --output <file>        Write output directly to specified file.\n\n"
        << "Examples:\n"
        << "  EDR_Map.exe                                      # Run all scan engines with full output\n"
        << "  EDR_Map.exe --hooks --iat --all-modules          # Scan only inline & IAT hooks across core DLLs\n"
        << "  EDR_Map.exe --peb --mem -s                       # Check only injected DLLs and unbacked memory silently\n"
        << "  EDR_Map.exe --etw --amsi --json -o report.json   # Export ETW and AMSI telemetry audit to JSON\n";
}

void PrintJsonOutput() {
    std::ostream& out = GetOutStream();
    out << "{\n";

    bool needsComma = false;

    if (g_results.hookScanExecuted) {
        out << "  \"hooks\": [\n";
        for (size_t i = 0; i < g_results.hookedFunctions.size(); ++i) {
            const auto& h = g_results.hookedFunctions[i];
            std::ostringstream addrStr;
            addrStr << "0x" << std::hex << h.targetAddress;

            out << "    {\n"
                << "      \"module\": \"" << EscapeJsonString(h.moduleName) << "\",\n"
                << "      \"function\": \"" << EscapeJsonString(h.functionName) << "\",\n"
                << "      \"disk_bytes\": \"" << EscapeJsonString(h.diskBytesHex) << "\",\n"
                << "      \"memory_bytes\": \"" << EscapeJsonString(h.memoryBytesHex) << "\",\n"
                << "      \"target_address\": \"" << addrStr.str() << "\",\n"
                << "      \"target_module\": \"" << EscapeJsonString(h.targetModule) << "\"\n"
                << "    }";
            if (i + 1 < g_results.hookedFunctions.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        needsComma = true;
    }

    if (g_results.iatScanExecuted) {
        if (needsComma) out << ",\n";
        out << "  \"iat_hooks\": [\n";
        for (size_t i = 0; i < g_results.iatHooks.size(); ++i) {
            const auto& iat = g_results.iatHooks[i];
            std::ostringstream addrStr;
            addrStr << "0x" << std::hex << iat.currentAddress;
            out << "    {\n"
                << "      \"source_module\": \"" << EscapeJsonString(iat.sourceModule) << "\",\n"
                << "      \"imported_dll\": \"" << EscapeJsonString(iat.importedDll) << "\",\n"
                << "      \"function\": \"" << EscapeJsonString(iat.functionName) << "\",\n"
                << "      \"address\": \"" << addrStr.str() << "\",\n"
                << "      \"destination\": \"" << EscapeJsonString(iat.destinationModule) << "\"\n"
                << "    }";
            if (i + 1 < g_results.iatHooks.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        needsComma = true;
    }

    if (g_results.memoryScanExecuted) {
        if (needsComma) out << ",\n";
        out << "  \"executable_memory\": [\n";
        for (size_t i = 0; i < g_results.execMemoryRegions.size(); ++i) {
            const auto& m = g_results.execMemoryRegions[i];
            std::ostringstream baseStr, sizeStr;
            baseStr << "0x" << std::hex << m.baseAddress;
            sizeStr << "0x" << std::hex << m.regionSize;
            out << "    {\n"
                << "      \"base_address\": \"" << baseStr.str() << "\",\n"
                << "      \"size\": \"" << sizeStr.str() << "\",\n"
                << "      \"type\": \"" << EscapeJsonString(m.stateType) << "\",\n"
                << "      \"protection\": \"" << EscapeJsonString(m.protection) << "\",\n"
                << "      \"backing\": \"" << EscapeJsonString(m.mappedInfo) << "\"\n"
                << "    }";
            if (i + 1 < g_results.execMemoryRegions.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        needsComma = true;
    }

    if (g_results.pebScanExecuted) {
        if (needsComma) out << ",\n";
        out << "  \"peb_modules\": [\n";
        for (size_t i = 0; i < g_results.loadedModules.size(); ++i) {
            const auto& m = g_results.loadedModules[i];
            std::ostringstream baseStr, sizeStr;
            baseStr << "0x" << std::hex << m.baseAddress;
            sizeStr << "0x" << std::hex << m.sizeOfImage;
            out << "    {\n"
                << "      \"name\": \"" << EscapeJsonString(WStringToString(m.moduleName)) << "\",\n"
                << "      \"path\": \"" << EscapeJsonString(WStringToString(m.fullPath)) << "\",\n"
                << "      \"base_address\": \"" << baseStr.str() << "\",\n"
                << "      \"size\": \"" << sizeStr.str() << "\",\n"
                << "      \"signed\": " << (m.isSigned ? "true" : "false") << ",\n"
                << "      \"signer\": \"" << EscapeJsonString(WStringToString(m.signatureSigner)) << "\",\n"
                << "      \"non_system\": " << (m.isNonSystemPath ? "true" : "false") << ",\n"
                << "      \"security_vendor\": " << (m.isKnownSecurityVendor ? "true" : "false") << "\n"
                << "    }";
            if (i + 1 < g_results.loadedModules.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        needsComma = true;
    }

    if (g_results.etwScanExecuted) {
        if (needsComma) out << ",\n";
        out << "  \"etw_sessions\": [\n";
        for (size_t i = 0; i < g_results.flaggedEtwSessions.size(); ++i) {
            std::string session = WStringToString(g_results.flaggedEtwSessions[i]);
            out << "    \"" << EscapeJsonString(session) << "\"";
            if (i + 1 < g_results.flaggedEtwSessions.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        needsComma = true;
    }

    if (g_results.minifilterScanExecuted) {
        if (needsComma) out << ",\n";
        out << "  \"minifilters\": [\n";
        for (size_t i = 0; i < g_results.minifilters.size(); ++i) {
            const auto& flt = g_results.minifilters[i];
            out << "    {\n"
                << "      \"name\": \"" << EscapeJsonString(WStringToString(flt.name)) << "\",\n"
                << "      \"altitude\": \"" << EscapeJsonString(WStringToString(flt.altitude)) << "\",\n"
                << "      \"category\": \"" << EscapeJsonString(flt.category) << "\",\n"
                << "      \"instances\": " << flt.numInstances << ",\n"
                << "      \"flagged\": " << (flt.isSecurityTelemetry ? "true" : "false") << "\n"
                << "    }";
            if (i + 1 < g_results.minifilters.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        needsComma = true;
    }

    if (g_results.amsiScanExecuted) {
        if (needsComma) out << ",\n";
        out << "  \"amsi_providers\": [\n";
        for (size_t i = 0; i < g_results.amsiProviders.size(); ++i) {
            const auto& p = g_results.amsiProviders[i];
            out << "    {\n"
                << "      \"guid\": \"" << EscapeJsonString(WStringToString(p.guid)) << "\",\n"
                << "      \"name\": \"" << EscapeJsonString(WStringToString(p.friendlyName)) << "\",\n"
                << "      \"dll_path\": \"" << EscapeJsonString(WStringToString(p.dllPath)) << "\",\n"
                << "      \"security_vendor\": " << (p.isSecurityVendor ? "true" : "false") << "\n"
                << "    }";
            if (i + 1 < g_results.amsiProviders.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        needsComma = true;
    }

    if (g_results.hwbpScanExecuted) {
        if (needsComma) out << ",\n";
        out << "  \"hardware_breakpoints\": [\n";
        for (size_t i = 0; i < g_results.hwBreakpoints.size(); ++i) {
            const auto& bp = g_results.hwBreakpoints[i];
            std::ostringstream addrStr;
            addrStr << "0x" << std::hex << bp.address;
            out << "    {\n"
                << "      \"register\": \"DR" << bp.registerIndex << "\",\n"
                << "      \"address\": \"" << addrStr.str() << "\",\n"
                << "      \"condition\": \"" << EscapeJsonString(bp.condition) << "\",\n"
                << "      \"symbol\": \"" << EscapeJsonString(bp.symbolInfo) << "\"\n"
                << "    }";
            if (i + 1 < g_results.hwBreakpoints.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
    }

    out << "\n}\n";
}

void PrintCsvOutput() {
    std::ostream& out = GetOutStream();
    out << "category,source,name,target_or_path,details\n";

    if (g_results.hookScanExecuted) {
        for (const auto& item : g_results.hookedFunctions) {
            out << "hook,\"" << EscapeCsvString(item.moduleName) << "\",\""
                << EscapeCsvString(item.functionName) << "\",\""
                << EscapeCsvString(item.targetModule) << "\",\""
                << EscapeCsvString("Disk: " + item.diskBytesHex + " | Mem: " + item.memoryBytesHex) << "\"\n";
        }
    }
    if (g_results.iatScanExecuted) {
        for (const auto& iat : g_results.iatHooks) {
            out << "iat_hook,\"" << EscapeCsvString(iat.sourceModule) << "\",\""
                << EscapeCsvString(iat.importedDll + "!" + iat.functionName) << "\",\""
                << EscapeCsvString(iat.destinationModule) << "\",\"\"\n";
        }
    }
    if (g_results.memoryScanExecuted) {
        for (const auto& m : g_results.execMemoryRegions) {
            std::ostringstream baseStr;
            baseStr << "0x" << std::hex << m.baseAddress;
            out << "exec_mem,\"" << EscapeCsvString(m.stateType) << "\",\""
                << baseStr.str() << "\",\""
                << EscapeCsvString(m.mappedInfo) << "\",\""
                << EscapeCsvString(m.protection) << "\"\n";
        }
    }
    if (g_results.pebScanExecuted) {
        for (const auto& m : g_results.loadedModules) {
            std::ostringstream baseStr;
            baseStr << "0x" << std::hex << m.baseAddress;
            out << "peb_module,\"" << EscapeCsvString(WStringToString(m.moduleName)) << "\",\""
                << baseStr.str() << "\",\""
                << EscapeCsvString(WStringToString(m.fullPath)) << "\",\""
                << EscapeCsvString(WStringToString(m.signatureSigner)) << "\"\n";
        }
    }
    if (g_results.etwScanExecuted) {
        for (const auto& session : g_results.flaggedEtwSessions) {
            out << "etw,\"System\",\"" << EscapeCsvString(WStringToString(session)) << "\",\"\",\"Flagged Session\"\n";
        }
    }
    if (g_results.minifilterScanExecuted) {
        for (const auto& flt : g_results.minifilters) {
            out << "minifilter,\"Kernel\",\"" << EscapeCsvString(WStringToString(flt.name)) << "\",\""
                << EscapeCsvString(WStringToString(flt.altitude)) << "\",\""
                << EscapeCsvString(flt.category) << "\"\n";
        }
    }
    if (g_results.amsiScanExecuted) {
        for (const auto& p : g_results.amsiProviders) {
            out << "amsi_provider,\"" << EscapeCsvString(WStringToString(p.friendlyName)) << "\",\""
                << EscapeCsvString(WStringToString(p.guid)) << "\",\""
                << EscapeCsvString(WStringToString(p.dllPath)) << "\",\"\"\n";
        }
    }
    if (g_results.hwbpScanExecuted) {
        for (const auto& bp : g_results.hwBreakpoints) {
            std::ostringstream addrStr;
            addrStr << "0x" << std::hex << bp.address;
            out << "hwbp,\"DR" << bp.registerIndex << "\",\""
                << addrStr.str() << "\",\""
                << EscapeCsvString(bp.symbolInfo) << "\",\""
                << EscapeCsvString(bp.condition) << "\"\n";
        }
    }
}