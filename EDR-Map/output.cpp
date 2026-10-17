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
            std::cout << "[+] Output successfully written to " << g_config.outputFile << "\n";
        }
    }
}

std::string WStringToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], sizeNeeded, NULL, NULL);
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

void PrintBanner() {
    GetOutStream() << R"""( _____ ____   ____   __  __              
| ____|  _ \|  _ \  |  \/  | __ _ _ __  
|  _| | | | | |_) | | |\/| |/ _` | '_ \ 
| |___| |_| |  _ <  | |  | | (_| | |_) |
|_____|____/|_| \_\ |_|  |_|\__,_| .__/ 
                                 |_|    
        github.com/N3agu/EDR-Map)""";
}

void PrintHelp() {
    GetOutStream() << "\n\nA comprehensive auditing tool for AV/EDR hooks, ETW, minifilters, AMSI, HWBP, IAT, and memory.\n\n"
        << "Usage: EDR_Map.exe [OPTIONS]\n\n"
        << "Options:\n"
        << "  -h, --help                 Show this help message and exit.\n"
        << "  -s, --silent               Disable verbose output (alerts only).\n"
        << "  --etwonly                  Run ONLY ETW session enumeration.\n"
        << "  --hooksonly                Run ONLY userland API hook scanning.\n"
        << "  --minifiltersonly          Run ONLY filesystem minifilter driver enumeration.\n"
        << "  --amsionly                 Run ONLY AMSI provider inspection.\n"
        << "  --hwbponly                 Run ONLY hardware breakpoint detection.\n"
        << "  --memonly                  Run ONLY unbacked executable memory page scan.\n"
        << "  --iatonly                  Run ONLY Import Address Table (IAT) integrity check.\n"
        << "  --modules <m1,m2,...>      Comma-separated list of DLLs to scan.\n"
        << "  --all-modules              Scan high-value targets (ntdll, kernel32, kernelbase, ws2_32, amsi).\n"
        << "  --json                     Output results in JSON format.\n"
        << "  --csv                      Output results in CSV format.\n"
        << "  -o, --output <file>        Write output directly to specified file.\n\n";
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
    }

    out << "\n}\n";
}

void PrintCsvOutput() {
    std::ostream& out = GetOutStream();
    out << "type,module,name,extra1,extra2\n";
    if (g_results.hookScanExecuted) {
        for (const auto& item : g_results.hookedFunctions) {
            out << "hook,\"" << item.moduleName << "\",\"" << item.functionName << "\",\""
                << item.targetModule << "\",\"" << item.diskBytesHex << "\"\n";
        }
    }
    if (g_results.etwScanExecuted) {
        for (const auto& session : g_results.flaggedEtwSessions) {
            out << "etw,\"\",\"" << WStringToString(session) << "\",\"\",\n";
        }
    }
    if (g_results.minifilterScanExecuted) {
        for (const auto& flt : g_results.minifilters) {
            out << "minifilter,\"\",\"" << WStringToString(flt.name) << "\",\""
                << WStringToString(flt.altitude) << "\",\"" << flt.category << "\"\n";
        }
    }
    if (g_results.amsiScanExecuted) {
        for (const auto& p : g_results.amsiProviders) {
            out << "amsi_provider,\"" << WStringToString(p.friendlyName) << "\",\""
                << WStringToString(p.guid) << "\",\"" << WStringToString(p.dllPath) << "\",\n";
        }
    }
    if (g_results.hwbpScanExecuted) {
        for (const auto& bp : g_results.hwBreakpoints) {
            std::ostringstream addrStr;
            addrStr << "0x" << std::hex << bp.address;
            out << "hwbp,\"DR" << bp.registerIndex << "\",\""
                << addrStr.str() << "\",\"" << bp.condition << "\",\"" << bp.symbolInfo << "\"\n";
        }
    }
    if (g_results.memoryScanExecuted) {
        for (const auto& m : g_results.execMemoryRegions) {
            std::ostringstream baseStr;
            baseStr << "0x" << std::hex << m.baseAddress;
            out << "exec_mem,\"" << m.stateType << "\",\"" << baseStr.str() << "\",\""
                << m.protection << "\",\"" << m.mappedInfo << "\"\n";
        }
    }
    if (g_results.iatScanExecuted) {
        for (const auto& iat : g_results.iatHooks) {
            out << "iat_hook,\"" << iat.sourceModule << "\",\"" << iat.importedDll << "!" << iat.functionName
                << "\",\"" << iat.destinationModule << "\",\"\"\n";
        }
    }
}