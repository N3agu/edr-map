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
    GetOutStream() << R"""( _____ ____   ____    __  __              
| ____|  _ \|  _ \  |  \/  | __ _ _ __  
|  _| | | | | |_) | | |\/| |/ _` | '_ \ 
| |___| |_| |  _ <  | |  | | (_| | |_) |
|_____|____/|_| \_\ |_|  |_|\__,_| .__/ 
                                 |_|    
        github.com/N3agu/EDR-Map)""";
}

void PrintHelp() {
    GetOutStream() << "\n\nA lightweight scanner that detects AV/EDR userland hooks, active ETW sessions, and minifilter drivers.\n\n"
        << "Usage: EDR_Map.exe [OPTIONS]\n\n"
        << "Options:\n"
        << "  -h, --help                 Show this help message and exit.\n"
        << "  -s, --silent               Disable verbose output (alerts only).\n"
        << "  --etwonly                  Run ONLY ETW session enumeration.\n"
        << "  --hooksonly                Run ONLY userland API hook scanning.\n"
        << "  --minifiltersonly          Run ONLY filesystem minifilter driver enumeration.\n"
        << "  --modules <m1,m2,...>      Comma-separated list of DLLs to scan.\n"
        << "  --all-modules              Scan high-value targets (ntdll, kernel32, kernelbase, ws2_32, amsi).\n"
        << "  --json                     Output results in JSON format.\n"
        << "  --csv                      Output results in CSV format.\n"
        << "  -o, --output <file>        Write output directly to specified file.\n\n"
        << "Examples:\n"
        << "  EDR_Map.exe                                      # Full audit with all modules\n"
        << "  EDR_Map.exe --minifiltersonly                    # Only check filter drivers and altitudes\n"
        << "  EDR_Map.exe --all-modules --json -o report.json  # Full scan exported to JSON\n";
}

void PrintJsonOutput() {
    std::ostream& out = GetOutStream();
    out << "{\n";

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
        if (g_results.etwScanExecuted || g_results.minifilterScanExecuted) out << ",";
        out << "\n";
    }

    if (g_results.etwScanExecuted) {
        out << "  \"etw_sessions\": [\n";
        for (size_t i = 0; i < g_results.flaggedEtwSessions.size(); ++i) {
            std::string session = WStringToString(g_results.flaggedEtwSessions[i]);
            out << "    \"" << EscapeJsonString(session) << "\"";
            if (i + 1 < g_results.flaggedEtwSessions.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        if (g_results.minifilterScanExecuted) out << ",";
        out << "\n";
    }

    if (g_results.minifilterScanExecuted) {
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
        out << "  ]\n";
    }

    out << "}\n";
}

void PrintCsvOutput() {
    std::ostream& out = GetOutStream();
    out << "type,module,name,disk_bytes,memory_bytes,target_module,altitude,category\n";
    if (g_results.hookScanExecuted) {
        for (const auto& item : g_results.hookedFunctions) {
            out << "hook,\"" << item.moduleName << "\",\"" << item.functionName << "\",\""
                << item.diskBytesHex << "\",\"" << item.memoryBytesHex << "\",\""
                << item.targetModule << "\",\"\",\"\"\n";
        }
    }
    if (g_results.etwScanExecuted) {
        for (const auto& session : g_results.flaggedEtwSessions) {
            out << "etw,\"\",\"" << WStringToString(session) << "\",\"\",\"\",\"\",\"\",\"\"\n";
        }
    }
    if (g_results.minifilterScanExecuted) {
        for (const auto& flt : g_results.minifilters) {
            out << "minifilter,\"\",\"" << WStringToString(flt.name) << "\",\"\",\"\",\"\",\""
                << WStringToString(flt.altitude) << "\",\"" << flt.category << "\"\n";
        }
    }
}