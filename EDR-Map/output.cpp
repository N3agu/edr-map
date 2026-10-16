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
    GetOutStream() << "\n\nA lightweight scanner that detects AV/EDR userland hooks and lists active ETW telemetry sessions.\n\n"
        << "Usage: EDR_Map.exe [OPTIONS]\n\n"
        << "Options:\n"
        << "  -h, --help               Show this help message and exit.\n"
        << "  -s, --silent             Disable verbose output (shows debug info).\n"
        << "  --etwonly                Skip userland hook scanning; ONLY enumerate ETW trace sessions.\n"
        << "  --hooksonly              Skip ETW enumeration; ONLY scan for userland API hooks.\n"
        << "  --json                   Output results in JSON format.\n"
        << "  --csv                    Output results in CSV format.\n"
        << "  -o, --output <file>      Write output directly to specified file.\n\n"
        << "Examples:\n"
        << "  EDR_Map.exe                      # Run both modules with full debug output\n"
        << "  EDR_Map.exe -s                   # Run both modules silently (alerts only)\n"
        << "  EDR_Map.exe --etwonly            # Run only ETW\n"
        << "  EDR_Map.exe --hooksonly -s       # Run silently only Hooks\n"
        << "  EDR_Map.exe --json               # Output structured JSON\n"
        << "  EDR_Map.exe --csv                # Output structured CSV\n"
        << "  EDR_Map.exe -o results.txt       # Save output to file\n"
        << "  EDR_Map.exe --json -o scan.json  # Save JSON directly to file\n";
}

void PrintJsonOutput() {
    std::ostream& out = GetOutStream();
    out << "{\n";
    if (g_results.hookScanExecuted) {
        out << "  \"hooks\": [\n";
        for (size_t i = 0; i < g_results.hookedFunctions.size(); ++i) {
            out << "    \"" << EscapeJsonString(g_results.hookedFunctions[i]) << "\"";
            if (i + 1 < g_results.hookedFunctions.size()) out << ",";
            out << "\n";
        }
        out << "  ]";
        if (g_results.etwScanExecuted) out << ",";
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
        out << "  ]\n";
    }
    out << "}\n";
}

void PrintCsvOutput() {
    std::ostream& out = GetOutStream();
    out << "type,name\n";
    if (g_results.hookScanExecuted) {
        for (const auto& func : g_results.hookedFunctions) {
            out << "hook,\"" << func << "\"\n";
        }
    }
    if (g_results.etwScanExecuted) {
        for (const auto& session : g_results.flaggedEtwSessions) {
            out << "etw,\"" << WStringToString(session) << "\"\n";
        }
    }
}