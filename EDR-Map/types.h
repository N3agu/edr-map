#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct Config {
    bool runSilent = false;
    bool runHooks = true;
    bool runEtw = true;
    bool outputJson = false;
    bool outputCsv = false;
    std::string outputFile = "";
};

struct ScanResults {
    std::vector<std::string> hookedFunctions;
    std::vector<std::wstring> flaggedEtwSessions;
    bool hookScanExecuted = false;
    bool etwScanExecuted = false;
};

extern Config g_config;
extern ScanResults g_results;