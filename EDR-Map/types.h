#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct HookFinding {
    std::string moduleName;
    std::string functionName;
};

struct Config {
    bool runSilent = false;
    bool runHooks = true;
    bool runEtw = true;
    bool outputJson = false;
    bool outputCsv = false;
    std::string outputFile = "";
    std::vector<std::string> targetModules = { "ntdll.dll" };
};

struct ScanResults {
    std::vector<HookFinding> hookedFunctions;
    std::vector<std::wstring> flaggedEtwSessions;
    bool hookScanExecuted = false;
    bool etwScanExecuted = false;
};

extern Config g_config;
extern ScanResults g_results;