#pragma once
#include <windows.h>
#include <string>
#include <vector>

struct HookFinding {
    std::string moduleName;
    std::string functionName;
    std::string diskBytesHex;
    std::string memoryBytesHex;
    ULONG_PTR targetAddress = 0;
    std::string targetModule;
};

struct MinifilterFinding {
    std::wstring name;
    std::wstring altitude;
    ULONG frameId;
    ULONG numInstances;
    std::string category;
    bool isSecurityTelemetry;
};

struct AmsiProviderFinding {
    std::wstring guid;
    std::wstring dllPath;
    std::wstring friendlyName;
    bool isSecurityVendor;
};

struct HwBreakpointFinding {
    int registerIndex;          // 0, 1, 2, or 3
    ULONG_PTR address;
    std::string condition;      // Execute, Write, Read/Write
    std::string symbolInfo;     // Resolved DLL + offset
    bool active;
};

struct Config {
    bool runSilent = false;
    bool runHooks = true;
    bool runEtw = true;
    bool runMinifilters = true;
    bool runAmsi = true;
    bool runHwbp = true;
    bool outputJson = false;
    bool outputCsv = false;
    std::string outputFile = "";
    std::vector<std::string> targetModules = { "ntdll.dll" };
};

struct ScanResults {
    std::vector<HookFinding> hookedFunctions;
    std::vector<std::wstring> flaggedEtwSessions;
    std::vector<MinifilterFinding> minifilters;
    std::vector<AmsiProviderFinding> amsiProviders;
    std::vector<HwBreakpointFinding> hwBreakpoints;
    bool hookScanExecuted = false;
    bool etwScanExecuted = false;
    bool minifilterScanExecuted = false;
    bool amsiScanExecuted = false;
    bool hwbpScanExecuted = false;
};

extern Config g_config;
extern ScanResults g_results;