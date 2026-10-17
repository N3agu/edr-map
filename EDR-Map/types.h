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
    int registerIndex;
    ULONG_PTR address;
    std::string condition;
    std::string symbolInfo;
    bool active;
};

struct ExecMemoryFinding {
    ULONG_PTR baseAddress;
    SIZE_T regionSize;
    std::string protection;
    std::string stateType;
    std::string mappedInfo;
};

struct IatHookFinding {
    std::string sourceModule;
    std::string importedDll;
    std::string functionName;
    ULONG_PTR currentAddress;
    std::string destinationModule;
};

struct LoadedModuleFinding {
    std::wstring moduleName;
    std::wstring fullPath;
    ULONG_PTR baseAddress;
    ULONG sizeOfImage;
    bool isNonSystemPath;
    bool isKnownSecurityVendor;
    bool isSigned;
    std::wstring signatureSigner;
};

struct Config {
    bool runSilent = false;
    bool runHooks = true;
    bool runEtw = true;
    bool runMinifilters = true;
    bool runAmsi = true;
    bool runHwbp = true;
    bool runMemoryScan = true;
    bool runIatScan = true;
    bool runPebScan = true;
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
    std::vector<ExecMemoryFinding> execMemoryRegions;
    std::vector<IatHookFinding> iatHooks;
    std::vector<LoadedModuleFinding> loadedModules;
    bool hookScanExecuted = false;
    bool etwScanExecuted = false;
    bool minifilterScanExecuted = false;
    bool amsiScanExecuted = false;
    bool hwbpScanExecuted = false;
    bool memoryScanExecuted = false;
    bool iatScanExecuted = false;
    bool pebScanExecuted = false;
};

extern Config g_config;
extern ScanResults g_results;