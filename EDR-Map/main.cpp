#include "types.h"
#include "output.h"
#include "hooks.h"
#include "etw.h"
#include "minifilters.h"
#include "amsi_audit.h"
#include "hwbp.h"
#include "memory_audit.h"
#include "iat_audit.h"
#include "peb_audit.h"
#include <iostream>
#include <sstream>

Config g_config;
ScanResults g_results;

static std::vector<std::string> ParseModuleList(const std::string& input) {
    std::vector<std::string> modules;
    std::stringstream ss(input);
    std::string token;
    while (std::getline(ss, token, ',')) {
        if (!token.empty()) {
            modules.push_back(token);
        }
    }
    return modules;
}

static void DisableAllEngines() {
    g_config.runHooks = false;
    g_config.runEtw = false;
    g_config.runMinifilters = false;
    g_config.runAmsi = false;
    g_config.runHwbp = false;
    g_config.runMemoryScan = false;
    g_config.runIatScan = false;
    g_config.runModuleScan = false;
}

int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintBanner();
            PrintHelp();
            return 0;
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
            g_config.runSilent = true;
        }
        else if (strcmp(argv[i], "--etwonly") == 0) {
            DisableAllEngines();
            g_config.runEtw = true;
        }
        else if (strcmp(argv[i], "--hooksonly") == 0) {
            DisableAllEngines();
            g_config.runHooks = true;
        }
        else if (strcmp(argv[i], "--minifiltersonly") == 0) {
            DisableAllEngines();
            g_config.runMinifilters = true;
        }
        else if (strcmp(argv[i], "--amsionly") == 0) {
            DisableAllEngines();
            g_config.runAmsi = true;
        }
        else if (strcmp(argv[i], "--hwbponly") == 0) {
            DisableAllEngines();
            g_config.runHwbp = true;
        }
        else if (strcmp(argv[i], "--memonly") == 0) {
            DisableAllEngines();
            g_config.runMemoryScan = true;
        }
        else if (strcmp(argv[i], "--iatonly") == 0) {
            DisableAllEngines();
            g_config.runIatScan = true;
        }
        else if (strcmp(argv[i], "--modulesonly") == 0) {
            DisableAllEngines();
            g_config.runModuleScan = true;
        }
        else if (strcmp(argv[i], "--all-modules") == 0) {
            g_config.targetModules = {
                "ntdll.dll",
                "kernel32.dll",
                "kernelbase.dll",
                "ws2_32.dll",
                "amsi.dll"
            };
        }
        else if (strcmp(argv[i], "--modules") == 0) {
            if (i + 1 < argc) {
                g_config.targetModules = ParseModuleList(argv[++i]);
            }
            else {
                std::cout << "[-] Error: --modules requires a comma-separated list of DLLs.\n";
                return -1;
            }
        }
        else if (strcmp(argv[i], "--json") == 0) {
            g_config.outputJson = true;
        }
        else if (strcmp(argv[i], "--csv") == 0) {
            g_config.outputCsv = true;
        }
        else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                g_config.outputFile = argv[++i];
            }
            else {
                std::cout << "[-] Error: " << argv[i] << " requires a file path argument.\n";
                return -1;
            }
        }
        else {
            PrintBanner();
            std::cout << "\n\n[-] Unknown argument: " << argv[i] << "\n"
                << "[*] Use -h or --help to see available options.\n";
            return -1;
        }
    }

    int activeEngines = (g_config.runHooks ? 1 : 0) + (g_config.runEtw ? 1 : 0) +
        (g_config.runMinifilters ? 1 : 0) + (g_config.runAmsi ? 1 : 0) +
        (g_config.runHwbp ? 1 : 0) + (g_config.runMemoryScan ? 1 : 0) +
        (g_config.runIatScan ? 1 : 0) + (g_config.runModuleScan ? 1 : 0);

    if (activeEngines == 0) {
        PrintBanner();
        std::cout << "\n\n[-] Error: Invalid configuration (no scan engines active).\n";
        return -1;
    }

    if (g_config.outputJson && g_config.outputCsv) {
        std::cout << "[-] Error: You cannot use --json and --csv at the same time.\n";
        return -1;
    }

    if (!InitializeOutputStream()) {
        std::cout << "[-] Error: Failed to open output file: " << g_config.outputFile << "\n";
        return -1;
    }

    if (!g_config.runSilent && !g_config.outputJson && !g_config.outputCsv) {
        PrintBanner();
    }

    if (g_config.runHooks) {
        EnumerateHookedFunctions();
    }

    if (g_config.runIatScan) {
        EnumerateIatHooks();
    }

    if (g_config.runMemoryScan) {
        EnumerateExecutableMemory();
    }

    if (g_config.runModuleScan) {
        EnumeratePebModules();
    }

    if (g_config.runEtw) {
        EnumerateETWSessions();
    }

    if (g_config.runMinifilters) {
        EnumerateMinifilters();
    }

    if (g_config.runAmsi) {
        EnumerateAmsiProviders();
    }

    if (g_config.runHwbp) {
        EnumerateHardwareBreakpoints();
    }

    if (g_config.outputJson) {
        PrintJsonOutput();
    }
    else if (g_config.outputCsv) {
        PrintCsvOutput();
    }

    CloseOutputStream();
    return 0;
}