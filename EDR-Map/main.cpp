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
    g_config.runPebScan = false;
}

int main(int argc, char* argv[]) {
    bool customEngineSelection = false;

    auto EnableSpecificEngine = [&](bool& engineFlag) {
        if (!customEngineSelection) {
            DisableAllEngines();
            customEngineSelection = true;
        }
        engineFlag = true;
        };

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintBanner();
            PrintHelp();
            return 0;
        }
        else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
            g_config.runSilent = true;
        }
        else if (strcmp(argv[i], "--hooks") == 0) {
            EnableSpecificEngine(g_config.runHooks);
        }
        else if (strcmp(argv[i], "--iat") == 0) {
            EnableSpecificEngine(g_config.runIatScan);
        }
        else if (strcmp(argv[i], "--mem") == 0) {
            EnableSpecificEngine(g_config.runMemoryScan);
        }
        else if (strcmp(argv[i], "--peb") == 0) {
            EnableSpecificEngine(g_config.runPebScan);
        }
        else if (strcmp(argv[i], "--etw") == 0) {
            EnableSpecificEngine(g_config.runEtw);
        }
        else if (strcmp(argv[i], "--minifilters") == 0) {
            EnableSpecificEngine(g_config.runMinifilters);
        }
        else if (strcmp(argv[i], "--amsi") == 0) {
            EnableSpecificEngine(g_config.runAmsi);
        }
        else if (strcmp(argv[i], "--hwbp") == 0) {
            EnableSpecificEngine(g_config.runHwbp);
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

    if (g_config.runPebScan) {
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