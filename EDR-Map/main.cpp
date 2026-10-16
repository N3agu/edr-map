#include "types.h"
#include "output.h"
#include "hooks.h"
#include "etw.h"
#include <iostream>

Config g_config;
ScanResults g_results;

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
            g_config.runHooks = false;
        }
        else if (strcmp(argv[i], "--hooksonly") == 0) {
            g_config.runEtw = false;
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

    if (!g_config.runHooks && !g_config.runEtw) {
        PrintBanner();
        std::cout << "\n\n[-] Error: You cannot use --etwonly and --hooksonly at the same time.\n";
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

    if (g_config.runEtw) {
        EnumerateETWSessions();
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