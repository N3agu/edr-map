#include "etw.h"
#include "types.h"
#include "output.h"
#include <evntrace.h>

void EnumerateETWSessions() {
    g_results.etwScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent || g_config.runHooks) GetOutStream() << "\n\n";
        GetOutStream() << "----- Enumerating Active ETW Trace Sessions -----\n\n";
    }

    const ULONG MAX_SESSIONS = 129;
    PEVENT_TRACE_PROPERTIES sessionPropertiesArray[MAX_SESSIONS];
    ULONG sessionCount = 0;

    for (int i = 0; i < MAX_SESSIONS; i++) {
        size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (2 * MAX_PATH * sizeof(WCHAR));
        sessionPropertiesArray[i] = (PEVENT_TRACE_PROPERTIES)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (sessionPropertiesArray[i] == NULL) {
            if (!g_config.outputJson && !g_config.outputCsv) GetOutStream() << "[-] Can't allocate memory\n";
            return;
        }

        sessionPropertiesArray[i]->Wnode.BufferSize = (ULONG)bufferSize;
        sessionPropertiesArray[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        sessionPropertiesArray[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(WCHAR));
    }

    ULONG status = QueryAllTracesW(sessionPropertiesArray, MAX_SESSIONS, &sessionCount);

    if (status != ERROR_SUCCESS) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] QueryAllTracesW failed (" << status << ")\n";
        }
    }
    else {
        if (!g_config.runSilent && !g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[+] Found " << sessionCount << " active ETW sessions\n";
            GetOutStream() << "\n[!] Scanning for active trace sessions...\n";
        }

        for (ULONG i = 0; i < sessionCount; i++) {
            PWCHAR sessionName = (PWCHAR)((char*)sessionPropertiesArray[i] + sessionPropertiesArray[i]->LoggerNameOffset);
            std::wstring nameStr(sessionName);

            if (nameStr.find(L"Defender") != std::wstring::npos ||
                nameStr.find(L"Sense") != std::wstring::npos ||
                nameStr.find(L"Sysmon") != std::wstring::npos ||
                nameStr.find(L"DiagLog") != std::wstring::npos ||
                nameStr.find(L"Diagtrack") != std::wstring::npos ||
                nameStr.find(L"WFP-Diagnostics") != std::wstring::npos ||
                nameStr.find(L"SecTelem") != std::wstring::npos ||
                nameStr.find(L"Security-Auditing") != std::wstring::npos ||
                nameStr.find(L"CrowdStrike") != std::wstring::npos ||
                nameStr.find(L"Sentinel") != std::wstring::npos ||
                nameStr.find(L"Cylance") != std::wstring::npos ||
                nameStr.find(L"CarbonBlack") != std::wstring::npos ||
                nameStr.find(L"cb") != std::wstring::npos ||
                nameStr.find(L"Tanium") != std::wstring::npos ||
                nameStr.find(L"Cortex") != std::wstring::npos ||
                nameStr.find(L"Cyvera") != std::wstring::npos ||
                nameStr.find(L"FireEye") != std::wstring::npos ||
                nameStr.find(L"xagt") != std::wstring::npos ||
                nameStr.find(L"Elastic") != std::wstring::npos ||
                nameStr.find(L"Symantec") != std::wstring::npos ||
                nameStr.find(L"SymEFA") != std::wstring::npos ||
                nameStr.find(L"McAfee") != std::wstring::npos ||
                nameStr.find(L"mfe") != std::wstring::npos ||
                nameStr.find(L"Sophos") != std::wstring::npos ||
                nameStr.find(L"TrendMicro") != std::wstring::npos ||
                nameStr.find(L"Kaspersky") != std::wstring::npos ||
                nameStr.find(L"Bitdefender") != std::wstring::npos ||
                nameStr.find(L"Qualys") != std::wstring::npos ||
                nameStr.find(L"Splunk") != std::wstring::npos) {
                g_results.flaggedEtwSessions.push_back(nameStr);
                if (!g_config.outputJson && !g_config.outputCsv) {
                    GetOutStream() << "[*] FLAGGED: " << WStringToString(nameStr) << "\n";
                }
            }
        }

        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "\n[!] Flagged " << g_results.flaggedEtwSessions.size() << " Security / Telemetry loggers";
        }
    }

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessionPropertiesArray[i] != NULL) {
            VirtualFree(sessionPropertiesArray[i], 0, MEM_RELEASE);
        }
    }
}