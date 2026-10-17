#include "etw.h"
#include "types.h"
#include "output.h"
#include <evntrace.h>
#include <algorithm>

static bool IsFlaggedEtwSession(const std::wstring& sessionName) {
    std::wstring lower = sessionName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    static const std::vector<std::wstring> keywords = {
        L"defender", L"sense", L"sysmon", L"diaglog", L"diagtrack",
        L"wfp-diagnostics", L"sectelem", L"security-auditing", L"crowdstrike",
        L"sentinel", L"cylance", L"carbonblack", L"cbfilter", L"tanium",
        L"cortex", L"cyvera", L"fireeye", L"xagt", L"elastic", L"symantec",
        L"symefa", L"mcafee", L"mfe", L"sophos", L"trendmicro", L"kaspersky",
        L"bitdefender", L"qualys", L"splunk"
    };

    for (const auto& kw : keywords) {
        if (lower.find(kw) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

void EnumerateETWSessions() {
    g_results.etwScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Enumerating Active ETW Trace Sessions -----\n\n";
    }

    const ULONG MAX_SESSIONS = 129;
    PEVENT_TRACE_PROPERTIES sessionPropertiesArray[MAX_SESSIONS] = { 0 };
    ULONG sessionCount = 0;

    for (ULONG i = 0; i < MAX_SESSIONS; i++) {
        size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (2 * MAX_PATH * sizeof(WCHAR));
        sessionPropertiesArray[i] = (PEVENT_TRACE_PROPERTIES)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (sessionPropertiesArray[i] == NULL) {
            if (!g_config.outputJson && !g_config.outputCsv) GetOutStream() << "[-] Can't allocate memory\n";
            for (ULONG j = 0; j < i; j++) {
                VirtualFree(sessionPropertiesArray[j], 0, MEM_RELEASE);
            }
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

            if (IsFlaggedEtwSession(nameStr)) {
                g_results.flaggedEtwSessions.push_back(nameStr);
                if (!g_config.outputJson && !g_config.outputCsv) {
                    GetOutStream() << "[*] FLAGGED: " << WStringToString(nameStr) << "\n";
                }
            }
        }

        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "\n[!] Flagged " << g_results.flaggedEtwSessions.size() << " Security / Telemetry loggers\n";
        }
    }

    for (ULONG i = 0; i < MAX_SESSIONS; i++) {
        if (sessionPropertiesArray[i] != NULL) {
            VirtualFree(sessionPropertiesArray[i], 0, MEM_RELEASE);
        }
    }
}