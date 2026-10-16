#include "minifilters.h"
#include "types.h"
#include "output.h"

#include <windows.h>
#include <fltuser.h>
#include <algorithm>

#pragma comment(lib, "fltlib.lib")

#ifndef FLTFL_AGGREGATE_INFO_IS_MINIFILTER
#define FLTFL_AGGREGATE_INFO_IS_MINIFILTER 0x00000001
#endif

static std::string ClassifyAltitude(const std::wstring& altitudeStr) {
    if (altitudeStr.empty()) return "Unknown";
    try {
        double alt = std::stod(altitudeStr);
        if (alt >= 320000.0 && alt <= 329999.0) return "FSFilter Anti-Virus";
        if (alt >= 360000.0 && alt <= 389999.0) return "FSFilter Activity Monitor";
        if (alt >= 260000.0 && alt <= 269999.0) return "FSFilter Encryption / DLP";
        if (alt >= 140000.0 && alt <= 149999.0) return "FSFilter System Recovery";
        if (alt >= 40000.0 && alt <= 49999.0)   return "FSFilter Compression";
    }
    catch (...) {
        return "Unknown";
    }
    return "Standard Minifilter";
}

static bool IsSecurityVendorFilter(const std::wstring& name, const std::string& category) {
    if (category == "FSFilter Anti-Virus" || category == "FSFilter Activity Monitor") {
        return true;
    }

    std::wstring lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    static const std::vector<std::wstring> knownSignatures = {
        L"wdfilter", L"edrsensor", L"csagent", L"sentinel", L"cylance",
        L"cbk7", L"cbflt", L"sysmon", L"tanium", L"cortex", L"mfe",
        L"sophos", L"tmfilter", L"klif", L"bdservicehost", L"atc"
    };

    for (const auto& sig : knownSignatures) {
        if (lowerName.find(sig) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

void EnumerateMinifilters() {
    g_results.minifilterScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Enumerating Filesystem Minifilter Drivers -----\n\n";
    }

    HANDLE filterFindHandle = INVALID_HANDLE_VALUE;
    BYTE buffer[2048] = { 0 };
    DWORD bytesReturned = 0;

    HRESULT hr = FilterFindFirst(
        FilterAggregateStandardInformation,
        buffer,
        sizeof(buffer),
        &bytesReturned,
        &filterFindHandle
    );

    if (FAILED(hr)) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] FilterFindFirst failed (HRESULT: 0x" << std::hex << hr << std::dec << ")\n";
            GetOutStream() << "[*] Note: Administrator privileges are required to inspect filter drivers.\n";
        }
        return;
    }

    int securityFilterCount = 0;

    do {
        PFILTER_AGGREGATE_STANDARD_INFORMATION stdInfo = (PFILTER_AGGREGATE_STANDARD_INFORMATION)buffer;

        if (stdInfo->Flags & FLTFL_AGGREGATE_INFO_IS_MINIFILTER) {
            LPCWSTR namePtr = (LPCWSTR)((PBYTE)stdInfo + stdInfo->Type.MiniFilter.FilterNameBufferOffset);
            std::wstring filterName(namePtr, stdInfo->Type.MiniFilter.FilterNameLength / sizeof(WCHAR));

            LPCWSTR altPtr = (LPCWSTR)((PBYTE)stdInfo + stdInfo->Type.MiniFilter.FilterAltitudeBufferOffset);
            std::wstring altitude(altPtr, stdInfo->Type.MiniFilter.FilterAltitudeLength / sizeof(WCHAR));

            ULONG frameId = stdInfo->Type.MiniFilter.FrameID;
            ULONG instances = stdInfo->Type.MiniFilter.NumberOfInstances;

            std::string category = ClassifyAltitude(altitude);
            bool isSecurity = IsSecurityVendorFilter(filterName, category);

            MinifilterFinding finding = {
                filterName,
                altitude,
                frameId,
                instances,
                category,
                isSecurity
            };

            g_results.minifilters.push_back(finding);

            if (isSecurity) {
                securityFilterCount++;
            }

            if (!g_config.outputJson && !g_config.outputCsv) {
                if (!g_config.runSilent || isSecurity) {
                    GetOutStream() << (isSecurity ? "[*] FLAGGED: " : "[-] ")
                        << WStringToString(filterName)
                        << " | Altitude: " << WStringToString(altitude)
                        << " | Class: " << category
                        << " | Instances: " << instances << "\n";
                }
            }
        }

        hr = FilterFindNext(filterFindHandle, FilterAggregateStandardInformation, buffer, sizeof(buffer), &bytesReturned);
    } while (SUCCEEDED(hr));

    FilterFindClose(filterFindHandle);

    if (!g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "\n[!] Identified " << securityFilterCount << " security/telemetry minifilters ("
            << g_results.minifilters.size() << " total active on system)\n";
    }
}