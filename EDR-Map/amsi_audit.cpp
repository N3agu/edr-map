#include "amsi_audit.h"
#include "types.h"
#include "output.h"
#include <algorithm>

static std::wstring QueryRegistryValueString(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName) {
    HKEY hKey = NULL;
    std::wstring result = L"";

    if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR buffer[MAX_PATH] = { 0 };
        DWORD dataSize = sizeof(buffer);
        DWORD type = 0;

        if (RegQueryValueExW(hKey, valueName.empty() ? NULL : valueName.c_str(), NULL, &type, (LPBYTE)buffer, &dataSize) == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ) {
                result = buffer;
            }
        }
        RegCloseKey(hKey);
    }

    return result;
}

static bool CheckIfSecurityVendorDll(const std::wstring& path) {
    std::wstring lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    static const std::vector<std::wstring> securityKeywords = {
        L"defender", L"mpengine", L"sophos", L"symantec", L"broadcom",
        L"kaspersky", L"bitdefender", L"cylance", L"sentinel", L"crowdstrike",
        L"csagent", L"eset", L"trendmicro", L"fireeye", L"mcafee"
    };

    for (const auto& kw : securityKeywords) {
        if (lower.find(kw) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

void EnumerateAmsiProviders() {
    g_results.amsiScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Enumerating Registered AMSI Providers -----\n\n";
    }

    HKEY hAmsiKey = NULL;
    const wchar_t* amsiProvidersKey = L"SOFTWARE\\Microsoft\\AMSI\\Providers";

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, amsiProvidersKey, 0, KEY_READ, &hAmsiKey) != ERROR_SUCCESS) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] Failed to open AMSI Providers registry key.\n";
        }
        return;
    }

    DWORD index = 0;
    WCHAR subKeyName[256];
    DWORD subKeyNameSize = ARRAYSIZE(subKeyName);

    int detectedCount = 0;

    while (RegEnumKeyExW(hAmsiKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        std::wstring providerGuid = subKeyName;

        std::wstring clsidPath = L"CLSID\\" + providerGuid + L"\\InprocServer32";
        std::wstring dllPath = QueryRegistryValueString(HKEY_CLASSES_ROOT, clsidPath, L"");

        if (dllPath.empty()) {
            clsidPath = L"SOFTWARE\\Classes\\CLSID\\" + providerGuid + L"\\InprocServer32";
            dllPath = QueryRegistryValueString(HKEY_LOCAL_MACHINE, clsidPath, L"");
        }

        std::wstring friendlyName = QueryRegistryValueString(HKEY_CLASSES_ROOT, L"CLSID\\" + providerGuid, L"");
        if (friendlyName.empty()) {
            friendlyName = L"Unknown AMSI Provider";
        }

        bool isSec = CheckIfSecurityVendorDll(dllPath) || CheckIfSecurityVendorDll(friendlyName);
        if (isSec) {
            detectedCount++;
        }

        AmsiProviderFinding finding = {
            providerGuid,
            dllPath.empty() ? L"(Unresolved / Missing InprocServer32)" : dllPath,
            friendlyName,
            isSec
        };

        g_results.amsiProviders.push_back(finding);

        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << (isSec ? "[*] FLAGGED PROVIDER: " : "[-] PROVIDER: ")
                << WStringToString(friendlyName) << "\n"
                << "    GUID : " << WStringToString(providerGuid) << "\n"
                << "    DLL  : " << WStringToString(finding.dllPath) << "\n";
        }

        index++;
        subKeyNameSize = ARRAYSIZE(subKeyName);
    }

    RegCloseKey(hAmsiKey);

    if (!g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "\n[!] Found " << g_results.amsiProviders.size()
            << " registered AMSI provider(s) (" << detectedCount << " security vendor matches)\n";
    }
}