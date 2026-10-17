#include "peb_audit.h"
#include "types.h"
#include "output.h"

#include <windows.h>
#include <winternl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

typedef struct _LDR_DATA_TABLE_ENTRY_EXT {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_EXT, * PLDR_DATA_TABLE_ENTRY_EXT;

static bool VerifyEmbeddedSignature(const std::wstring& filePath, std::wstring& signerOut) {
    signerOut = L"Unsigned / Invalid";

    WINTRUST_FILE_INFO fileData = { 0 };
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = filePath.c_str();

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileData;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(NULL, &actionGuid, &trustData);
    bool isValid = (status == ERROR_SUCCESS);

    if (isValid) {
        signerOut = L"Valid Signature";

        CRYPT_PROVIDER_DATA const* provData = WTHelperProvDataFromStateData(trustData.hWVTStateData);
        if (provData) {
            CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(const_cast<CRYPT_PROVIDER_DATA*>(provData), 0, FALSE, 0);
            if (sgnr && sgnr->pasCertChain && sgnr->csCertChain > 0) {
                PCCERT_CONTEXT cert = sgnr->pasCertChain[0].pCert;
                WCHAR subjectName[256] = { 0 };
                if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subjectName, ARRAYSIZE(subjectName))) {
                    signerOut = subjectName;
                }
            }
        }
    }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &trustData);

    return isValid;
}

static bool CheckIfSecurityVendorModule(const std::wstring& name, const std::wstring& path) {
    std::wstring lower = name + L" " + path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    static const std::vector<std::wstring> vendorKeywords = {
        L"csagent", L"crowdstrike", L"umppc", L"sentinel", L"inprocessclient",
        L"atcuf", L"bdservice", L"cylance", L"symantec", L"broadcom",
        L"sophos", L"mfe", L"mcafee", L"kaspersky", L"cortex", L"cyvera",
        L"fireeye", L"xagt", L"elastic", L"tanium", L"carbonblack", L"cbk7"
    };

    for (const auto& kw : vendorKeywords) {
        if (lower.find(kw) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

void EnumeratePebModules() {
    g_results.moduleScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Scanning In-Memory Modules (PEB Loader Walking) -----\n\n";
    }

    PPEB peb = NULL;
#if defined(_WIN64)
    peb = (PPEB)__readgsqword(0x60);
#else
    peb = (PPEB)__readfsdword(0x30);
#endif

    if (!peb || !peb->Ldr) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] Failed to resolve PEB or LDR table.\n";
        }
        return;
    }

    char sysDirA[MAX_PATH] = { 0 };
    GetSystemDirectoryA(sysDirA, MAX_PATH);
    std::string sysDirStr = sysDirA;
    std::wstring sysDir(sysDirStr.begin(), sysDirStr.end());

    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    if (current != head) {
        current = current->Flink;
    }

    int flaggedModules = 0;

    while (current != head && current != NULL) {
        PLDR_DATA_TABLE_ENTRY_EXT entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY_EXT, InMemoryOrderLinks);

        if (entry->DllBase != NULL && entry->FullDllName.Buffer != NULL && entry->BaseDllName.Buffer != NULL) {
            std::wstring fullPath(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
            std::wstring baseName(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR));

            bool isNonSystem = (_wcsnicmp(fullPath.c_str(), sysDir.c_str(), sysDir.length()) != 0);
            bool isSecurity = CheckIfSecurityVendorModule(baseName, fullPath);

            std::wstring signer;
            bool isSigned = VerifyEmbeddedSignature(fullPath, signer);

            LoadedModuleFinding finding = {
                baseName,
                fullPath,
                reinterpret_cast<ULONG_PTR>(entry->DllBase),
                entry->SizeOfImage,
                isNonSystem,
                isSecurity,
                isSigned,
                signer
            };

            g_results.loadedModules.push_back(finding);

            bool shouldAlert = isSecurity || isNonSystem || !isSigned;
            if (shouldAlert) {
                flaggedModules++;
            }

            if (!g_config.outputJson && !g_config.outputCsv) {
                if (!g_config.runSilent || shouldAlert) {
                    GetOutStream() << (shouldAlert ? "[*] FLAGGED MODULE: " : "[-] MODULE: ")
                        << WStringToString(baseName) << " (0x" << std::hex << finding.baseAddress << std::dec << ")\n"
                        << "    Path     : " << WStringToString(fullPath) << "\n"
                        << "    Signer   : " << WStringToString(signer) << "\n"
                        << "    Category : " << (isSecurity ? "Known Security Vendor / EDR" : (isNonSystem ? "Non-System Directory" : "Standard System Binary")) << "\n";
                }
            }
        }

        current = current->Flink;
    }

    if (!g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "\n[!] Completed module audit: " << g_results.loadedModules.size()
            << " loaded DLLs scanned (" << flaggedModules << " flagged as security/external/unsigned).\n";
    }
}