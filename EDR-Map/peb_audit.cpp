#include "peb_audit.h"
#include "types.h"
#include "output.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace NativeLdr {
    struct UNICODE_STRING_T {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    };

    struct PEB_LDR_DATA_FULL {
        ULONG Length;
        BOOLEAN Initialized;
        HANDLE SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    };

    struct PEB_FULL {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        BOOLEAN BitField;
        HANDLE Mutant;
        PVOID ImageBaseAddress;
        PEB_LDR_DATA_FULL* Ldr;
    };

    struct LDR_DATA_TABLE_ENTRY_FULL {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING_T FullDllName;
        UNICODE_STRING_T BaseDllName;
    };
}

static bool VerifyEmbeddedSignature(const std::wstring& filePath, std::wstring& signerOut) {
    signerOut = L"Unsigned / Catalog-Signed";

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
        signerOut = L"Valid Embedded Signature";

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
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

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
    g_results.pebScanExecuted = true;

    if (!g_config.outputJson && !g_config.outputCsv) {
        if (!g_config.runSilent) GetOutStream() << "\n\n";
        GetOutStream() << "----- Scanning In-Memory Modules (PEB Loader Walking) -----\n\n";
    }

    NativeLdr::PEB_FULL* peb = NULL;
#if defined(_WIN64)
    peb = reinterpret_cast<NativeLdr::PEB_FULL*>(__readgsqword(0x60));
#else
    peb = reinterpret_cast<NativeLdr::PEB_FULL*>(__readfsdword(0x30));
#endif

    if (!peb || !peb->Ldr) {
        if (!g_config.outputJson && !g_config.outputCsv) {
            GetOutStream() << "[-] Failed to resolve PEB or LDR table.\n";
        }
        return;
    }

    WCHAR winDirBuf[MAX_PATH] = { 0 };
    GetWindowsDirectoryW(winDirBuf, MAX_PATH);
    std::wstring winDir = winDirBuf;

    PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY current = head->Flink;

    if (current != head) {
        current = current->Flink;
    }

    int flaggedModules = 0;

    while (current != head && current != NULL) {
        auto entry = CONTAINING_RECORD(current, NativeLdr::LDR_DATA_TABLE_ENTRY_FULL, InLoadOrderLinks);

        if (entry->DllBase != NULL && entry->FullDllName.Buffer != NULL && entry->BaseDllName.Buffer != NULL) {
            std::wstring fullPath(entry->FullDllName.Buffer, entry->FullDllName.Length / sizeof(WCHAR));
            std::wstring baseName(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR));

            bool isNonSystem = (_wcsnicmp(fullPath.c_str(), winDir.c_str(), winDir.length()) != 0);
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

            bool shouldAlert = isSecurity || isNonSystem;
            if (shouldAlert) {
                flaggedModules++;
            }

            if (!g_config.outputJson && !g_config.outputCsv) {
                if (!g_config.runSilent || shouldAlert) {
                    GetOutStream() << (shouldAlert ? "[*] FLAGGED MODULE: " : "[-] MODULE: ")
                        << WStringToString(baseName) << " (0x" << std::hex << finding.baseAddress << std::dec << ")\n"
                        << "    Path     : " << WStringToString(fullPath) << "\n"
                        << "    Signer   : " << WStringToString(signer) << "\n"
                        << "    Category : " << (isSecurity ? "Known Security Vendor / EDR" : (isNonSystem ? "Non-Windows Directory" : "Standard Windows Binary")) << "\n";
                }
            }
        }

        current = current->Flink;
    }

    if (!g_config.outputJson && !g_config.outputCsv) {
        GetOutStream() << "\n[!] Completed PEB module audit: " << g_results.loadedModules.size()
            << " loaded DLLs scanned (" << flaggedModules << " non-Windows or security vendor modules).\n";
    }
}