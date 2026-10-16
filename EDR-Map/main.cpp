#include <windows.h>
#include <evntrace.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <fstream>

using std::cout;

const char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";

bool runSilent = false;
bool runHooks = true;
bool runEtw = true;
bool outputJson = false;
bool outputCsv = false;
std::string outputFile = "";
std::ofstream fileStream;

struct ScanResults {
	std::vector<std::string> hookedFunctions;
	std::vector<std::wstring> flaggedEtwSessions;
	bool hookScanExecuted = false;
	bool etwScanExecuted = false;
};

ScanResults g_results;

std::ostream& GetOutStream() {
	if (fileStream.is_open()) {
		return fileStream;
	}
	return cout;
}

std::string WStringToString(const std::wstring& wstr) {
	if (wstr.empty()) return "";
	int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string str(sizeNeeded, 0);
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], sizeNeeded, NULL, NULL);
	return str;
}

PVOID ReadFileInMemory(const char* filePath) {
	HANDLE fileHandle = CreateFileA(
		filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (fileHandle == INVALID_HANDLE_VALUE) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] Failed to open file (" << filePath << ")\n";
			GetOutStream() << "[-] Error: " << GetLastError() << "\n";
		}
		return NULL;
	}

	DWORD fileSize = GetFileSize(fileHandle, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] Failed to get file size\n";
		}
		CloseHandle(fileHandle);
		return NULL;
	}

	PVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!fileBuffer && !outputJson && !outputCsv) {
		GetOutStream() << "[-] Can't allocate memory\n";
	}

	DWORD bytesRead;
	if (!ReadFile(fileHandle, fileBuffer, fileSize, &bytesRead, NULL)) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] ReadFile failed\n";
			GetOutStream() << "[-] Error: " << GetLastError() << "\n";
		}
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		CloseHandle(fileHandle);
		return NULL;
	}

	if (bytesRead != fileSize && !outputJson && !outputCsv) {
		GetOutStream() << "[-] Failed to read file\n";
	}

	CloseHandle(fileHandle);

	if (!runSilent && !outputJson && !outputCsv) {
		GetOutStream() << "[+] Loaded " << filePath << " in memory at 0x" << fileBuffer << "\n";
	}

	return fileBuffer;
}

DWORD RvaToRawOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
		DWORD sectionSize = sectionHeader->Misc.VirtualSize;
		DWORD sectionAddress = sectionHeader->VirtualAddress;

		if (rva >= sectionAddress && rva < sectionAddress + sectionSize) {
			return rva - sectionAddress + sectionHeader->PointerToRawData;
		}
	}

	return 0;
}

void PrintBanner() {
	GetOutStream() << R"""( _____ ____   ____    __  __              
| ____|  _ \|  _ \  |  \/  | __ _ _ __  
|  _| | | | | |_) | | |\/| |/ _` | '_ \ 
| |___| |_| |  _ <  | |  | | (_| | |_) |
|_____|____/|_| \_\ |_|  |_|\__,_| .__/ 
                                 |_|    
        github.com/N3agu/EDR-Map)""";
}

void PrintHelp() {
	GetOutStream() << "\n\nA lightweight scanner that detects AV/EDR userland hooks and lists active ETW telemetry sessions.\n\n";

	GetOutStream() << "Usage: EDR_Map.exe [OPTIONS]\n\n";

	GetOutStream() << "Options:\n";
	GetOutStream() << "  -h, --help               Show this help message and exit.\n";
	GetOutStream() << "  -s, --silent             Disable verbose output (shows debug info).\n";
	GetOutStream() << "  --etwonly                Skip userland hook scanning; ONLY enumerate ETW trace sessions.\n";
	GetOutStream() << "  --hooksonly              Skip ETW enumeration; ONLY scan for userland API hooks.\n";
	GetOutStream() << "  --json                   Output results in JSON format.\n";
	GetOutStream() << "  --csv                    Output results in CSV format.\n";
	GetOutStream() << "  -o, --output <file>      Write output directly to specified file.\n\n";

	GetOutStream() << "Examples:\n";
	GetOutStream() << "  EDR_Map.exe                      # Run both modules with full debug output\n";
	GetOutStream() << "  EDR_Map.exe -s                   # Run both modules silently (alerts only)\n";
	GetOutStream() << "  EDR_Map.exe --etwonly            # Run only ETW\n";
	GetOutStream() << "  EDR_Map.exe --hooksonly -s       # Run silently only Hooks\n";
	GetOutStream() << "  EDR_Map.exe --json               # Output structured JSON\n";
	GetOutStream() << "  EDR_Map.exe --csv                # Output structured CSV\n";
	GetOutStream() << "  EDR_Map.exe -o results.txt       # Save output to file\n";
	GetOutStream() << "  EDR_Map.exe --json -o scan.json  # Save JSON directly to file\n";
}

void EnumerateHookedFunctions() {
	g_results.hookScanExecuted = true;

	if (!outputJson && !outputCsv) {
		if (!runSilent) {
			GetOutStream() << "\n\n";
		}
		GetOutStream() << "----- Enumerating Hooked Userland Functions -----\n\n";

		if (!runSilent) {
			GetOutStream() << "[!] Loading the clean NTDLL from Disk...\n";
		}
	}

	PVOID diskNtdllBuffer = ReadFileInMemory(ntdllPath);

	if (!diskNtdllBuffer) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] Failed to load " << ntdllPath << " from Disk\n";
		}
		return;
	}

	if (!runSilent && !outputJson && !outputCsv) {
		GetOutStream() << "\n[!] Parsing PE Headers to find Exports...\n";
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)diskNtdllBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] DOS Signature != 'MZ'\n";
		}
		VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
		return;
	}

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)diskNtdllBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] NT Signature != 'PE\\0\\0'\n";
		}
		VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
		return;
	}

	DWORD exportDirectoryRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportDirectoryRva) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] Can't find Export Directory\n";
		}
		VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
		return;
	}

	DWORD exportDirectoryOffset = RvaToRawOffset(ntHeaders, exportDirectoryRva);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)diskNtdllBuffer + exportDirectoryOffset);

	if (!runSilent && !outputJson && !outputCsv) {
		GetOutStream() << "[+] Export Directory found at RVA 0x" << std::hex << exportDirectoryRva << "\n";
		GetOutStream() << "[+] Found " << std::dec << exportDirectory->NumberOfNames << " Exported Functions\n";
		GetOutStream() << "\n[!] Getting handle to the NTDLL from Memory...\n";
	}

	HMODULE memoryNtdllBase = GetModuleHandleA("ntdll.dll");
	if (!memoryNtdllBase) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] Can't get handle to the NTDLL from Memory\n";
		}
		VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
		return;
	}

	if (!runSilent && !outputJson && !outputCsv) {
		GetOutStream() << "[+] Found Memory NTDLL base address at 0x" << memoryNtdllBase << "\n";
		GetOutStream() << "\n[!] Scanning for hooks in functions...\n";
	}

	PDWORD addressOfFunctions = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfFunctions));
	PDWORD addressOfNames = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNames));
	PWORD addressOfNameOrdinals = (PWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNameOrdinals));

	for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
		char* functionName = (char*)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, addressOfNames[i]));

		if (!strncmp(functionName, "Nt", 2) ||
			!strncmp(functionName, "Zw", 2) ||
			!strncmp(functionName, "Etw", 3) ||
			!strncmp(functionName, "Ldr", 3) ||
			!strncmp(functionName, "Rtl", 3) ||
			!strncmp(functionName, "Ki", 2) ||
			!strncmp(functionName, "RegNt", 5)) {
			DWORD functionRva = addressOfFunctions[addressOfNameOrdinals[i]];
			PVOID diskFunctionAddress = (PVOID)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, functionRva));
			PVOID memoryFunctionAddress = (PVOID)((ULONG_PTR)memoryNtdllBase + functionRva);

			if (memcmp(diskFunctionAddress, memoryFunctionAddress, 16) != 0) {
				g_results.hookedFunctions.push_back(functionName);
				if (!outputJson && !outputCsv) {
					GetOutStream() << "[*] HOOKED: " << functionName << "\n";
				}
			}
		}
	}

	if (!outputJson && !outputCsv) {
		if (g_results.hookedFunctions.empty()) {
			GetOutStream() << "\n[-] No hooks detected in the functions";
		}
		else {
			GetOutStream() << "\n[+] Found " << g_results.hookedFunctions.size() << " hooks";
		}
	}

	VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
}

void EnumerateETWSessions() {
	g_results.etwScanExecuted = true;

	if (!outputJson && !outputCsv) {
		if (!runSilent || runHooks) {
			GetOutStream() << "\n\n";
		}
		GetOutStream() << "----- Enumerating Active ETW Trace Sessions -----\n\n";
	}

	const ULONG MAX_SESSIONS = 129;
	PEVENT_TRACE_PROPERTIES sessionPropertiesArray[MAX_SESSIONS];
	ULONG sessionCount = 0;

	for (int i = 0; i < MAX_SESSIONS; i++) {
		size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (2 * MAX_PATH * sizeof(WCHAR));
		sessionPropertiesArray[i] = (PEVENT_TRACE_PROPERTIES)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (sessionPropertiesArray[i] == NULL) {
			if (!outputJson && !outputCsv) {
				GetOutStream() << "[-] Can't allocate memory\n";
			}
			return;
		}

		sessionPropertiesArray[i]->Wnode.BufferSize = (ULONG)bufferSize;
		sessionPropertiesArray[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		sessionPropertiesArray[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(WCHAR));
	}

	ULONG status = QueryAllTracesW(sessionPropertiesArray, MAX_SESSIONS, &sessionCount);

	if (status != ERROR_SUCCESS) {
		if (!outputJson && !outputCsv) {
			GetOutStream() << "[-] QueryAllTracesW failed (" << status << ")\n";
		}
	}
	else {
		if (!runSilent && !outputJson && !outputCsv) {
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
				nameStr.find(L"Splunk") != std::wstring::npos)
			{
				g_results.flaggedEtwSessions.push_back(nameStr);
				if (!outputJson && !outputCsv) {
					GetOutStream() << "[*] FLAGGED: " << WStringToString(nameStr) << "\n";
				}
			}
		}

		if (!outputJson && !outputCsv) {
			GetOutStream() << "\n[!] Flagged " << g_results.flaggedEtwSessions.size() << " Security / Telemetry loggers";
		}
	}

	for (int i = 0; i < MAX_SESSIONS; i++) {
		if (sessionPropertiesArray[i] != NULL) {
			VirtualFree(sessionPropertiesArray[i], 0, MEM_RELEASE);
		}
	}
}

std::string EscapeJsonString(const std::string& input) {
	std::ostringstream ss;
	for (char c : input) {
		if (c == '"') ss << "\\\"";
		else if (c == '\\') ss << "\\\\";
		else if (c == '\b') ss << "\\b";
		else if (c == '\f') ss << "\\f";
		else if (c == '\n') ss << "\\n";
		else if (c == '\r') ss << "\\r";
		else if (c == '\t') ss << "\\t";
		else ss << c;
	}
	return ss.str();
}

void PrintJsonOutput() {
	std::ostream& out = GetOutStream();
	out << "{\n";
	if (g_results.hookScanExecuted) {
		out << "  \"hooks\": [\n";
		for (size_t i = 0; i < g_results.hookedFunctions.size(); ++i) {
			out << "    \"" << EscapeJsonString(g_results.hookedFunctions[i]) << "\"";
			if (i + 1 < g_results.hookedFunctions.size()) out << ",";
			out << "\n";
		}
		out << "  ]";
		if (g_results.etwScanExecuted) out << ",";
		out << "\n";
	}

	if (g_results.etwScanExecuted) {
		out << "  \"etw_sessions\": [\n";
		for (size_t i = 0; i < g_results.flaggedEtwSessions.size(); ++i) {
			std::string session = WStringToString(g_results.flaggedEtwSessions[i]);
			out << "    \"" << EscapeJsonString(session) << "\"";
			if (i + 1 < g_results.flaggedEtwSessions.size()) out << ",";
			out << "\n";
		}
		out << "  ]\n";
	}
	out << "}\n";
}

void PrintCsvOutput() {
	std::ostream& out = GetOutStream();
	out << "type,name\n";
	if (g_results.hookScanExecuted) {
		for (const auto& func : g_results.hookedFunctions) {
			out << "hook,\"" << func << "\"\n";
		}
	}
	if (g_results.etwScanExecuted) {
		for (const auto& session : g_results.flaggedEtwSessions) {
			out << "etw,\"" << WStringToString(session) << "\"\n";
		}
	}
}

int main(int argc, char* argv[]) {
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			PrintBanner();
			PrintHelp();
			return 0;
		}
		else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
			runSilent = true;
		}
		else if (strcmp(argv[i], "--etwonly") == 0) {
			runHooks = false;
		}
		else if (strcmp(argv[i], "--hooksonly") == 0) {
			runEtw = false;
		}
		else if (strcmp(argv[i], "--json") == 0) {
			outputJson = true;
		}
		else if (strcmp(argv[i], "--csv") == 0) {
			outputCsv = true;
		}
		else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
			if (i + 1 < argc) {
				outputFile = argv[++i];
			}
			else {
				cout << "[-] Error: " << argv[i] << " requires a file path argument.\n";
				return -1;
			}
		}
		else {
			PrintBanner();
			cout << "\n\n[-] Unknown argument: " << argv[i] << "\n";
			cout << "[*] Use -h or --help to see available options.\n";
			return -1;
		}
	}

	if (!runHooks && !runEtw) {
		PrintBanner();
		cout << "\n\n[-] Error: You cannot use --etwonly and --hooksonly at the same time.\n";
		return -1;
	}

	if (outputJson && outputCsv) {
		cout << "[-] Error: You cannot use --json and --csv at the same time.\n";
		return -1;
	}

	if (!outputFile.empty()) {
		fileStream.open(outputFile, std::ios::out | std::ios::trunc);
		if (!fileStream.is_open()) {
			cout << "[-] Error: Failed to open output file: " << outputFile << "\n";
			return -1;
		}
	}

	if (!runSilent && !outputJson && !outputCsv) {
		PrintBanner();
	}

	if (runHooks) {
		EnumerateHookedFunctions();
	}

	if (runEtw) {
		EnumerateETWSessions();
	}

	if (outputJson) {
		PrintJsonOutput();
	}
	else if (outputCsv) {
		PrintCsvOutput();
	}

	if (fileStream.is_open()) {
		fileStream.close();
		if (!runSilent) {
			cout << "[+] Output successfully written to " << outputFile << "\n";
		}
	}

	return 0;
}