<div align="center">
  <h1>EDR Map</h1>
  <img src="https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/logo.png" width="256">
  
  <p><b>An educational Proof of Concept demonstrating how to dynamically detect EDR userland hooks, enumerate active telemetry sensors, and audit process integrity.</b></p>
</div>

## Overview
**EDR Map** is a modular scanner that detects AV/EDR userland inline and IAT hooks, attributes hook destinations to their owning EDR DLLs, inspects virtual memory and loaded PEB modules, checks for hookless hardware breakpoints, and enumerates active ETW sessions, AMSI providers, and kernel minifilter drivers.

<div align="center">
  <img src="https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/hooks.png" alt="EDR-Map Showcase">
</div>

## Features

- **Dynamic Hook Detection & Hex Diffing:** Maps loaded DLLs in process memory against pristine, unhooked copies read directly from disk, displaying a side-by-side 16-byte hex dump of modified prologues.
- **Hook Destination Attribution:** Decodes relative and indirect jump trampolines (`E9`, `EB`, `FF 25`, 64-bit register jumps, and two-stage trampolines) to resolve the exact EDR module and offset where the hook redirects execution.
- **Multi-Module & Targeted Scanning:** Checks high-value APIs in `ntdll.dll` (`Nt*`, `Zw*`, `Etw*`, `Ldr*`, `Rtl*`, `Ki*`, `RegNt*`) and supports scanning additional subsystem DLLs (`kernel32.dll`, `kernelbase.dll`, `ws2_32.dll`, `amsi.dll`, or custom lists).
- **Import Address Table (IAT) Auditing:** Verifies that resolved function pointers in module Import Address Tables point within the expected target DLL boundaries.
- **Unbacked Executable Memory Scanner:** Walks the process virtual address space via `VirtualQuery` to flag anomalous `MEM_PRIVATE` or `MEM_MAPPED` executable pages (trampoline allocations) and `RWX` image sections.
- **PEB Module Enumeration & Signature Verification:** Walks `PEB->Ldr->InLoadOrderModuleList` to detect injected third-party/EDR DLLs and validates embedded digital signatures via `WinVerifyTrust`.
- **Hardware Breakpoint Inspection:** Checks thread debug registers (`DR0`–`DR3` and `DR7`) via `GetThreadContext` to detect hookless EDR interception mechanisms.
- **Telemetry & Kernel Sensor Auditing:**
  * **ETW Enumeration:** Queries active trace sessions via `QueryAllTracesW` and flags known security logging services.
  * **Minifilter Enumeration:** Lists active filesystem minifilter drivers via `FltLib` and maps their altitudes to Windows `FSFilter` load order groups (`Anti-Virus`, `Activity Monitor`, `Encryption / DLP`).
  * **AMSI Provider Auditing:** Enumerates registered Anti-Malware Scan Interface (AMSI) providers in the registry and resolves their `InprocServer32` CLSIDs to backing vendor DLLs.
- **Combinable Engines & Structured Output:** Run all engines by default or combine specific scanners on the command line, with support for exporting results to **JSON**, **CSV**, or directly to a file (`-o`).

## How It Works

### 1. Inline Hook Scanning & Attribution
EDR-Map parses the PE headers of raw on-disk DLLs, calculates the exact offsets of exported functions, and uses `memcmp` to compare the first 16 bytes against the live module loaded in memory. When a discrepancy is found, it prints a hex diff, disassembles the jump opcode to calculate the target address, follows intermediate trampoline pages if present, and resolves the destination address to the owning EDR DLL using `GetModuleHandleExA`.

### 2. IAT, PEB & Virtual Memory Forensics
* **IAT Audit:** Parses the `IMAGE_DIRECTORY_ENTRY_IMPORT` table of the main executable and target modules, ensuring every imported function pointer resides within the base and size boundaries of its backing module while filtering out legitimate Windows API-Set and `System32` export forwarders.
* **Memory Audit:** Queries committed memory regions across the process address space and flags executable permissions (`RX`, `RWX`, `X`) on non-image memory (`MEM_PRIVATE` / `MEM_MAPPED`).
* **PEB Walk:** Traverses the internal loader doubly-linked list to surface non-Windows modules and verifies their Authenticode status and signer subject names using `WinVerifyTrust`.

### 3. Hardware Breakpoints (Hookless EDR Detection)
Some modern EDRs avoid patching `ntdll.dll` inline and instead place hardware breakpoints on syscall stubs coupled with a Vectored Exception Handler (VEH). EDR-Map inspects the current thread's `CONTEXT_DEBUG_REGISTERS` to check if `DR0`–`DR3` hold active addresses or if local/global enable bits are set in `DR7`.

### 4. Host Telemetry & Kernel Sensors (ETW, Minifilters, AMSI)
* **ETW:** Allocates `EVENT_TRACE_PROPERTIES` structures and calls `QueryAllTracesW` to match active kernel and userland trace sessions against security vendor signatures.
* **Minifilters:** Uses `FilterFindFirst` and `FilterFindNext` (`fltlib.lib`) to enumerate attached kernel filter drivers and classify their interception layer by numerical altitude.
* **AMSI:** Queries `HKLM\SOFTWARE\Microsoft\AMSI\Providers` and resolves each registered provider GUID under `HKCR\CLSID` to reveal the registered scanning engine DLL.

## AVs & EDRs
- Bitdefender Free, 18/04/2026 ([bitdefender_hooks.md](https://github.com/N3agu/EDR-Map/blob/main/AVs%20&%20EDRs/bitdefender_hooks.md))
- Windows Defender, 19/04/2026 ([wd_hooks.md](https://github.com/N3agu/EDR-Map/blob/main/AVs%20&%20EDRs/wd_hooks.md))
- Avast One Free, 19/04/2026 ([avastone_hooks.md](https://github.com/N3agu/EDR-Map/blob/main/AVs%20&%20EDRs/avastone_hooks.md))

## Screenshots

<details open>
  <summary><strong>Screenshot of a Full Scan</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/full.png)
</details>

<details>
  <summary><strong>Screenshot of EDR-Map with --etwonly</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/etw.png)
</details>

<details>
  <summary><strong>Screenshot of EDR-Map with --hooksonly</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/hooks.png)
</details>

<details>
  <summary><strong>Screenshot of Bitdefender Hooks</strong></summary>
  
  ![](https://raw.githubusercontent.com/N3agu/EDR-Map/refs/heads/main/Images/bitdefender.png)
</details>

## Usage
EDR-Map runs all scan engines by default, or you can pass specific engine flags in any combination.
```
Usage: EDR_Map.exe [SCAN FLAGS] [OPTIONS]

Scan Engines (Default: Runs ALL if none are specified; can be combined):
  --hooks                    Scan userland DLL exports for inline hooks.
  --iat                      Audit Import Address Tables (IAT) for pointer redirection.
  --mem                      Scan virtual memory for unbacked executable / RWX pages.
  --peb                      Walk PEB loader list to detect injected/non-system DLLs & check signatures.
  --etw                      Enumerate active ETW trace sessions.
  --minifilters              Enumerate filesystem minifilter drivers and altitudes (Admin).
  --amsi                     Enumerate registered AMSI providers in the registry.
  --hwbp                     Inspect thread debug registers (DR0-DR7) for hardware breakpoints.

Options:
  -h, --help                 Show this help message and exit.
  -s, --silent               Disable verbose output (alerts only).
  --modules <m1,m2,...>      Comma-separated list of DLLs for --hooks and --iat (default: ntdll.dll).
  --all-modules              Target high-value DLLs (ntdll, kernel32, kernelbase, ws2_32, amsi).
  --json                     Output results in JSON format.
  --csv                      Output results in CSV format.
  -o, --output <file>        Write output directly to specified file.
```
Examples:
```
  EDR_Map.exe                                      # Run all scan engines with full output
  EDR_Map.exe --hooks --iat --all-modules          # Scan only inline & IAT hooks across core DLLs
  EDR_Map.exe --peb --mem -s                       # Check only injected DLLs and unbacked memory silently
  EDR_Map.exe --etw --amsi --json -o report.json   # Export ETW and AMSI telemetry audit to JSON
```

## Changelog

### v2.0.0
- **Modular Architecture:** Refactored the codebase into dedicated header and source modules (`hooks`, `iat_audit`, `memory_audit`, `peb_audit`, `etw`, `minifilters`, `amsi_audit`, `hwbp`, and `output`).
- **Hook Attribution & Hex Diffing:** Added 16-byte disk vs. memory hex dumps and trampoline jump target decoding (`E9`, `EB`, `FF 25`, 64-bit register jumps, and multi-stage trampolines) to identify the exact EDR DLL owning each hook.
- **Multi-Module Scanning:** Added `--modules <list>` and `--all-modules` (`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`, `ws2_32.dll`, `amsi.dll`) with export forwarder filtering.
- **IAT Integrity Auditing (`--iat`):** Added Import Address Table verification to detect redirected function pointers.
- **Executable Memory Scanner (`--mem`):** Added virtual memory inspection via `VirtualQuery` to detect unbacked executable pages (`MEM_PRIVATE` / `MEM_MAPPED`) and `RWX` image sections.
- **PEB Module & Signature Audit (`--peb`):** Added PEB `InLoadOrderModuleList` walking to identify injected non-Windows DLLs and verify digital signatures via `WinVerifyTrust`.
- **Minifilter Driver Enumeration (`--minifilters`):** Added kernel filesystem minifilter enumeration and altitude classification via `FltLib`.
- **AMSI Provider Enumeration (`--amsi`):** Added registry auditing to list registered AMSI providers and resolve their `InprocServer32` DLL paths.
- **Hardware Breakpoint Detection (`--hwbp`):** Added thread debug register (`DR0`–`DR7`) inspection to detect hookless EDR monitoring.
- **Combinable CLI & Structured Output:** Replaced exclusive `--*only` flags with combinable engine flags and added `--json`, `--csv`, and `-o` / `--output <file>` export options.

### v1.0.0
- Initial release featuring `ntdll.dll` userland inline hook detection and active ETW trace session enumeration (`QueryAllTracesW`).

## Disclaimer
***This tool is strictly for educational purposes, security research, and authorized red team engagements. The author is not responsible for any misuse or damage caused by this software. Never deploy this tool in environments where you do not have explicit permission.***
