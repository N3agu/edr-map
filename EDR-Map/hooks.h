#pragma once
#include <windows.h>
#include <string>

void EnumerateHookedFunctions();
void ScanModule(const std::string& moduleName);