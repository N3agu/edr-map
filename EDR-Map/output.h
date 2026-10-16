#pragma once
#include <iostream>
#include <string>

std::ostream& GetOutStream();
bool InitializeOutputStream();
void CloseOutputStream();

std::string WStringToString(const std::wstring& wstr);
std::string EscapeJsonString(const std::string& input);

void PrintBanner();
void PrintHelp();
void PrintJsonOutput();
void PrintCsvOutput();