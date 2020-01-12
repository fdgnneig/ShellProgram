#pragma once
#include <Windows.h>

struct StubConf
{
	DWORD oep;
	DWORD text_rva;
	DWORD text_size;
	DWORD text_key;
};