#include <Windows.h>
#include <DbgEng.h>
#include <atlcomcli.h>

#pragma comment(lib, "dbgeng")

#ifdef _WIN64
#define KDEXT_64BIT
#endif

#include <WDBGEXTS.H>

WINDBG_EXTENSION_APIS ExtensionApis{ sizeof(WINDBG_EXTENSION_APIS) };

typedef struct {
	ULONG64 startAddress;
	ULONG64 endAddress;
	ULONG size;
	BYTE pattern;
	ULONG memoryProtection;
} CODE_CAVE;


STDAPI help(IDebugClient* client, PCSTR args);
STDAPI helpcave(IDebugClient* client, PCSTR args);

HRESULT __stdcall DebugExtensionInitialize(PULONG version, PULONG flags) {
	CComPtr<IDebugClient> client;
	auto hr = DebugCreate(__uuidof(IDebugClient), (void**)&client);
	if (FAILED(hr)) {
		return hr;
	}

	CComQIPtr<IDebugControl> control(client);
	if (!control) {
		return E_NOINTERFACE;
	}
#ifdef _WIN64
	hr = control->GetWindbgExtensionApis64(&ExtensionApis);
#else
	hr = control->GetWindbgExtensionApis32((PWINDBG_EXTENSION_APIS32)&ExtensionApis);
#endif
	if (FAILED(hr)) {
		return hr;
	}

	*version = DEBUG_EXTENSION_VERSION(1, 0);
	*flags = 0;

	help(client, "");

	return S_OK;
}

BOOL isExecutableMemory(IDebugDataSpaces2* dataSpaces, ULONG64 address, ULONG* pProtect, ULONG64* pRegionRemaining) {
	MEMORY_BASIC_INFORMATION64 mbi = { 0 };
	HRESULT hr = dataSpaces->QueryVirtual(address, &mbi);

	if (FAILED(hr)) {
		return FALSE;
	}

	if (pProtect) {
		*pProtect = mbi.Protect;
	}

	if (pRegionRemaining) {
		*pRegionRemaining = (mbi.BaseAddress + mbi.RegionSize) - address;
	}

	DWORD executableFlags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
	return (mbi.Protect & executableFlags) != 0;
}


static BOOL TryRecordCave(CODE_CAVE** ppCaves, ULONG* pCaveCount, ULONG* pCaveCapacity, ULONG minCaveSize,
	ULONG64 caveStart, ULONG64 caveEnd, BYTE pattern, ULONG protection) {
	ULONG size = (ULONG)(caveEnd - caveStart + 1);
	if (size < minCaveSize) {
		return FALSE;
	}

	if (*pCaveCount >= *pCaveCapacity) {
		ULONG newCapacity = (*pCaveCapacity > ULONG_MAX / 2) ? ULONG_MAX : *pCaveCapacity * 2;
		CODE_CAVE* newBuf = (CODE_CAVE*)realloc(*ppCaves, sizeof(CODE_CAVE) * newCapacity);
		if (!newBuf) {
			dprintf("Warning: failed to grow caves array, results may be incomplete\n");
			return FALSE;
		}
		*ppCaves = newBuf;
		*pCaveCapacity = newCapacity;
	}

	CODE_CAVE* cave = &(*ppCaves)[*pCaveCount];
	cave->startAddress = caveStart;
	cave->endAddress = caveEnd;
	cave->size = size;
	cave->pattern = pattern;
	cave->memoryProtection = protection;
	(*pCaveCount)++;
	return TRUE;
}

HRESULT ScanForCaves(IDebugDataSpaces2* dataSpaces, ULONG64 startAddress, ULONG64 endAddress, CODE_CAVE** ppCaves, ULONG* pCaveCount,
	ULONG minCaveSize) {
	HRESULT hr;
	ULONG bytesRead;
	const ULONG PAGE_SIZE = 0x1000;
	const ULONG INITIAL_CAPACITY = 16;

	// Allocate scan buffer for one page
	BYTE* scanBuffer = (BYTE*)malloc(PAGE_SIZE);
	if (!scanBuffer) {
		dprintf("Failed to allocate scan buffer\n");
		return E_OUTOFMEMORY;
	}

	ULONG caveCapacity = INITIAL_CAPACITY;
	CODE_CAVE* caves = (CODE_CAVE*)malloc(sizeof(CODE_CAVE) * caveCapacity);
	if (!caves) {
		free(scanBuffer);
		dprintf("Failed to allocate code caves array\n");
		return E_OUTOFMEMORY;
	}

	ULONG caveCount = 0;
	ULONG64 currentAddress = startAddress;
	ULONG64 currentCaveStart = 0;
	BOOL inCave = FALSE;
	BYTE cavePattern = 0;
	ULONG caveProtection = 0;

	while (currentAddress < endAddress) {
		ULONG protect = 0;
		ULONG64 regionRemaining = 0;
		if (!isExecutableMemory(dataSpaces, currentAddress, &protect, &regionRemaining)) {
			if (inCave) {
				TryRecordCave(&caves, &caveCount, &caveCapacity, minCaveSize,
					currentCaveStart, currentAddress - 1, cavePattern, caveProtection);
				inCave = FALSE;
			}
			// Skip the entire non-executable region
			currentAddress += regionRemaining ? regionRemaining : PAGE_SIZE;
			continue;
		}

		// Split cave if protection changed on this page
		if (inCave && protect != caveProtection) {
			TryRecordCave(&caves, &caveCount, &caveCapacity, minCaveSize,
				currentCaveStart, currentAddress - 1, cavePattern, caveProtection);
			currentCaveStart = currentAddress;
			caveProtection = protect;
		}

		// Read exactly one page
		ULONG toRead = min(PAGE_SIZE, (ULONG)(endAddress - currentAddress));

		hr = dataSpaces->ReadVirtual(currentAddress, scanBuffer, toRead, &bytesRead);
		if (FAILED(hr) || bytesRead == 0) {
			if (inCave) {
				TryRecordCave(&caves, &caveCount, &caveCapacity, minCaveSize,
					currentCaveStart, currentAddress - 1, cavePattern, caveProtection);
				inCave = FALSE;
			}
			currentAddress += PAGE_SIZE;
			continue;
		}

		// Scan this single page for caves
		for (ULONG i = 0; i < bytesRead; i++) {
			ULONG64 addressAtI = currentAddress + i;
			BYTE byte = scanBuffer[i];
			BOOL isCaveByte = (byte == 0x90 || byte == 0xCC || byte == 0x00);

			if (isCaveByte) {
				if (!inCave) {
					inCave = TRUE;
					currentCaveStart = addressAtI;
					cavePattern = byte;
					caveProtection = protect;
				}
				else if (byte != cavePattern) {
					TryRecordCave(&caves, &caveCount, &caveCapacity, minCaveSize,
						currentCaveStart, addressAtI - 1, cavePattern, caveProtection);
					currentCaveStart = addressAtI;
					cavePattern = byte;
					caveProtection = protect;
				}
			}
			else if (inCave) {
				TryRecordCave(&caves, &caveCount, &caveCapacity, minCaveSize,
					currentCaveStart, addressAtI - 1, cavePattern, caveProtection);
				inCave = FALSE;
			}
		}

		currentAddress += bytesRead;
	}

	// Handle cave at the very end
	if (inCave) {
		TryRecordCave(&caves, &caveCount, &caveCapacity, minCaveSize,
			currentCaveStart, endAddress - 1, cavePattern, caveProtection);
	}

	*ppCaves = caves;
	*pCaveCount = caveCount;

	free(scanBuffer);
	return S_OK;
}

const char* ResolveProt(ULONG prot) {
	if (prot & PAGE_EXECUTE_READWRITE) return "PAGE_EXECUTE_READWRITE";
	if (prot & PAGE_EXECUTE_READ) return "PAGE_EXECUTE_READ";
	if (prot & PAGE_EXECUTE_WRITECOPY) return "PAGE_EXECUTE_WRITECOPY";
	if (prot & PAGE_EXECUTE) return "PAGE_EXECUTE";
	return "UNKNOWN";
}

void PrintCaveTableHeader() {
	dprintf("%-18s  %-18s  %-10s  %-10s  %-25s\n", "START ADDRESS", "END ADDRESS", "SIZE", "PATTERN", "PROTECTION");
	dprintf("%-18s  %-18s  %-10s  %-10s  %-25s\n",
		"------------------",
		"------------------",
		"----------",
		"----------",
		"-------------------------");
}

void PrintCaveRow(CODE_CAVE* pCave) {
	const char* patternStr = "UNKNOWN";
	if (pCave->pattern == 0x90) {
		patternStr = "NOP";
	}
	else if (pCave->pattern == 0xCC) {
		patternStr = "INT3";
	}
	else if (pCave->pattern == 0x00) {
		patternStr = "PADDING";
	}
	dprintf("0x%016I64x  0x%016I64x  0x%-8x  %-10s  %-25s\n",
		pCave->startAddress,
		pCave->endAddress,
		pCave->size,
		patternStr,
		ResolveProt(pCave->memoryProtection)
	);
}

STDAPI cave(IDebugClient* client, PCSTR args) {
	if (!args || strlen(args) == 0) {
		dprintf("Usage: !cave <module_name> [min_size]\n");
		dprintf("Example: !cave kernel32 0x10\n");
		return E_INVALIDARG;
	}

	if (_stricmp(args, "-h") == 0) {
		return helpcave(client, NULL);
	}

	CComQIPtr<IDebugSymbols3> symbols(client);
	if (!symbols) {
		dprintf("Failed to get IDebugSymbols3 interface\n");
		return E_FAIL;
	}

	CComQIPtr<IDebugDataSpaces2> dataSpaces(client);
	if (!dataSpaces) {
		dprintf("Failed to get IDebugDataSpaces2 interface\n");
		return E_FAIL;
	}

	// Parse arguments
	char moduleName[256] = { 0 };
	ULONG minCaveSize = 0x40;
	sscanf_s(args, "%255s", moduleName, (unsigned int)sizeof(moduleName));

	const char* sizeArg = strchr(args, ' ');
	if (sizeArg) {
		while (*sizeArg == ' ') sizeArg++;
		if (*sizeArg) {
			char* endPtr = NULL;
			ULONG parsed = strtoul(sizeArg, &endPtr, 0);
			if (endPtr != sizeArg && parsed > 0) {
				minCaveSize = parsed;
			}
			else {
				dprintf("Invalid min_size '%s', using default 0x%x\n", sizeArg, minCaveSize);
			}
		}
	}

	// Find module by name
	ULONG64 moduleBase = 0;
	HRESULT hr = symbols->GetModuleByModuleName(moduleName, 0, NULL, &moduleBase);
	if (FAILED(hr)) {
		dprintf("Module '%s' not found\n", moduleName);
		return E_FAIL;
	}

	// Get module size by reading PE headers
	ULONG bytesRead = 0;
	IMAGE_DOS_HEADER dosHeader;
	hr = dataSpaces->ReadVirtual(moduleBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead);
	if (FAILED(hr) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
		dprintf("Failed to read DOS header\n");
		return E_FAIL;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
		dosHeader.e_lfanew <= 0 ||
		(ULONG)dosHeader.e_lfanew > 0x10000000) {
		dprintf("Invalid DOS header (bad e_lfanew: 0x%08lx)\n", (ULONG)dosHeader.e_lfanew);
		return E_FAIL;
	}

	IMAGE_NT_HEADERS ntHeaders;
	hr = dataSpaces->ReadVirtual(moduleBase + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead);
	if (FAILED(hr) || bytesRead != sizeof(IMAGE_NT_HEADERS)) {
		dprintf("Failed to read NT headers\n");
		return E_FAIL;
	}

	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
		dprintf("Invalid NT signature: 0x%08lx\n", ntHeaders.Signature);
		return E_FAIL;
	}

	ULONG sizeOfImage = ntHeaders.OptionalHeader.SizeOfImage;
	if (sizeOfImage == 0 || sizeOfImage > 0x80000000) {
		dprintf("Invalid SizeOfImage: 0x%lx\n", sizeOfImage);
		return E_FAIL;
	}

	ULONG64 startAddress = moduleBase;
	ULONG64 endAddress = moduleBase + sizeOfImage;

	CODE_CAVE* caves = NULL;
	ULONG caveCount = 0;

	hr = ScanForCaves(dataSpaces, startAddress, endAddress, &caves, &caveCount, minCaveSize);
	if (FAILED(hr)) {
		dprintf("Failed to scan for code caves\n");
		free(caves);
		return hr;
	}

	if (caveCount == 0) {
		dprintf("No code caves found\n");
		free(caves);
		return S_OK;
	}

	dprintf("\nFound %lu code cave(s):\n\n", caveCount);

	PrintCaveTableHeader();
	for (ULONG i = 0; i < caveCount; i++) {
		PrintCaveRow(&caves[i]);
	}

	free(caves);
	return S_OK;
}



STDAPI helpcave(IDebugClient* client, PCSTR args) {
	dprintf("\n");
	dprintf("CAVE - Code Cave Scanner\n");
	dprintf("========================\n");
	dprintf("\n");
	dprintf("  Scans a loaded module for contiguous regions of NOP (0x90),\n");
	dprintf("  INT3 (0xCC), or NULL padding (0x00) bytes in executable memory.\n");
	dprintf("\n");
	dprintf("USAGE:\n");
	dprintf("  !cave <module> [min_size]\n");
	dprintf("\n");
	dprintf("PARAMETERS:\n");
	dprintf("  module      Name of the loaded module (e.g. kernel32, ntdll)\n");
	dprintf("  min_size    Minimum cave size, supports hex/dec (default: 0x40)\n");
	dprintf("\n");
	dprintf("EXAMPLES:\n");
	dprintf("  !cave kernel32              Scan kernel32 with default min size\n");
	dprintf("  !cave ntdll 0x100           Scan ntdll for caves >= 256 bytes\n");
	dprintf("  !cave myapp 0x10            Scan myapp for caves >= 16 bytes\n");
	dprintf("\n");
	return S_OK;
}

STDAPI help(IDebugClient* client, PCSTR args) {
	dprintf("\n");
	dprintf("====================================================================\n");
	dprintf("                           CODECAVER                                \n");
	dprintf("              Created by: nop (@thenopcode)                         \n");
	dprintf("            GitHub: https://github.com/nop-tech/codecaver           \n");
	dprintf("====================================================================\n");
	dprintf("\n");
	dprintf("AVAILABLE COMMANDS:\n");
	dprintf("  !cave                      - Code cave scanner\n");
	dprintf("  Type '!cave -h' for detailed help:\n");
	dprintf("\n\n");
	return S_OK;
}