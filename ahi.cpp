#include "ahi.hpp"

#include <iostream>

AHI::AHI(LPVOID image_base){
    this->base_addr = GetModuleHandle(0x0);
    this->pe = image_base;
}

AHI::~AHI(){
    for(auto const& func_backup : func_backups){
        delete[] func_backup.second;
    }
}

LPVOID AHI::hook_dll_func(std::string dll, std::string func_name, LPVOID dst_func){
    HMODULE module_handle = GetModuleHandle(dll.c_str());
    if (!module_handle){
        std::cerr << __FUNCTION__ << ": GetModuleHandle error: " << GetLastError() << std::endl;
        return 0;
    }
    LPVOID relative_func_addr = (LPVOID)GetProcAddress(module_handle, func_name.c_str());
    if(!relative_func_addr){
        std::cerr << __FUNCTION__ << ": GetProcAddress error: " << GetLastError() << std::endl;
        return 0;
    }
    HANDLE process_handle = GetCurrentProcess();
    if(!process_handle){
        std::cerr << __FUNCTION__ << ": GetCurrentProcess error: " << GetLastError() << std::endl;
        return 0;
    }

    // sizeof(LPVOID) + 2 allows this to be portable across different architectures.
    if(!ReadProcessMemory(process_handle, relative_func_addr, func_backups[relative_func_addr], JMP_OPCODE_SIZE, 0)){
        std::cerr << __FUNCTION__ << ": ReadProcessMemory error: " << GetLastError() << std::endl;
        return 0;
    }
    LPVOID func_addr = (LPVOID)((uintptr_t)dst_func - (uintptr_t)relative_func_addr - (JMP_OPCODE_SIZE - 1));
    DWORD previous_protection;
    VirtualProtect(relative_func_addr, JMP_OPCODE_SIZE, PAGE_EXECUTE_READWRITE,
                   &previous_protection);
    memcpy(&jmp_opcode[1], &func_addr, ADDR_SIZE);
    if(!WriteProcessMemory(process_handle, (LPVOID)relative_func_addr, jmp_opcode, JMP_OPCODE_SIZE,
                       0)){
        std::cerr << __FUNCTION__ << ": WriteProcessMemory error: " << GetLastError() << std::endl;
        return 0;
    }
    if(!VirtualProtect((LPVOID)relative_func_addr, JMP_OPCODE_SIZE, previous_protection,
                   &previous_protection)){
        std::cerr << __FUNCTION__ << ": VirtualProtect error: " << GetLastError() << std::endl;
        return 0;
    }
    if(!FlushInstructionCache(process_handle, 0, 0)){
        std::cerr << __FUNCTION__ << ": FlushInstructionCache error: " << GetLastError() << std::endl;
        return 0;
    }
    return relative_func_addr;
}
