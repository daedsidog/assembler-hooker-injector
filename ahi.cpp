#include "ahi.hpp"

#include <iostream>

uintptr_t                                   AHI::base_addr = 0x0;
std::map<LPVOID, BYTE[JMP_OPCODE_SIZE]>     AHI::func_backups;
std::map<std::pair<LPVOID, LPVOID>, BYTE *> AHI::opcode_backups;

void AHI::init(void) { base_addr = (uintptr_t)GetModuleHandle(nullptr); }

LPVOID AHI::hook_func(uintptr_t func_addr, LPVOID dst_func_addr, bool silent) {
    func_addr = func_addr + base_addr;
    if (func_backups.find((LPVOID)func_addr) != func_backups.end()) {
        std::cerr << __FUNCTION__ << ": " << (LPVOID)func_addr
                  << " is already hooked!" << std::endl;
        return 0;
    }
    for (auto const &opcode_backup : opcode_backups) {
        LPVOID backup_start_addr = opcode_backup.first.first;
        LPVOID backup_end_addr   = opcode_backup.first.second;
        if ((LPVOID)func_addr >= backup_start_addr &&
            (LPVOID)func_addr <= backup_end_addr) {
            std::cerr << __FUNCTION__
                      << ": Target is located inside function injection range ["
                      << backup_start_addr << ", " << backup_end_addr << "]!"
                      << std::endl;
            return 0;
        }
    }
    HANDLE process_handle = GetCurrentProcess();
    if (!process_handle) {
        std::cerr << __FUNCTION__
                  << ": GetCurrentProcess error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    if (!ReadProcessMemory(process_handle, (LPVOID)func_addr,
                           func_backups[(LPVOID)func_addr], JMP_OPCODE_SIZE,
                           0)) {
        std::cerr << __FUNCTION__
                  << ": ReadProcessMemory error: " << GetLastError()
                  << std::endl;
        func_backups.erase((LPVOID)func_addr);
        return 0;
    }
    LPVOID dst_func_relative_addr =
        (LPVOID)((uintptr_t)dst_func_addr - func_addr - JMP_OPCODE_SIZE);
    DWORD previous_protection;
    VirtualProtect((LPVOID)func_addr, JMP_OPCODE_SIZE, PAGE_EXECUTE_READWRITE,
                   &previous_protection);
    BYTE jmp_opcode[JMP_OPCODE_SIZE] = {JMP_OPCODE_BYTES};
    memcpy(&jmp_opcode[1], &dst_func_relative_addr, ADDR_SIZE);
    if (!WriteProcessMemory(process_handle, (LPVOID)func_addr, jmp_opcode,
                            JMP_OPCODE_SIZE, 0)) {
        std::cerr << __FUNCTION__
                  << ": WriteProcessMemory error: " << GetLastError()
                  << std::endl;
        func_backups.erase((LPVOID)func_addr);
        return 0;
    }
    if (!VirtualProtect((LPVOID)func_addr, JMP_OPCODE_SIZE, previous_protection,
                        &previous_protection)) {
        std::cerr << __FUNCTION__
                  << ": VirtualProtect error: " << GetLastError() << std::endl;
        func_backups.erase((LPVOID)func_addr);
        return 0;
    }
    if (!FlushInstructionCache(process_handle, 0, 0)) {
        std::cerr << __FUNCTION__
                  << ": FlushInstructionCache error: " << GetLastError()
                  << std::endl;
        func_backups.erase((LPVOID)func_addr);
        return 0;
    }
    if(!silent){
        std::cout << "Hooked " << dst_func_relative_addr << " to "
                  << (LPVOID)func_addr << std::endl;
    }
    return (LPVOID)func_addr;
}

LPVOID AHI::unhook_func(uintptr_t func_addr, bool silent) {
    func_addr = func_addr + base_addr;
    if (func_backups.find((LPVOID)func_addr) == func_backups.end()) {
        std::cerr << __FUNCTION__ << ": " << func_addr << " is not hooked!"
                  << std::endl;
        return 0;
    }
    HANDLE process_handle = GetCurrentProcess();
    if (!process_handle) {
        std::cerr << __FUNCTION__
                  << ": GetCurrentProcess error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    if (!WriteProcessMemory(process_handle, (LPVOID)func_addr,
                            func_backups[(LPVOID)func_addr], JMP_OPCODE_SIZE,
                            0)) {
        std::cerr << __FUNCTION__
                  << ": WriteProcessMemory error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    if (!FlushInstructionCache(process_handle, 0, 0)) {
        std::cerr << __FUNCTION__
                  << ": FlushInstructionCache error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    if(!silent){
        std::cout << "Unhooked function from " << (LPVOID)func_addr << std::endl;
    }
    func_backups.erase((LPVOID)func_addr);
    return (LPVOID)func_addr;
}

LPVOID AHI::hook_dll_func(std::string dll, std::string func_name,
                          LPVOID dst_func_addr) {
    HMODULE module_handle = GetModuleHandle(dll.c_str());
    if (!module_handle) {
        std::cerr << __FUNCTION__
                  << ": GetModuleHandle error: " << GetLastError() << std::endl;
        return 0;
    }
    LPVOID func_addr = (LPVOID)GetProcAddress(module_handle, func_name.c_str());
    if (!func_addr) {
        std::cerr << __FUNCTION__
                  << ": GetProcAddress error: " << GetLastError() << std::endl;
        return 0;
    }
    std::cout << dll << "." << func_name << ": ";
    // Pointer arithmetic required because hook_func doesn't expect absolute
    // address.
    return hook_func((uintptr_t)func_addr + base_addr, dst_func_addr);
}

LPVOID AHI::unhook_dll_func(std::string dll, std::string func_name) {
    HMODULE module_handle = GetModuleHandle(dll.c_str());
    if (!module_handle) {
        std::cerr << __FUNCTION__
                  << ": GetModuleHandle error: " << GetLastError() << std::endl;
        return 0;
    }
    LPVOID func_addr = (LPVOID)GetProcAddress(module_handle, func_name.c_str());
    if (!func_addr) {
        std::cerr << __FUNCTION__
                  << ": GetProcAddress error: " << GetLastError() << std::endl;
        return 0;
    }
    std::cout << dll << "." << func_name << ": ";
    // Pointer arithmetic required because unhook_func doesn't expect absolute
    // address.
    return unhook_func((uintptr_t)func_addr + base_addr);
}

LPVOID AHI::inject_func(uintptr_t start_addr, uintptr_t end_addr,
                        LPVOID func_addr) {
    start_addr = start_addr + base_addr;
    end_addr   = end_addr + base_addr;
    if(end_addr - start_addr < CALL_OPCODE_SIZE){
        std::cerr << __FUNCTION__ << ": Not enough space to inject call instruction!" << std::endl;
        return 0;
    }
    for (auto const &opcode_backup : opcode_backups) {
        LPVOID backup_start_addr = opcode_backup.first.first;
        LPVOID backup_end_addr   = opcode_backup.first.second;
        if ((LPVOID)start_addr < backup_start_addr &&
                (LPVOID)end_addr <= backup_start_addr ||
            (LPVOID)start_addr >= backup_end_addr &&
                (LPVOID)end_addr > backup_end_addr) {
            continue;
        } else {
            std::cerr << __FUNCTION__
                      << ": Injection conflicts with another in range ["
                      << backup_start_addr << ", " << backup_end_addr << "]!"
                      << std::endl;
            return 0;
        }
    }
    if (func_backups.find((LPVOID)start_addr) != func_backups.end() ||
        func_backups.find((LPVOID)end_addr) != func_backups.end()) {
        std::cerr << __FUNCTION__ << ": "
                  << "Injection at " << (LPVOID)start_addr
                  << " conflicts with function hook!" << std::endl;
        return 0;
    }
    HANDLE process_handle = GetCurrentProcess();
    if (!process_handle) {
        std::cerr << __FUNCTION__
                  << ": GetCurrentProcess error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    uintptr_t size   = end_addr - start_addr;
    BYTE *    backup = new BYTE[size];
    if (!ReadProcessMemory(process_handle, (LPVOID)start_addr, backup, size,
                           0)) {
        std::cerr << __FUNCTION__
                  << ": ReadProcessMemory error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    LPVOID dst_func_relative_addr =
        (LPVOID)((uintptr_t)func_addr - start_addr - CALL_OPCODE_SIZE);
    DWORD previous_protection;
    VirtualProtect((LPVOID)func_addr, size, PAGE_EXECUTE_READWRITE,
                   &previous_protection);
    BYTE *nops = new BYTE[size];
    for (int i = 0; i < size; ++i) {
        nops[i] = NOP_OPCODE;
    }
    if (!WriteProcessMemory(process_handle, (LPVOID)start_addr, nops, size,
                            0)) {
        std::cerr << __FUNCTION__
                  << ": 1st WriteProcessMemory error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    delete[] nops;
    BYTE call_opcode[CALL_OPCODE_SIZE] = {CALL_OPCODE_BYTES};
    memcpy(&call_opcode[1], &dst_func_relative_addr, ADDR_SIZE);
    if (!WriteProcessMemory(process_handle, (LPVOID)start_addr, call_opcode,
                            CALL_OPCODE_SIZE, 0)) {
        std::cerr << __FUNCTION__
                  << ": 2nd WriteProcessMemory error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    if (!VirtualProtect((LPVOID)func_addr, size, previous_protection,
                        &previous_protection)) {
        std::cerr << __FUNCTION__
                  << ": VirtualProtect error: " << GetLastError() << std::endl;
        return 0;
    }
    if (!FlushInstructionCache(process_handle, 0, 0)) {
        std::cerr << __FUNCTION__
                  << ": FlushInstructionCache error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    std::cout << "Injected " << func_addr << " into [" << (LPVOID)start_addr
              << ", " << (LPVOID)end_addr << ")" << std::endl;
    opcode_backups[std::pair<LPVOID, LPVOID>((LPVOID)start_addr,
                                             (LPVOID)end_addr)] = backup;
    return (LPVOID)start_addr;
}

LPVOID AHI::eject_func(uintptr_t start_addr) {
    start_addr = start_addr + base_addr;
    for (auto const &opcode_backup : opcode_backups) {
        LPVOID backup_start_addr = opcode_backup.first.first;
        LPVOID backup_end_addr   = opcode_backup.first.second;
        if ((LPVOID)start_addr == backup_start_addr) {
            HANDLE process_handle = GetCurrentProcess();
            if (!process_handle) {
                std::cerr << __FUNCTION__
                          << ": GetCurrentProcess error: " << GetLastError()
                          << std::endl;
                return 0;
            }
            uintptr_t size =
                (uintptr_t)backup_end_addr - (uintptr_t)backup_start_addr;
            if (!WriteProcessMemory(process_handle, (LPVOID)start_addr,
                                    opcode_backup.second, size, 0)) {
                std::cerr << __FUNCTION__
                          << ": WriteProcessMemory error: " << GetLastError()
                          << std::endl;
                return 0;
            }
            if (!FlushInstructionCache(process_handle, 0, 0)) {
                std::cerr << __FUNCTION__
                          << ": FlushInstructionCache error: " << GetLastError()
                          << std::endl;
                return 0;
            }
            std::cout << "Ejected function from [" << backup_start_addr << ", "
                      << backup_end_addr << ")" << std::endl;
            delete[] opcode_backup.second;
            opcode_backups.erase(opcode_backup.first);
            return backup_start_addr;
        }
    }
    std::cerr << __FUNCTION__ << ": No function injected at "
              << (LPVOID)start_addr << "!" << std::endl;
    return 0;
}

uintptr_t AHI::get_abs_addr(uintptr_t image_base, uintptr_t rva){
    return (rva - image_base) + base_addr;
}
