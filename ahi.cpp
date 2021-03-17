#include "ahi.hpp"

#include <iostream>

AHI::AHI(uintptr_t image_base) {
    base_addr = (uintptr_t)GetModuleHandle(0x0);
    pe = image_base;
}

AHI::~AHI() {
    for (const auto &func_backup : func_backups) {
        unhook_func(func_backup.first);
    }
}

LPVOID AHI::hook_func(LPVOID func_addr, LPVOID dst_func) {
    func_addr =
        (LPVOID)((uintptr_t)func_addr - pe + base_addr);
    if (func_backups.find(func_addr) != func_backups.end()) {
        std::cerr << __FUNCTION__ << ": " << func_addr << " is already hooked!"
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
    if (!ReadProcessMemory(process_handle, func_addr, func_backups[func_addr],
                           JMP_OPCODE_SIZE, 0)) {
        std::cerr << __FUNCTION__
                  << ": ReadProcessMemory error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    LPVOID dst_func_addr = (LPVOID)((uintptr_t)dst_func - (uintptr_t)func_addr -
                                    (JMP_OPCODE_SIZE - 1));
    DWORD previous_protection;
    VirtualProtect(func_addr, JMP_OPCODE_SIZE, PAGE_EXECUTE_READWRITE,
                   &previous_protection);
    memcpy(&jmp_opcode[1], &dst_func_addr, ADDR_SIZE);
    if (!WriteProcessMemory(process_handle, (LPVOID)func_addr, jmp_opcode,
                            JMP_OPCODE_SIZE, 0)) {
        std::cerr << __FUNCTION__
                  << ": WriteProcessMemory error: " << GetLastError()
                  << std::endl;
        return 0;
    }
    if (!VirtualProtect((LPVOID)func_addr, JMP_OPCODE_SIZE, previous_protection,
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
    std::cout << "Hooked " << dst_func_addr << " to " << func_addr << std::endl;
    return func_addr;
}

LPVOID AHI::unhook_func(LPVOID func_addr) {
    func_addr =
        (LPVOID)((uintptr_t)func_addr - pe + base_addr);
    if (func_backups.find(func_addr) == func_backups.end()) {
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
                            func_backups[func_addr], JMP_OPCODE_SIZE, 0)) {
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
    std::cout << "Unooked function from " << func_addr << std::endl;
    func_backups.erase(func_addr);
    return func_addr;
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
    return func_addr = hook_func((LPVOID)((uintptr_t)func_addr + pe -
                                          base_addr),
                                 dst_func_addr);
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
    return unhook_func(
        (LPVOID)((uintptr_t)func_addr + pe - base_addr));
}
