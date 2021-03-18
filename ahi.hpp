#ifndef _AHI_HPP_
#define _AHI_HPP_

#include <windows.h>
#include <string>
#include <map>

#define ADDR_SIZE 4
#define JMP_OPCODE_BYTES 0xe9, 0x0, 0x0, 0x0, 0x0, 0xc3
#define JMP_OPCODE_SIZE 6
#define NOP_OPCODE 0x90

class AHI {
    LPVOID base_addr = 0x0;
    LPVOID pe = 0x0;
    BYTE jmp_opcode[JMP_OPCODE_SIZE] = {JMP_OPCODE_BYTES};

    std::map<LPVOID, BYTE[JMP_OPCODE_SIZE]> func_backups;
    std::map<std::pair<LPVOID, LPVOID>, BYTE *> opcode_backups;

  public:
    AHI(uintptr_t image_base = 0x0);
    ~AHI();

    // Hook function dst_func_addr to func_addr.
    LPVOID hook_func(uintptr_t func_addr, LPVOID dst_func_addr);
    // Unhook from func_addr.
    LPVOID unhook_func(uintptr_t func_addr);
    // Hook dst_func_addr to dll.func_name.
    LPVOID hook_dll_func(std::string dll, std::string func_name,
                         LPVOID dst_func_addr);
    // Unhook from dll.func_name.
    LPVOID unhook_dll_func(std::string dll, std::string func_name);
    // Change bytecodes [start_addr, end_addr) to NOP & inject func_addr to
    // start_addr. Mostly useful for injecting inline assembly in an address
    // range.
    LPVOID inject_func(uintptr_t start_addr, uintptr_t end_addr,
                       LPVOID func_addr);
    // Restore bytecodes & remove function injected at start_addr.
    LPVOID eject_func(uintptr_t start_addr);
};

#endif
