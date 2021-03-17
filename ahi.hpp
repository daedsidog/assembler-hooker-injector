#ifndef _AHI_HPP_
#define _AHI_HPP_

#include <windows.h>
#include <string>
#include <map>

#define ADDR_SIZE 4
#define JMP_OPCODE_BYTES 0xe9, 0x0, 0x0, 0x0, 0x0, 0xc3
#define JMP_OPCODE_SIZE 6

class AHI {
    uintptr_t base_addr = 0x0;
    uintptr_t pe = 0x0;
    BYTE jmp_opcode[JMP_OPCODE_SIZE] = {JMP_OPCODE_BYTES};

    std::map<LPVOID, BYTE[JMP_OPCODE_SIZE]> func_backups;

  public:
    AHI(uintptr_t image_base = 0x0);
    ~AHI();

    LPVOID hook_func(LPVOID func_addr, LPVOID dst_func_addr);
    LPVOID unhook_func(LPVOID func_addr);
    LPVOID hook_dll_func(std::string dll, std::string func_name,
                         LPVOID dst_func_addr);
    LPVOID unhook_dll_func(std::string dll, std::string func_name);
};

#endif
