#ifndef _AHI_HPP_
#define _AHI_HPP_

#include <windows.h>
#include <string>
#include <map>

#define ADDR_SIZE 4
#define JMP_OPCODE 0xe9, 0x0, 0x0, 0x0, 0x0, 0xc3
#define JMP_OPCODE_SIZE 6

class AHI {
    LPVOID base_addr = 0x0;
    LPVOID pe = 0x0;
    BYTE jmp_opcode[JMP_OPCODE_SIZE] = { JMP_OPCODE };

    std::map<LPVOID, BYTE*> func_backups;
public:
    AHI(LPVOID image_base = 0x0);
    ~AHI();

    LPVOID hook_dll_func(std::string dll, std::string func_name, LPVOID dst_func);
    LPVOID unhook_dll_func(std::string dll, std::string func_name);
    LPVOID hook_func(LPVOID func, LPVOID dst_func);
    LPVOID unhook_func(LPVOID func);
};

#endif
