#ifndef AHI_HPP_
#define AHI_HPP_

#include <windows.h>
#include <string>
#include <map>

#define JMP_OPCODE_BYTES  0xe9, 0x0, 0x0, 0x0, 0x0
#define CALL_OPCODE_BYTES 0xe8, 0x0, 0x0, 0x0, 0x0
#define NOP_OPCODE        0x90
#define ADDR_SIZE         4
#define JMP_OPCODE_SIZE   5
#define CALL_OPCODE_SIZE  5

#define UNREADABLE_CHAR_PLACEHOLDER '.'
#define READABLE_RANGE_START ' '
#define READABLE_RANGE_END '~'

class AHI {
    static uintptr_t base_addr;
    static std::map<LPVOID, BYTE[JMP_OPCODE_SIZE]>     func_backups;
    static std::map<std::pair<LPVOID, LPVOID>, BYTE *> opcode_backups;

  public:

    // Set the base address to that of the current program.
    static void init(void);

    // Hook function dst_func_addr to func_addr.
    static LPVOID hook_func(uintptr_t func_addr, LPVOID dst_func_addr, bool silent = false);

    // Unhook from func_addr.
    static LPVOID unhook_func(uintptr_t func_addr, bool silent = false);

    // Hook dst_func_addr to dll.func_name.
    static LPVOID hook_dll_func(std::string dll, std::string func_name,
                                LPVOID dst_func_addr, bool silent = false);
    // Unhook from dll.func_name.
    static LPVOID unhook_dll_func(std::string dll, std::string func_name, bool silent = false);

    // Change bytecodes [start_addr, end_addr) to NOP & inject func_addr to
    // start_addr. Mostly useful for injecting inline assembly in an address
    // range.
    static LPVOID inject_func(uintptr_t start_addr, uintptr_t end_addr,
                              LPVOID func_addr);
    // Restore bytecodes & remove function injected at start_addr.
    static LPVOID eject_func(uintptr_t start_addr);

    // Get the base address of the current process.
    static uintptr_t get_base_addr();

    // Get the relative offset given the virtual relative & base addresses.
    static uintptr_t get_offset(uintptr_t image_base, uintptr_t rva);

    // Get the absolute address given the virtual relative & base addresses.
    static uintptr_t get_abs_addr(uintptr_t image_base, uintptr_t rva);

    // Get readable string from byte stream.
    static std::string stringify(char *buf, long len);
};

#endif
