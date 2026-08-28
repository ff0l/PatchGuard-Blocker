#pragma once

#include <cstdint>

namespace pg::stack {
    // Switch RSP to new_stack, place argument in RCX, jump to function.
    // Never returns. MSVC x64: executable stub in .text (no .asm file).
    extern "C" void transfer(
        std::uint64_t new_stack,
        void* function,
        void* argument );
}
