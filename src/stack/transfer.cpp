#include "transfer.hpp"

namespace pg::stack {
    #pragma section( ".text" )
    __declspec( allocate( ".text" ) )
    static const unsigned char k_transfer[] = {
        0x48, 0x89, 0xCC, // mov rsp, rcx
        0x4C, 0x89, 0xC1, // mov rcx, r8
        0xFF, 0xE2        // jmp rdx
    };

    extern "C" void transfer(
        std::uint64_t new_stack,
        void* function,
        void* argument ) {
        using fn_t = void ( * )( std::uint64_t, void*, void* );
        reinterpret_cast< fn_t >(
            const_cast< unsigned char* >( k_transfer ) )(
                new_stack, function, argument );
    }
}
