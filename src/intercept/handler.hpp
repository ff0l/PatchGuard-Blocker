#pragma once

#include <cstdint>

namespace pg::intercept {
    void park_thread( void* unused );

    void on_privileged_instruction( PEXCEPTION_RECORD record, PCONTEXT context );
    void on_breakpoint( PEXCEPTION_RECORD record, PCONTEXT context );

    void bugcheck_hook(
        unsigned int code,
        std::uint64_t a,
        std::uint64_t b,
        std::uint64_t c,
        std::uint64_t d );

    bool on_kdp_report(
        std::uint64_t trap_frame,
        std::uint64_t exception_frame,
        PEXCEPTION_RECORD record,
        PCONTEXT context,
        KPROCESSOR_MODE mode,
        bool first_chance );

    // Install KeBugCheckEx + KdpReport hooks and enable the debug path.
    bool install( );
}
