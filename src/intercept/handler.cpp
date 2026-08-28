#include "handler.hpp"
#include "../stack/transfer.hpp"
#include "../hook/physical.hpp"

namespace pg::intercept {
    namespace {
        void ( *g_bugcheck_original )(
            unsigned int,
            std::uint64_t,
            std::uint64_t,
            std::uint64_t,
            std::uint64_t ) = nullptr;

        bool is_mov_to_cr0( const std::uint8_t* rip ) {
            // mov cr0, r32/r64
            if ( rip[ 0 ] == 0x0F && rip[ 1 ] == 0x22 && ( rip[ 2 ] & 0xF8 ) == 0xC0 )
                return true;

            // REX.W mov cr0, r64
            if ( ( rip[ 0 ] & 0xF0 ) == 0x40 &&
                rip[ 1 ] == 0x0F &&
                rip[ 2 ] == 0x22 &&
                ( rip[ 3 ] & 0xF8 ) == 0xC0 )
                return true;

            return false;
        }

        void freeze_current_thread( ) {
            auto* stack_top = kernel::io_get_initial_stack( );
            pg::stack::transfer(
                reinterpret_cast< std::uint64_t >( stack_top ) - 8,
                park_thread,
                nullptr );
        }
    }

    void park_thread( void* ) {
        LARGE_INTEGER delay{ };
        delay.u.LowPart = 0;
        delay.u.HighPart = 0x80000000;
        KeDelayExecutionThread( KernelMode, FALSE, &delay );
    }

    void on_privileged_instruction( PEXCEPTION_RECORD record, PCONTEXT context ) {
        if ( record->ExceptionCode != STATUS_PRIVILEGED_INSTRUCTION )
            return;

        auto* rip = reinterpret_cast< const std::uint8_t* >( context->Rip );
        if ( !is_mov_to_cr0( rip ) )
            return;

        freeze_current_thread( );
    }

    void on_breakpoint( PEXCEPTION_RECORD record, PCONTEXT context ) {
        if ( record->ExceptionCode != STATUS_BREAKPOINT )
            return;

        context->Rip += 1;
        kernel::zw_continue( context, FALSE );
    }

    void bugcheck_hook(
        unsigned int code,
        std::uint64_t a,
        std::uint64_t b,
        std::uint64_t c,
        std::uint64_t d ) {
        // CRITICAL_STRUCTURE_CORRUPTION
        if ( code == 0x109 )
            freeze_current_thread( );

        g_bugcheck_original( code, a, b, c, d );
    }

    bool on_kdp_report(
        std::uint64_t,
        std::uint64_t,
        PEXCEPTION_RECORD record,
        PCONTEXT context,
        KPROCESSOR_MODE mode,
        bool first_chance ) {
        if ( !kernel::mm_is_address_valid( record ) ||
            !kernel::mm_is_address_valid( context ) )
            return false;

        if ( mode || !first_chance )
            return false;

        switch ( record->ExceptionCode ) {
            case STATUS_PRIVILEGED_INSTRUCTION:
                on_privileged_instruction( record, context );
                break;
            case STATUS_BREAKPOINT:
                on_breakpoint( record, context );
                break;
            default:
                break;
        }

        return false;
    }

    bool install( ) {
        const auto bugcheck = kernel::get_export(
            kernel::m_ntoskrnl_base, obf( "KeBugCheckEx" ) );

        auto* bugcheck_state = hook::physical::create(
            bugcheck, &g_bugcheck_original );
        if ( !bugcheck_state )
            return false;
        if ( !hook::physical::enable( bugcheck_state, &bugcheck_hook ) )
            return false;

        auto* kdp_state = hook::physical::create( kernel::m_pdb.m_kdp_report );
        if ( !kdp_state )
            return false;
        if ( !hook::physical::enable( kdp_state, &on_kdp_report ) )
            return false;

        *reinterpret_cast< unsigned long* >(
            kernel::m_pdb.m_kdp_debug_routine_select ) = 1;
        return true;
    }
}
