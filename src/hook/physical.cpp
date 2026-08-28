#include "physical.hpp"

#include <cstring>

namespace pg::hook::physical {
    std::size_t cover_instructions( std::uint64_t target_pa, std::size_t minimum ) {
        std::uint8_t buffer[ 64 ];
        if ( !dpm::read_physical( target_pa, buffer, sizeof( buffer ) ) )
            return 0;

        std::size_t total = 0;
        while ( total < minimum && total < sizeof( buffer ) ) {
            hde64s decoded{ };
            hde64_disasm( &buffer[ total ], &decoded );
            if ( decoded.len == 0 )
                break;
            total += decoded.len;
        }
        return total;
    }

    bool write_trampoline(
        std::uint64_t cave_va,
        std::uint64_t resume_va,
        std::uint8_t* stolen,
        std::size_t stolen_len ) {
        pt_entries_t entries{ };
        if ( !paging::hyperspace_entries( entries, cave_va ) ||
            !entries.m_pte.hard.present )
            return false;

        const auto cave_pa =
            ( entries.m_pte.hard.pfn << paging::page_shift ) |
            ( cave_va & paging::page_4kb_mask );

        if ( !dpm::write_physical( cave_pa, stolen, stolen_len ) )
            return false;

        std::uint8_t jmp[ 14 ]{ };
        jmp[ 0 ] = 0xFF;
        jmp[ 1 ] = 0x25;
        *reinterpret_cast< std::uint32_t* >( &jmp[ 2 ] ) = 0;
        *reinterpret_cast< std::uint64_t* >( &jmp[ 6 ] ) = resume_va;

        if ( !dpm::write_physical( cave_pa + stolen_len, jmp, sizeof( jmp ) ) )
            return false;

        kernel::dbg_print(
            obf( "trampoline 0x%llx -> 0x%llx\n" ), cave_va, resume_va );
        return true;
    }

    bool enable( state* hook, void* detour ) {
        if ( !hook || !hook->page_pa )
            return false;
        if ( !hook->shadow.active ) {
            kernel::dbg_print( obf( "shadow inactive\n" ) );
            return false;
        }

        std::uint8_t jmp[ 14 ]{ };
        jmp[ 0 ] = 0xFF;
        jmp[ 1 ] = 0x25;
        *reinterpret_cast< std::uint32_t* >( &jmp[ 2 ] ) = 0;
        *reinterpret_cast< std::uint64_t* >( &jmp[ 6 ] ) =
            reinterpret_cast< std::uint64_t >( detour );

        if ( !dpm::write_physical( hook->page_pa, jmp, k_jmp_size ) )
            return false;

        if ( hook->length > k_jmp_size ) {
            std::uint8_t nops[ 48 ]{ };
            std::memset( nops, 0x90, hook->length - k_jmp_size );
            if ( !dpm::write_physical(
                hook->page_pa + k_jmp_size,
                nops,
                hook->length - k_jmp_size ) )
                return false;
        }

        return true;
    }

    bool use_hooked_view( state* hook ) {
        if ( !hook || !hook->shadow.active )
            return false;

        pte entry{ };
        if ( !dpm::read_physical( hook->shadow.canonical_pte_pa, &entry, sizeof( entry ) ) )
            return false;

        entry.hard.pfn = hook->page_pa >> paging::page_shift;
        if ( !dpm::write_physical( hook->shadow.canonical_pte_pa, &entry, sizeof( entry ) ) )
            return false;

        kernel::flush_caches( hook->page_va );
        return true;
    }

    bool use_clean_view( state* hook ) {
        if ( !hook || !hook->shadow.active )
            return false;

        pte entry{ };
        if ( !dpm::read_physical( hook->shadow.canonical_pte_pa, &entry, sizeof( entry ) ) )
            return false;

        entry.hard.pfn = hook->clean_pa >> paging::page_shift;
        if ( !dpm::write_physical( hook->shadow.canonical_pte_pa, &entry, sizeof( entry ) ) )
            return false;

        kernel::ke_flush_entire_tb( true, true );
        return true;
    }

    bool remove( std::uint64_t address, state* hook ) {
        if ( !address || !hook || !hook->pte_pa || !hook->pte_value )
            return false;

        if ( hook->shadow.active ) {
            use_clean_view( hook );
            if ( !destroy_shadow( hook->shadow ) ) {
                kernel::dbg_print( obf( "shadow destroy failed\n" ) );
                return false;
            }
        }

        kernel::ke_flush_entire_tb( true, true );

        if ( hook->trampoline_va ) {
            pt_entries_t entries{ };
            if ( paging::hyperspace_entries( entries, hook->trampoline_va ) &&
                entries.m_pte.hard.present ) {
                const auto cave_pa =
                    ( entries.m_pte.hard.pfn << paging::page_shift ) |
                    ( hook->trampoline_va & paging::page_4kb_mask );
                std::uint8_t zeros[ k_trampoline_cap ]{ };
                dpm::write_physical( cave_pa, zeros, hook->length + 14 );
            }
        }

        kernel::dbg_print( obf( "hook removed 0x%llx\n" ), address );
        return true;
    }

    bool is_active( std::uint64_t address, const state* known ) {
        if ( !address || !known || !known->length )
            return false;

        std::uint64_t pa = 0;
        if ( !paging::translate_linear( address, &pa ) )
            return false;

        std::uint8_t current[ 64 ];
        if ( !dpm::read_physical( pa, current, sizeof( current ) ) )
            return false;

        return std::memcmp( current, known->original, known->length ) != 0;
    }
}
