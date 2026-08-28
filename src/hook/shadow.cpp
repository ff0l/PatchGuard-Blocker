#include "shadow.hpp"

namespace pg::hook {
    namespace {
        std::uint32_t free_pml4_slot( std::uint64_t system_pml4_pa ) {
            for ( std::uint32_t index = 257; index < 511; ++index ) {
                pml4e entry{ };
                if ( !dpm::read_physical(
                    system_pml4_pa + index * sizeof( pml4e ),
                    &entry,
                    sizeof( entry ) ) )
                    continue;

                if ( !entry.hard.present )
                    return index;
            }

            kernel::dbg_print( obf( "no free pml4 slot\n" ) );
            return static_cast< std::uint32_t >( -1 );
        }

        std::uint64_t allocate_page_table( ) {
            const auto va = kernel::mm_allocate_independent_pages( paging::page_4kb_size );
            if ( !va )
                return 0;

            return kernel::mm_get_physical_address( va );
        }
    }

    bool build_shadow(
        std::uint64_t private_pa,
        std::uint64_t hooked_va,
        std::uint64_t canonical_pte_pa,
        std::uint64_t canonical_pte_value,
        shadow_map& out ) {
        const auto system_pml4_pa = __readcr3( ) & ~0xFFFULL;
        const auto slot = free_pml4_slot( system_pml4_pa );
        if ( slot == static_cast< std::uint32_t >( -1 ) )
            return false;

        const auto shadow_pml4_va =
            kernel::mm_allocate_independent_pages( paging::page_4kb_size );
        if ( !shadow_pml4_va )
            return false;

        const auto shadow_pml4_pa = kernel::mm_get_physical_address( shadow_pml4_va );
        if ( !shadow_pml4_pa )
            return false;

        std::uint8_t copy[ paging::page_4kb_size ];
        if ( !dpm::read_physical( system_pml4_pa, copy, sizeof( copy ) ) )
            return false;
        if ( !dpm::write_physical( shadow_pml4_pa, copy, sizeof( copy ) ) )
            return false;

        paging::hide_pages( shadow_pml4_va, paging::page_4kb_size, true );

        const auto pdpt_pa = allocate_page_table( );
        const auto pd_pa = allocate_page_table( );
        const auto pt_pa = allocate_page_table( );
        if ( !pdpt_pa || !pd_pa || !pt_pa )
            return false;

        const auto shadow_base = paging::create_virtual_address( slot, true );
        const auto shadow_va =
            ( shadow_base & ~paging::page_4kb_mask ) |
            ( hooked_va & paging::page_4kb_mask );

        virt_addr_t va{ shadow_va };

        pml4e pml4{ };
        pml4.hard.present = 1;
        pml4.hard.read_write = 1;
        pml4.hard.pfn = pdpt_pa >> paging::page_shift;
        dpm::write_physical(
            shadow_pml4_pa + va.pml4e_index * sizeof( pml4e ),
            &pml4,
            sizeof( pml4 ) );

        pdpte pdpt{ };
        pdpt.hard.present = 1;
        pdpt.hard.read_write = 1;
        pdpt.hard.pfn = pd_pa >> paging::page_shift;
        dpm::write_physical(
            pdpt_pa + va.pdpte_index * sizeof( pdpte ),
            &pdpt,
            sizeof( pdpt ) );

        pde pd{ };
        pd.hard.present = 1;
        pd.hard.read_write = 1;
        pd.hard.pfn = pt_pa >> paging::page_shift;
        dpm::write_physical(
            pd_pa + va.pde_index * sizeof( pde ),
            &pd,
            sizeof( pd ) );

        pte pt{ };
        pt.hard.present = 1;
        pt.hard.read_write = 0;
        pt.hard.no_execute = 0;
        pt.hard.global = 0;
        pt.hard.pfn = private_pa >> paging::page_shift;

        const auto shadow_pte_pa = pt_pa + va.pte_index * sizeof( pte );
        dpm::write_physical( shadow_pte_pa, &pt, sizeof( pt ) );

        pte canonical{ };
        if ( !dpm::read_physical( canonical_pte_pa, &canonical, sizeof( canonical ) ) )
            return false;

        kernel::flush_caches( kernel::mm_get_virtual_for_physical( private_pa ) );

        out.pml4_pa = shadow_pml4_pa;
        out.pdpt_pa = pdpt_pa;
        out.pd_pa = pd_pa;
        out.pt_pa = pt_pa;
        out.pte_pa = shadow_pte_pa;
        out.shadow_va = shadow_va;
        out.pml4_index = slot;
        out.canonical_pte_pa = canonical_pte_pa;
        out.canonical_pte_value = canonical_pte_value;
        out.active = true;
        return true;
    }

    bool destroy_shadow( shadow_map& map ) {
        if ( !map.active )
            return false;

        if ( map.canonical_pte_pa && map.canonical_pte_value ) {
            pte original{ map.canonical_pte_value };
            dpm::write_physical(
                map.canonical_pte_pa, &original, sizeof( original ) );
        }

        if ( map.pml4_pa ) {
            virt_addr_t va{ map.shadow_va };
            pml4e zero{ };
            dpm::write_physical(
                map.pml4_pa + va.pml4e_index * sizeof( pml4e ),
                &zero,
                sizeof( zero ) );
        }

        kernel::ke_flush_entire_tb( true, true );
        map.active = false;
        return true;
    }
}
