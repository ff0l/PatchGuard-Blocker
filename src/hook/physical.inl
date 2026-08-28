#pragma once

namespace pg::hook::physical {
    template <typename Fn>
    state* create( std::uint64_t address, Fn* out_original ) {
        pt_entries_t entries{ };
        if ( !paging::hyperspace_entries( entries, address ) )
            return nullptr;

        virt_addr_t virt{ address };

        if ( entries.m_pdpte.hard.page_size ) {
            if ( !paging::split_1gb_to_4kb( address ) )
                return nullptr;
            if ( !paging::hyperspace_entries( entries, address ) )
                return nullptr;
        }
        else if ( entries.m_pde.hard.page_size ) {
            if ( !paging::split_2mb_to_4kb( address ) )
                return nullptr;
            if ( !paging::hyperspace_entries( entries, address ) )
                return nullptr;
        }

        if ( !entries.m_pte.hard.present )
            return nullptr;

        if ( !paging::hide_pages( address, paging::page_4kb_size ) )
            return nullptr;

        auto* pte_ptr = reinterpret_cast< std::uint64_t* >(
            paging::get_pte_address( address ) );
        if ( !pte_ptr )
            return nullptr;

        const auto clean_pa =
            ( entries.m_pte.hard.pfn << paging::page_shift ) |
            ( address & paging::page_4kb_mask );

        const auto stolen_len = cover_instructions( clean_pa, k_jmp_size );
        if ( stolen_len < k_jmp_size )
            return nullptr;

        const auto cave = memory::find_cave( stolen_len + 14 );
        if ( !cave )
            return nullptr;

        std::uint8_t stolen[ 64 ]{ };
        if ( !dpm::read_physical( clean_pa, stolen, sizeof( stolen ) ) )
            return nullptr;

        if ( kernel::mi_copy_on_write( address, pte_ptr ) )
            return nullptr;

        if ( !paging::hyperspace_entries( entries, address ) )
            return nullptr;

        const auto private_pa =
            ( entries.m_pte.hard.pfn << paging::page_shift ) |
            ( address & paging::page_4kb_mask );

        if ( private_pa == clean_pa ) {
            kernel::dbg_print( obf( "copy-on-write did not private the page\n" ) );
            return nullptr;
        }

        const auto canonical_pte_pa =
            ( entries.m_pde.hard.pfn << paging::page_shift ) +
            virt.pte_index * sizeof( pte );
        const auto canonical_pte_value = entries.m_pte.value;

        shadow_map shadow{ };
        if ( !build_shadow(
            private_pa,
            address,
            canonical_pte_pa,
            canonical_pte_value,
            shadow ) ) {
            kernel::dbg_print( obf( "shadow map failed\n" ) );
            return nullptr;
        }

        if ( !write_trampoline( cave, address + stolen_len, stolen, stolen_len ) )
            return nullptr;

        if ( out_original )
            *out_original = reinterpret_cast< Fn >( cave );

        auto* hook = reinterpret_cast< state* >(
            kernel::mm_allocate_independent_pages( sizeof( state ) ) );
        if ( !hook )
            return nullptr;

        hook->pte_pa = canonical_pte_pa;
        hook->pte_value = canonical_pte_value;
        hook->length = stolen_len;
        hook->trampoline_va = cave;
        hook->page_va = address;
        hook->page_pa = private_pa;
        hook->clean_pa = clean_pa;
        hook->shadow = shadow;
        std::memcpy( hook->original, stolen, stolen_len );

        kernel::dbg_print( obf( "physical hook ready\n" ) );
        return hook;
    }
}
