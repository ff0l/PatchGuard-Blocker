#pragma once

#include <cstdint>

namespace pg::hook {
    struct shadow_map {
        std::uint64_t pml4_pa{ };
        std::uint64_t pdpt_pa{ };
        std::uint64_t pd_pa{ };
        std::uint64_t pt_pa{ };
        std::uint64_t pte_pa{ };
        std::uint64_t shadow_va{ };
        std::uint32_t pml4_index{ };
        std::uint64_t canonical_pte_pa{ };
        std::uint64_t canonical_pte_value{ };
        bool active{ };
    };

    bool build_shadow(
        std::uint64_t private_pa,
        std::uint64_t hooked_va,
        std::uint64_t canonical_pte_pa,
        std::uint64_t canonical_pte_value,
        shadow_map& out );

    bool destroy_shadow( shadow_map& map );
}
