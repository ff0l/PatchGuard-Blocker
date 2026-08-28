#pragma once

#include "shadow.hpp"

#include <cstddef>
#include <cstdint>

namespace pg::hook::physical {
    struct state {
        std::uint8_t original[ 64 ]{ };
        std::size_t length{ };
        std::uint64_t trampoline_va{ };
        std::uint64_t page_va{ };
        std::uint64_t page_pa{ };
        std::uint64_t clean_pa{ };
        std::uint64_t pte_pa{ };
        std::uint64_t pte_value{ };
        shadow_map shadow{ };
    };

    constexpr std::size_t k_jmp_size = 14;
    constexpr std::size_t k_trampoline_cap = 64 + 14;

    std::size_t cover_instructions( std::uint64_t target_pa, std::size_t minimum );
    bool write_trampoline(
        std::uint64_t cave_va,
        std::uint64_t resume_va,
        std::uint8_t* stolen,
        std::size_t stolen_len );

    template <typename Fn = void*>
    state* create( std::uint64_t address, Fn* out_original = nullptr );

    bool enable( state* hook, void* detour );
    bool use_hooked_view( state* hook );
    bool use_clean_view( state* hook );
    bool remove( std::uint64_t address, state* hook );
    bool is_active( std::uint64_t address, const state* known );
}

#include "physical.inl"
