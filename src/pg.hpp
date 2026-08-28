#pragma once

#include "stack/transfer.hpp"
#include "intercept/handler.hpp"
#include "hook/physical.hpp"
#include "hook/shadow.hpp"

// PatchGuard exception-path blocker.
// Call pg::install() once the host kernel / paging / dpm layers are ready.
namespace pg {
    inline bool install( ) {
        return intercept::install( );
    }
}
