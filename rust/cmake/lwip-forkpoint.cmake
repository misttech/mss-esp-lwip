# Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

# Reports lwIP's assertions to Forkpoint as properties, from C and Rust alike.
#
#   include(<this file>)
#   lwip_forkpoint_apply(<target>)
#
# When the LWIP_FORKPOINT_HOSTCALL_BASE cache variable holds the address of the board's
# Forkpoint hostcall device (0xa0000000, say), <target>'s C files are compiled with
# LWIP_FORKPOINT, so each LWIP_ASSERT is also a Forkpoint property (src/include/lwip/
# debug.h), and lwip_rust_apply builds the Rust modules with their forkpoint feature, which
# does the same for lwip_assert!. Both report through the Forkpoint SDK in
# third_party/forkpoint-sdk. Without the variable this does nothing.
#
# The SDK also records every assertion in the image's .fpt_catalog section. The image's
# link must keep that section out of target memory; cmake/lwip-forkpoint-catalog.ld does,
# for a GNU ld link that takes it with -T.

set(LWIP_FORKPOINT_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." CACHE INTERNAL "")

function(lwip_forkpoint_apply target)
    if(NOT LWIP_FORKPOINT_HOSTCALL_BASE)
        return()
    endif()
    target_compile_definitions(${target} PRIVATE
        LWIP_FORKPOINT FPT_ENABLE "FPT_HOSTCALL_BASE=${LWIP_FORKPOINT_HOSTCALL_BASE}")
    target_include_directories(${target} PRIVATE
        "${LWIP_FORKPOINT_ROOT}/third_party/forkpoint-sdk/include")
endfunction()
