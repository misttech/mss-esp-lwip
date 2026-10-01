# Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

# ESP-IDF's lwip component, built from this lwIP tree, with the Rust modules named in the
# LWIP_RUST_MODULES cache variable (a list, such as "def;inet_chksum") in place of their C
# files.
#
# Use it as a component directory named lwip that overrides ESP-IDF's, for instance
# through EXTRA_COMPONENT_DIRS, holding:
#
#   CMakeLists.txt  this file
#   lwip            this lwIP tree (the directory with src/ and rust/)
#   apps include port Kconfig linker.lf sdkconfig.rename
#                   ESP-IDF's components/lwip entries of the same names
#
# ESP-IDF's own CMakeLists.txt then builds the component unchanged, with every relative
# path resolving in this directory, and lwip_rust_apply swaps the modules afterwards.

include("${IDF_PATH}/components/lwip/CMakeLists.txt")

# During ESP-IDF's early expansion, component files only declare requirements.
if(NOT CMAKE_BUILD_EARLY_EXPANSION AND CONFIG_LWIP_ENABLE)
    # ESP-IDF's file names lwIP's headers in its own lwip tree, while the sources resolve
    # here. Compile this tree's sources, and every component that includes lwIP, against
    # this tree's headers.
    file(REAL_PATH "${IDF_PATH}/components/lwip/lwip/src/include" idf_headers)
    foreach(property INCLUDE_DIRECTORIES INTERFACE_INCLUDE_DIRECTORIES)
        get_target_property(dirs ${COMPONENT_LIB} ${property})
        set(replaced "")
        foreach(dir ${dirs})
            file(REAL_PATH "${dir}" real)
            if(real STREQUAL idf_headers)
                set(dir "${CMAKE_CURRENT_LIST_DIR}/lwip/src/include")
            endif()
            list(APPEND replaced "${dir}")
        endforeach()
        if(dirs STREQUAL replaced)
            message(FATAL_ERROR "${property} of ${COMPONENT_LIB} does not name ${idf_headers}")
        endif()
        set_property(TARGET ${COMPONENT_LIB} PROPERTY ${property} ${replaced})
    endforeach()

    include("${CMAKE_CURRENT_LIST_DIR}/lwip/rust/cmake/lwip-rust.cmake")
    lwip_rust_apply(${COMPONENT_LIB} ${LWIP_RUST_MODULES})
endif()
