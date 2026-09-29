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
    include("${CMAKE_CURRENT_LIST_DIR}/lwip/rust/cmake/lwip-rust.cmake")
    lwip_rust_apply(${COMPONENT_LIB} ${LWIP_RUST_MODULES})
endif()
