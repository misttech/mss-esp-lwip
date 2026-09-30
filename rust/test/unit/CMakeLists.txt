# Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

# lwIP's unit tests (test/unit), built as contrib/ports/unix/check builds them, with the
# options in lwipopts.h here and the Rust modules in LWIP_RUST_MODULES (a list, such as
# "def;inet_chksum"; "all" for every ported module; empty for the all-C build) in place
# of their C files.
#
#   cmake -S rust/test/unit -B <dir> -DLWIP_RUST_MODULES="..." \
#       -DLWIP_RUST_TARGET=<host triple>
#
# run.sh builds and runs both and compares their results.

cmake_minimum_required(VERSION 3.13)
project(lwip_rust_unittests C)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
set(LWIP_USE_SANITIZERS true)
include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

# The tests print and compare heap sizes as lwIP's own heap types them, not as the C
# library's allocator does.
list(APPEND LWIP_COMPILER_FLAGS -Wno-format -Wno-sign-compare)
if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    list(APPEND LWIP_COMPILER_FLAGS -Wno-gnu-zero-variadic-macro-arguments)
endif()

# As contrib/ports/unix/check, and ESP_LWIP as its CI sets it; not LWIP_DEBUG, whose
# messages the Rust modules do not port.
set(LWIP_DEFINITIONS -DLWIP_NOASSERT_ON_ERROR -DESP_LWIP=1)
# This directory first: its lwipopts.h includes test/unit's.
set(LWIP_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${LWIP_DIR}/test/unit"
    "${LWIP_DIR}/src/include"
    "${LWIP_CONTRIB_DIR}/"
    "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
    "${LWIP_CONTRIB_DIR}/ports/unix/check"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/test/unit/Filelists.cmake)

include(${LWIP_DIR}/rust/cmake/lwip-rust.cmake)
if(LWIP_RUST_MODULES STREQUAL "all")
    set(LWIP_RUST_MODULES "")
    foreach(entry ${LWIP_RUST_FILES})
        string(REGEX REPLACE "=.*" "" module "${entry}")
        list(APPEND LWIP_RUST_MODULES ${module})
    endforeach()
endif()
lwip_rust_apply(lwipcore ${LWIP_RUST_MODULES})

find_path(LIBCHECK_INCLUDE_DIR check.h REQUIRED)
find_library(LIBCHECK check REQUIRED)
find_library(LIBSUBUNIT subunit)
find_library(LIBM m)

add_executable(lwip_unittests ${LWIP_TESTFILES} ${CMAKE_CURRENT_SOURCE_DIR}/hooks.c)
target_include_directories(lwip_unittests PRIVATE ${LWIP_INCLUDE_DIRS})
target_include_directories(lwip_unittests SYSTEM PRIVATE ${LIBCHECK_INCLUDE_DIR})
target_compile_options(lwip_unittests PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwip_unittests PRIVATE ${LWIP_DEFINITIONS})
target_link_options(lwip_unittests PRIVATE -Wl,--wrap=mem_free)
target_link_libraries(lwip_unittests ${LWIP_SANITIZER_LIBS} lwipallapps lwipcore ${LIBCHECK} ${LIBM})
if(LIBSUBUNIT)
    target_link_libraries(lwip_unittests ${LIBSUBUNIT})
endif()
find_library(LIBUTIL util)
find_library(LIBPTHREAD pthread)
find_library(LIBRT rt)
target_link_libraries(lwip_unittests ${LIBUTIL} ${LIBPTHREAD} ${LIBRT})
