# Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

# Links Rust modules into an lwIP library target in place of their C files.
#
#   include(<this file>)
#   lwip_rust_apply(<target> <module>...)
#
# <target> is the library that compiles lwIP's C sources (ESP-IDF's lwip component, for
# instance); each <module> names one ported C file (see LWIP_RUST_FILES below). The
# function:
#
#   1. drops those C files from <target>'s sources;
#   2. compiles cmake/lwip_rust_config.c to assembly with <target>'s compiler, include
#      directories, definitions, and options, so the crate sees the same lwIP
#      configuration;
#   3. builds the lwip crate for LWIP_RUST_TARGET with the modules' features, and turns
#      its staticlib into one relocatable object whose only global symbols are the lwIP C
#      ones the modules define (cmake/lwip-rust-localize.cmake); the Rust runtime and
#      compiler builtins it carries stay local, so no C code binds to them;
#   4. adds that object to <target>.
#
# LWIP_RUST_CARGO names cargo (found on PATH by default), LWIP_RUST_TARGET the Rust target
# (riscv32imafc-unknown-none-elf by default: rv32imafc, ilp32f).

set(LWIP_RUST_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." CACHE INTERNAL "")

# Ported module -> its C file under lwIP's src/.
set(LWIP_RUST_FILES
    "def=core/def.c"
    "inet_chksum=core/inet_chksum.c"
    "ip4_addr=core/ipv4/ip4_addr.c"
    "mem=core/mem.c"
    "memp=core/memp.c"
    "pbuf=core/pbuf.c"
    "netif=core/netif.c"
    "ethernet=netif/ethernet.c"
    "etharp=core/ipv4/etharp.c"
    "ip4=core/ipv4/ip4.c"
    "ip4_frag=core/ipv4/ip4_frag.c"
    "icmp=core/ipv4/icmp.c"
    "udp=core/udp.c")

function(lwip_rust_apply target)
    set(modules ${ARGN})
    if(NOT modules)
        return()
    endif()
    if(NOT LWIP_RUST_CARGO)
        find_program(LWIP_RUST_CARGO cargo REQUIRED)
    endif()
    if(NOT LWIP_RUST_TARGET)
        set(LWIP_RUST_TARGET riscv32imafc-unknown-none-elf)
    endif()
    set(root "${LWIP_RUST_ROOT}")

    # 1. Drop the C files.
    get_target_property(sources ${target} SOURCES)
    set(features "")
    foreach(module ${modules})
        set(file "")
        foreach(entry ${LWIP_RUST_FILES})
            if(entry MATCHES "^${module}=(.*)$")
                set(file "${CMAKE_MATCH_1}")
            endif()
        endforeach()
        if(NOT file)
            message(FATAL_ERROR "lwip_rust_apply: no Rust module '${module}'")
        endif()
        set(before ${sources})
        list(FILTER sources EXCLUDE REGEX "(^|/)src/${file}$")
        if(before STREQUAL sources)
            message(FATAL_ERROR "lwip_rust_apply: ${target} does not compile src/${file}")
        endif()
        list(APPEND features ${module})
    endforeach()
    set_property(TARGET ${target} PROPERTY SOURCES ${sources})
    string(JOIN "," features ${features})

    # 2. The configuration, compiled to assembly as <target> compiles lwIP. A custom command,
    # not a target: every library <target> links (and so a target linking them) can depend
    # back on <target>, which needs the configuration first.
    set(out "${CMAKE_CURRENT_BINARY_DIR}/lwip_rust")
    set(config "${out}/lwip_rust_config.s")
    separate_arguments(c_flags NATIVE_COMMAND "${CMAKE_C_FLAGS}")
    set(includes "$<TARGET_PROPERTY:${target},INCLUDE_DIRECTORIES>")
    get_target_property(links ${target} LINK_LIBRARIES)
    foreach(link ${links})
        if(TARGET "${link}")
            list(APPEND includes "$<TARGET_PROPERTY:${link},INTERFACE_INCLUDE_DIRECTORIES>")
        endif()
    endforeach()
    set(definitions "$<TARGET_PROPERTY:${target},COMPILE_DEFINITIONS>")
    add_custom_command(
        OUTPUT "${config}"
        COMMAND "${CMAKE_C_COMPILER}" ${c_flags}
            "$<$<BOOL:${definitions}>:-D$<JOIN:${definitions},;-D>>"
            "-I$<JOIN:$<REMOVE_DUPLICATES:${includes}>,;-I>"
            "$<TARGET_PROPERTY:${target},COMPILE_OPTIONS>"
            -S "${root}/cmake/lwip_rust_config.c" -o "${config}"
        DEPENDS "${root}/cmake/lwip_rust_config.c"
        COMMENT "Reading the lwIP configuration for Rust"
        COMMAND_EXPAND_LISTS
        VERBATIM)

    # 3. The crate, as one object with only the lwIP symbols global.
    set(object "${out}/lwip_rust.o")
    set(archive "${out}/target/${LWIP_RUST_TARGET}/release/liblwip.a")
    file(GLOB_RECURSE crate_sources CONFIGURE_DEPENDS
        "${root}/lwip/src/*.rs" "${root}/third_party/fp/src/*.rs"
        "${root}/third_party/libc/src/*.rs")
    add_custom_command(
        OUTPUT "${object}"
        COMMAND ${CMAKE_COMMAND} -E env
            "LWIP_RUST_CONFIG=${config}"
            "CARGO_TARGET_DIR=${out}/target"
            "RUSTFLAGS=--remap-path-prefix=${root}=/lwip-rust"
            "${LWIP_RUST_CARGO}" rustc --quiet --locked
            --manifest-path "${root}/lwip/Cargo.toml" --release
            --target ${LWIP_RUST_TARGET} --crate-type staticlib --features "${features}"
        COMMAND ${CMAKE_COMMAND}
            "-DNM=${CMAKE_NM}" "-DLINKER=${CMAKE_LINKER}" "-DOBJCOPY=${CMAKE_OBJCOPY}"
            "-DARCHIVE=${archive}" "-DOUTPUT=${object}"
            -P "${root}/cmake/lwip-rust-localize.cmake"
        DEPENDS "${config}" ${crate_sources}
            "${root}/Cargo.toml" "${root}/Cargo.lock" "${root}/lwip/Cargo.toml"
            "${root}/lwip/build.rs" "${root}/cmake/lwip-rust-localize.cmake"
        COMMENT "Building lwIP Rust modules: ${features}"
        VERBATIM)

    # 4. Into the library, next to the C objects it replaces.
    set_source_files_properties("${object}" PROPERTIES EXTERNAL_OBJECT TRUE GENERATED TRUE)
    target_sources(${target} PRIVATE "${object}")
endfunction()
