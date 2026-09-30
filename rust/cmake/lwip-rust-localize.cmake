# Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

# cmake -DNM=... -DLINKER=... -DOBJCOPY=... -DARCHIVE=liblwip.a -DOUTPUT=lwip_rust.o -P <this>
#
# Turns the lwip crate's staticlib into one relocatable object that exports only the
# lwIP C symbols the crate defines: the unmangled globals of the crate's own members.
# Everything else in the archive is linked in only as far as those symbols need it, then
# made local, so the C stack keeps binding to its own C library and libgcc.
#
# The Rust code's C library calls, including the memcpy and memmove the compiler emits,
# go to rivet-libc: its members are linked in whole, and their strong definitions
# win over the weak ones the compiler builtins carry.

foreach(var NM LINKER OBJCOPY ARCHIVE OUTPUT)
    if(NOT ${var})
        message(FATAL_ERROR "lwip-rust-localize: ${var} is not set")
    endif()
endforeach()

execute_process(
    COMMAND "${NM}" -g --defined-only "${ARCHIVE}"
    OUTPUT_VARIABLE listing
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "lwip-rust-localize: ${NM} failed on ${ARCHIVE}")
endif()

# nm prints each member as "<name>:" followed by "<value> <type> <symbol>" lines.
string(REPLACE "\n" ";" lines "${listing}")
set(member "")
set(exports "")
set(libc "")
foreach(line ${lines})
    if(line MATCHES "^(.+):$")
        set(member "${CMAKE_MATCH_1}")
    elseif(line MATCHES "^[0-9a-fA-F]+ [TDRBG] (.+)$")
        set(symbol "${CMAKE_MATCH_1}")
        if(symbol MATCHES "^(_R|_ZN)")
            continue()
        elseif(member MATCHES "^lwip-")
            list(APPEND exports "${symbol}")
        elseif(member MATCHES "^rivet_libc-")
            list(APPEND libc "${symbol}")
        endif()
    endif()
endforeach()
list(REMOVE_DUPLICATES exports)
list(SORT exports)
if(NOT exports)
    message(FATAL_ERROR "lwip-rust-localize: ${ARCHIVE} defines no lwIP symbols")
endif()

set(undefined "")
foreach(symbol ${exports} ${libc})
    list(APPEND undefined -u "${symbol}")
endforeach()
execute_process(
    COMMAND "${LINKER}" -r ${undefined} -o "${OUTPUT}.partial" "${ARCHIVE}"
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "lwip-rust-localize: ${LINKER} -r failed")
endif()

string(REPLACE ";" "\n" export_list "${exports}")
file(WRITE "${OUTPUT}.exports" "${export_list}\n")
execute_process(
    COMMAND "${OBJCOPY}" "--keep-global-symbols=${OUTPUT}.exports"
        "${OUTPUT}.partial" "${OUTPUT}"
    RESULT_VARIABLE result)
if(result)
    message(FATAL_ERROR "lwip-rust-localize: ${OBJCOPY} failed")
endif()
file(REMOVE "${OUTPUT}.partial")
