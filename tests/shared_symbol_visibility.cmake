# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT DEFINED LIBRDP_SOURCE_DIR)
    message(FATAL_ERROR "LIBRDP_SOURCE_DIR is required")
endif()
if(NOT DEFINED LIBRDP_BINARY_DIR)
    message(FATAL_ERROR "LIBRDP_BINARY_DIR is required")
endif()
if(NOT DEFINED LIBRDP_SHARED_LIBRARY_SUFFIX)
    message(FATAL_ERROR "LIBRDP_SHARED_LIBRARY_SUFFIX is required")
endif()
if(NOT DEFINED LIBRDP_ABI_VERSION)
    message(FATAL_ERROR "LIBRDP_ABI_VERSION is required")
endif()

set(shared_binary_dir "${LIBRDP_BINARY_DIR}/shared-symbol-visibility")
file(REMOVE_RECURSE "${shared_binary_dir}")

set(configure_args
    -S "${LIBRDP_SOURCE_DIR}"
    -B "${shared_binary_dir}"
    -DBUILD_SHARED_LIBS=OFF
    -DLIBRDP_LIBRARY_TYPE=BOTH
    -DLIBRDP_BUILD_TESTS=OFF
    -DLIBRDP_BUILD_FUZZ=OFF
    -DLIBRDP_BUILD_X11_VIEWER=OFF
    -DLIBRDP_BUILD_EXAMPLES=OFF
    -DLIBRDP_WITH_FFMPEG_AVC=OFF
    -DLIBRDP_WITH_OPENH264_AVC=OFF
    -DLIBRDP_WITH_PCSC=OFF
    -DLIBRDP_WITH_LIBUSB=OFF
    -DLIBRDP_WITH_FIDO2=OFF
    -DLIBRDP_WITH_CBOR=OFF
    -DLIBRDP_WITH_CUPS=OFF
    -DLIBRDP_WITH_ACL=OFF
    -DLIBRDP_WITH_ATTR=OFF
    -DLIBRDP_WITH_ARCHIVE=OFF
    -DLIBRDP_WITH_PIPEWIRE=OFF
    -DLIBRDP_WITH_JPEG=OFF
    -DLIBRDP_WITH_XSHM=OFF
)

if(DEFINED LIBRDP_CMAKE_GENERATOR AND NOT "${LIBRDP_CMAKE_GENERATOR}" STREQUAL "")
    list(APPEND configure_args -G "${LIBRDP_CMAKE_GENERATOR}")
endif()
if(DEFINED LIBRDP_C_COMPILER AND NOT "${LIBRDP_C_COMPILER}" STREQUAL "")
    list(APPEND configure_args -DCMAKE_C_COMPILER=${LIBRDP_C_COMPILER})
endif()
if(DEFINED LIBRDP_BUILD_TYPE AND NOT "${LIBRDP_BUILD_TYPE}" STREQUAL "")
    list(APPEND configure_args -DCMAKE_BUILD_TYPE=${LIBRDP_BUILD_TYPE})
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" ${configure_args}
    RESULT_VARIABLE configure_result
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "shared symbol visibility configure failed with ${configure_result}")
endif()

set(build_args --build "${shared_binary_dir}" --target librdp_shared)
if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
    list(APPEND build_args --config "${LIBRDP_BUILD_CONFIG}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" ${build_args}
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "shared symbol visibility build failed with ${build_result}")
endif()

file(GLOB_RECURSE shared_candidates
    "${shared_binary_dir}/liblibrdp${LIBRDP_SHARED_LIBRARY_SUFFIX}"
    "${shared_binary_dir}/liblibrdp${LIBRDP_SHARED_LIBRARY_SUFFIX}.*"
)
if(NOT shared_candidates)
    message(FATAL_ERROR "unable to find built shared library in ${shared_binary_dir}")
endif()
list(GET shared_candidates 0 shared_library)

set(export_map "${LIBRDP_SOURCE_DIR}/cmake/librdp.exports.map")
file(READ "${export_map}" export_map_text)
string(REGEX MATCHALL "librdp_[A-Za-z0-9_]+" approved_symbols "${export_map_text}")
list(REMOVE_DUPLICATES approved_symbols)

find_program(READELF_EXECUTABLE NAMES readelf)
find_program(NM_EXECUTABLE NAMES nm)

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    if(NOT READELF_EXECUTABLE)
        message(FATAL_ERROR "readelf is required for Linux SONAME checks")
    endif()
    execute_process(
        COMMAND "${READELF_EXECUTABLE}" -d "${shared_library}"
        RESULT_VARIABLE soname_result
        OUTPUT_VARIABLE soname_output
        ERROR_VARIABLE soname_error
    )
    if(NOT soname_result EQUAL 0)
        message(FATAL_ERROR "SONAME inspection failed with ${soname_result}: ${soname_error}")
    endif()
    set(expected_soname "liblibrdp${LIBRDP_SHARED_LIBRARY_SUFFIX}.${LIBRDP_ABI_VERSION}")
    if(NOT soname_output MATCHES "\\(SONAME\\).*\\[${expected_soname}\\]")
        message(FATAL_ERROR "expected SONAME ${expected_soname} was not found")
    endif()
endif()

if(READELF_EXECUTABLE)
    execute_process(
        COMMAND "${READELF_EXECUTABLE}" --dyn-syms --wide "${shared_library}"
        RESULT_VARIABLE symbols_result
        OUTPUT_VARIABLE symbols_output
        ERROR_VARIABLE symbols_error
    )
elseif(NM_EXECUTABLE)
    if(APPLE)
        set(nm_args -gU "${shared_library}")
    else()
        set(nm_args -D --defined-only "${shared_library}")
    endif()
    execute_process(
        COMMAND "${NM_EXECUTABLE}" ${nm_args}
        RESULT_VARIABLE symbols_result
        OUTPUT_VARIABLE symbols_output
        ERROR_VARIABLE symbols_error
    )
else()
    message(FATAL_ERROR "readelf or nm is required for shared symbol visibility checks")
endif()

if(NOT symbols_result EQUAL 0)
    message(FATAL_ERROR "dynamic symbol inspection failed with ${symbols_result}: ${symbols_error}")
endif()

string(REPLACE "\n" ";" symbol_lines "${symbols_output}")
set(exported_public_count 0)
set(bad_symbols "")
foreach(line IN LISTS symbol_lines)
    if(READELF_EXECUTABLE AND (line MATCHES "[ \t]UND[ \t]" OR line MATCHES "^[ \t]*Num:"))
        continue()
    endif()
    if(line MATCHES "[ \t]([_A-Za-z][_A-Za-z0-9]*(\@\@?[^ \t]+)?)$")
        set(symbol "${CMAKE_MATCH_1}")
    else()
        continue()
    endif()
    string(REGEX REPLACE "\@\@?.*$" "" symbol "${symbol}")
    if(symbol MATCHES "^_librdp_")
        string(REGEX REPLACE "^_" "" symbol "${symbol}")
    elseif(symbol MATCHES "^_rdp_")
        string(REGEX REPLACE "^_" "" symbol "${symbol}")
    endif()

    if(symbol MATCHES "^LIBRDP_[0-9]")
        continue()
    endif()
    if(symbol MATCHES "^rdp_")
        list(APPEND bad_symbols "${symbol}")
        continue()
    endif()
    if(symbol MATCHES "^librdp_")
        list(FIND approved_symbols "${symbol}" approved_index)
        if(approved_index EQUAL -1)
            list(APPEND bad_symbols "${symbol}")
        else()
            math(EXPR exported_public_count "${exported_public_count} + 1")
        endif()
        continue()
    endif()
    if(NOT symbol MATCHES "^(_init|_fini|_edata|_end|__bss_start)$")
        list(APPEND bad_symbols "${symbol}")
    endif()
endforeach()

if(bad_symbols)
    list(REMOVE_DUPLICATES bad_symbols)
    string(REPLACE ";" ", " bad_symbols_text "${bad_symbols}")
    message(FATAL_ERROR "unexpected exported dynamic symbols: ${bad_symbols_text}")
endif()
if(exported_public_count EQUAL 0)
    message(FATAL_ERROR "no approved public librdp symbols were exported")
endif()
