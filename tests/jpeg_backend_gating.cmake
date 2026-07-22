# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT DEFINED LIBRDP_SOURCE_DIR OR NOT DEFINED LIBRDP_BINARY_DIR)
    message(FATAL_ERROR "LIBRDP_SOURCE_DIR and LIBRDP_BINARY_DIR are required")
endif()

set(work_dir "${LIBRDP_BINARY_DIR}/jpeg-backend-gating")
set(include_dir "${work_dir}/include")
set(pkgconfig_dir "${work_dir}/pkgconfig")
file(REMOVE_RECURSE "${work_dir}")
file(MAKE_DIRECTORY "${include_dir}" "${pkgconfig_dir}")
file(WRITE "${include_dir}/jpeglib.h"
    "#ifndef TEST_LEGACY_JPEGLIB_H\n"
    "#define TEST_LEGACY_JPEGLIB_H\n"
    "struct jpeg_decompress_struct { int unused; };\n"
    "#endif\n")
file(WRITE "${pkgconfig_dir}/libjpeg.pc"
    "Name: legacy-libjpeg\n"
    "Description: libjpeg fixture without an in-memory source manager\n"
    "Version: 6.0\n"
    "Cflags: -I${include_dir}\n"
    "Libs:\n")

set(configure_args
    -S "${LIBRDP_SOURCE_DIR}"
    -DLIBRDP_BUILD_TESTS=OFF
    -DLIBRDP_BUILD_EXAMPLES=OFF
    -DLIBRDP_BUILD_VIEWER=OFF
    -DLIBRDP_BUILD_SERVER=OFF
    -DLIBRDP_BUILD_ADMIN=OFF
    -DLIBRDP_BUILD_WORKSPACE=OFF
)
if(DEFINED LIBRDP_CMAKE_GENERATOR AND
   NOT "${LIBRDP_CMAKE_GENERATOR}" STREQUAL "")
    list(APPEND configure_args -G "${LIBRDP_CMAKE_GENERATOR}")
endif()
if(DEFINED LIBRDP_C_COMPILER AND
   NOT "${LIBRDP_C_COMPILER}" STREQUAL "")
    list(APPEND configure_args
        -DCMAKE_C_COMPILER=${LIBRDP_C_COMPILER})
endif()
if(DEFINED LIBRDP_BUILD_TYPE AND
   NOT "${LIBRDP_BUILD_TYPE}" STREQUAL "")
    list(APPEND configure_args
        -DCMAKE_BUILD_TYPE=${LIBRDP_BUILD_TYPE})
endif()
if(DEFINED LIBRDP_OPENSSL_DIR AND
   NOT "${LIBRDP_OPENSSL_DIR}" STREQUAL "")
    list(APPEND configure_args
        -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON
        -DOpenSSL_DIR=${LIBRDP_OPENSSL_DIR})
endif()
if(DEFINED LIBRDP_OPENSSL_ROOT_DIR AND
   NOT "${LIBRDP_OPENSSL_ROOT_DIR}" STREQUAL "")
    list(APPEND configure_args
        -DOPENSSL_ROOT_DIR=${LIBRDP_OPENSSL_ROOT_DIR})
endif()
if(DEFINED LIBRDP_OPENSSL_INCLUDE_DIR AND
   NOT "${LIBRDP_OPENSSL_INCLUDE_DIR}" STREQUAL "")
    list(APPEND configure_args
        -DOPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}
        -DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR})
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
        "PKG_CONFIG_PATH=${pkgconfig_dir}"
        "PKG_CONFIG_LIBDIR=${pkgconfig_dir}"
        "${CMAKE_COMMAND}"
        ${configure_args}
        -B "${work_dir}/auto"
        -DLIBRDP_WITH_JPEG=AUTO
    RESULT_VARIABLE auto_result
    OUTPUT_VARIABLE auto_output
    ERROR_VARIABLE auto_error
)
if(NOT auto_result EQUAL 0)
    message(FATAL_ERROR
        "legacy libjpeg AUTO configure failed:\n${auto_output}${auto_error}")
endif()
set(auto_log "${auto_output}${auto_error}")
if(NOT auto_log MATCHES
   "feature name=jpeg requested=AUTO dependency=missing target=librdp compiled=no reason=missing-memory-source")
    message(FATAL_ERROR
        "legacy libjpeg AUTO did not report the expected gating reason")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
        "PKG_CONFIG_PATH=${pkgconfig_dir}"
        "PKG_CONFIG_LIBDIR=${pkgconfig_dir}"
        "${CMAKE_COMMAND}"
        ${configure_args}
        -B "${work_dir}/required"
        -DLIBRDP_WITH_JPEG=ON
    RESULT_VARIABLE required_result
    OUTPUT_VARIABLE required_output
    ERROR_VARIABLE required_error
)
if(required_result EQUAL 0)
    message(FATAL_ERROR "legacy libjpeg ON configure unexpectedly succeeded")
endif()
set(required_log "${required_output}${required_error}")
if(NOT required_log MATCHES
   "LIBRDP_WITH_JPEG=ON requires libjpeg with jpeg_mem_src")
    message(FATAL_ERROR
        "legacy libjpeg ON failed without the expected diagnostic")
endif()
