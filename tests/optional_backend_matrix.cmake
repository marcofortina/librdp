# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT DEFINED LIBRDP_SOURCE_DIR)
    message(FATAL_ERROR "LIBRDP_SOURCE_DIR is required")
endif()
if(NOT DEFINED LIBRDP_BINARY_DIR)
    message(FATAL_ERROR "LIBRDP_BINARY_DIR is required")
endif()

set(work_dir "${LIBRDP_BINARY_DIR}/optional-backend-matrix")
file(REMOVE_RECURSE "${work_dir}")
file(MAKE_DIRECTORY "${work_dir}")

set(all_backend_off_args
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
    -DLIBRDP_WITH_CURL=OFF
    -DLIBRDP_WITH_LIBXML2=OFF
    -DLIBRDP_WITH_CAIRO=OFF
    -DLIBRDP_WITH_QUARTZ=OFF
    -DLIBRDP_WITH_PIPEWIRE=OFF
    -DLIBRDP_WITH_JPEG=OFF
    -DLIBRDP_WITH_XSHM=OFF
    -DLIBRDP_WITH_XRANDR=OFF
)

set(common_configure_args
    -S "${LIBRDP_SOURCE_DIR}"
    -DLIBRDP_BUILD_TESTS=ON
    -DLIBRDP_BUILD_FUZZ=OFF
    -DLIBRDP_BUILD_X11_VIEWER=OFF
    -DLIBRDP_BUILD_EXAMPLES=OFF
)
if(DEFINED LIBRDP_CMAKE_GENERATOR AND NOT "${LIBRDP_CMAKE_GENERATOR}" STREQUAL "")
    list(APPEND common_configure_args -G "${LIBRDP_CMAKE_GENERATOR}")
endif()
if(DEFINED LIBRDP_C_COMPILER AND NOT "${LIBRDP_C_COMPILER}" STREQUAL "")
    list(APPEND common_configure_args -DCMAKE_C_COMPILER=${LIBRDP_C_COMPILER})
endif()
if(DEFINED LIBRDP_BUILD_TYPE AND NOT "${LIBRDP_BUILD_TYPE}" STREQUAL "")
    list(APPEND common_configure_args -DCMAKE_BUILD_TYPE=${LIBRDP_BUILD_TYPE})
endif()
if(DEFINED LIBRDP_OPENSSL_DIR AND NOT "${LIBRDP_OPENSSL_DIR}" STREQUAL "")
    list(APPEND common_configure_args
        -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON
        -DOpenSSL_DIR=${LIBRDP_OPENSSL_DIR})
endif()
if(DEFINED LIBRDP_OPENSSL_INCLUDE_DIR AND NOT "${LIBRDP_OPENSSL_INCLUDE_DIR}" STREQUAL "")
    list(APPEND common_configure_args
        -DOPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}
        -DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR})
endif()

function(librdp_matrix_build_and_probe name expectation)
    set(case_dir "${work_dir}/${name}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            ${common_configure_args}
            -B "${case_dir}"
            ${ARGN}
        RESULT_VARIABLE configure_result
    )
    if(NOT configure_result EQUAL 0)
        message(FATAL_ERROR "${name} configure failed with ${configure_result}")
    endif()

    set(build_args --build "${case_dir}" --target test_optional_backend_probe)
    if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
        list(APPEND build_args --config "${LIBRDP_BUILD_CONFIG}")
    endif()
    execute_process(
        COMMAND "${CMAKE_COMMAND}" ${build_args}
        RESULT_VARIABLE build_result
    )
    if(NOT build_result EQUAL 0)
        message(FATAL_ERROR "${name} build failed with ${build_result}")
    endif()

    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            "LIBRDP_OPTIONAL_PROBE_EXPECT_AVC=${expectation}"
            "${case_dir}/test_optional_backend_probe"
        RESULT_VARIABLE probe_result
    )
    if(NOT probe_result EQUAL 0)
        message(FATAL_ERROR "${name} probe failed with ${probe_result}")
    endif()
endfunction()

function(librdp_matrix_expect_configure_failure name)
    set(case_dir "${work_dir}/${name}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            ${common_configure_args}
            -B "${case_dir}"
            ${ARGN}
        RESULT_VARIABLE configure_result
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(configure_result EQUAL 0)
        message(FATAL_ERROR "${name} configure unexpectedly succeeded")
    endif()
endfunction()

librdp_matrix_build_and_probe(all-off none ${all_backend_off_args})
librdp_matrix_build_and_probe(auto auto)

find_program(LIBRDP_MATRIX_PKG_CONFIG pkg-config)
set(LIBRDP_MATRIX_OPENH264_FOUND 0)
if(LIBRDP_MATRIX_PKG_CONFIG)
    execute_process(
        COMMAND "${LIBRDP_MATRIX_PKG_CONFIG}" --exists openh264
        RESULT_VARIABLE openh264_result
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(openh264_result EQUAL 0)
        set(LIBRDP_MATRIX_OPENH264_FOUND 1)
    endif()
endif()

if(LIBRDP_MATRIX_OPENH264_FOUND)
    librdp_matrix_build_and_probe(openh264-on openh264
        ${all_backend_off_args}
        -DLIBRDP_WITH_OPENH264_AVC=ON)
else()
    librdp_matrix_expect_configure_failure(openh264-on-missing
        ${all_backend_off_args}
        -DLIBRDP_WITH_OPENH264_AVC=ON)
endif()
