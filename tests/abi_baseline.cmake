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
if(NOT DEFINED LIBRDP_PYTHON_EXECUTABLE)
    message(FATAL_ERROR "LIBRDP_PYTHON_EXECUTABLE is required")
endif()

set(abi_binary_dir "${LIBRDP_BINARY_DIR}/abi-baseline")
file(REMOVE_RECURSE "${abi_binary_dir}")

set(configure_args
    -S "${LIBRDP_SOURCE_DIR}"
    -B "${abi_binary_dir}"
    -DBUILD_SHARED_LIBS=OFF
    -DLIBRDP_LIBRARY_TYPE=BOTH
    -DLIBRDP_BUILD_TESTS=ON
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
    -DLIBRDP_WITH_CURL=OFF
    -DLIBRDP_WITH_PIPEWIRE=OFF
    -DLIBRDP_WITH_JPEG=OFF
    -DLIBRDP_WITH_XSHM=OFF
    -DLIBRDP_WITH_XRANDR=OFF
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
if(DEFINED LIBRDP_OPENSSL_DIR AND NOT "${LIBRDP_OPENSSL_DIR}" STREQUAL "")
    list(APPEND configure_args
        -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON
        -DOpenSSL_DIR=${LIBRDP_OPENSSL_DIR})
endif()
if(DEFINED LIBRDP_OPENSSL_INCLUDE_DIR AND NOT "${LIBRDP_OPENSSL_INCLUDE_DIR}" STREQUAL "")
    list(APPEND configure_args
        -DOPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}
        -DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR})
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" ${configure_args}
    RESULT_VARIABLE configure_result
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "ABI baseline configure failed with ${configure_result}")
endif()

set(build_args --build "${abi_binary_dir}" --target librdp_shared test_abi_probe)
if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
    list(APPEND build_args --config "${LIBRDP_BUILD_CONFIG}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" ${build_args}
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "ABI baseline build failed with ${build_result}")
endif()

file(GLOB_RECURSE shared_candidates
    "${abi_binary_dir}/liblibrdp${LIBRDP_SHARED_LIBRARY_SUFFIX}"
    "${abi_binary_dir}/liblibrdp${LIBRDP_SHARED_LIBRARY_SUFFIX}.*"
)
if(NOT shared_candidates)
    message(FATAL_ERROR "unable to find built shared library in ${abi_binary_dir}")
endif()
list(GET shared_candidates 0 shared_library)

execute_process(
    COMMAND "${LIBRDP_PYTHON_EXECUTABLE}"
        "${LIBRDP_SOURCE_DIR}/scripts/check-abi-baseline.py"
        "--baseline" "${LIBRDP_SOURCE_DIR}/tests/abi_baseline.json"
        "--library" "${shared_library}"
        "--probe" "${abi_binary_dir}/test_abi_probe"
    RESULT_VARIABLE abi_result
)
if(NOT abi_result EQUAL 0)
    message(FATAL_ERROR "ABI baseline validation failed with ${abi_result}")
endif()
