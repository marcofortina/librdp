# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT DEFINED LIBRDP_SOURCE_DIR)
    message(FATAL_ERROR "LIBRDP_SOURCE_DIR is required")
endif()
if(NOT DEFINED LIBRDP_BINARY_DIR)
    message(FATAL_ERROR "LIBRDP_BINARY_DIR is required")
endif()
if(NOT DEFINED LIBRDP_C_COMPILER)
    message(FATAL_ERROR "LIBRDP_C_COMPILER is required")
endif()

set(sanitizer_binary_dir "${LIBRDP_BINARY_DIR}/sanitizer-core")
file(REMOVE_RECURSE "${sanitizer_binary_dir}")

set(configure_args
    -S "${LIBRDP_SOURCE_DIR}"
    -B "${sanitizer_binary_dir}"
    -DCMAKE_C_COMPILER=${LIBRDP_C_COMPILER}
    -DLIBRDP_ENABLE_SANITIZERS=ON
    -DLIBRDP_SANITIZERS=address,undefined
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
    -DLIBRDP_WITH_LIBXML2=OFF
    -DLIBRDP_WITH_PIPEWIRE=OFF
    -DLIBRDP_WITH_JPEG=OFF
    -DLIBRDP_WITH_XSHM=OFF
    -DLIBRDP_WITH_XRANDR=OFF
)
if(DEFINED LIBRDP_CMAKE_GENERATOR AND NOT "${LIBRDP_CMAKE_GENERATOR}" STREQUAL "")
    list(APPEND configure_args -G "${LIBRDP_CMAKE_GENERATOR}")
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
    message(FATAL_ERROR "sanitizer core configure failed with ${configure_result}")
endif()

set(build_args --build "${sanitizer_binary_dir}" --target librdp_tests)
if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
    list(APPEND build_args --config "${LIBRDP_BUILD_CONFIG}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" ${build_args}
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "sanitizer core build failed with ${build_result}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env
        "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1"
        "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"
        "${CMAKE_CTEST_COMMAND}" --test-dir "${sanitizer_binary_dir}" -R "^(common|core|protocol|transport)$" --output-on-failure
    RESULT_VARIABLE test_result
)
if(NOT test_result EQUAL 0)
    message(FATAL_ERROR "sanitizer core test failed with ${test_result}")
endif()
