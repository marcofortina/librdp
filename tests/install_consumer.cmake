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

set(work_dir "${LIBRDP_BINARY_DIR}/install-consumer")
set(producer_build_dir "${work_dir}/producer")
set(consumer_build_dir "${work_dir}/consumer")
set(prefix_dir "${work_dir}/prefix")

file(REMOVE_RECURSE "${work_dir}")
file(MAKE_DIRECTORY "${work_dir}")

set(configure_common_args
    -G "${LIBRDP_CMAKE_GENERATOR}"
    -DCMAKE_C_COMPILER=${LIBRDP_C_COMPILER}
)
if(DEFINED LIBRDP_BUILD_TYPE AND NOT "${LIBRDP_BUILD_TYPE}" STREQUAL "")
    list(APPEND configure_common_args -DCMAKE_BUILD_TYPE=${LIBRDP_BUILD_TYPE})
endif()
if(DEFINED LIBRDP_OPENSSL_DIR AND NOT "${LIBRDP_OPENSSL_DIR}" STREQUAL "")
    list(APPEND configure_common_args
        -DCMAKE_FIND_PACKAGE_PREFER_CONFIG=ON
        -DOpenSSL_DIR=${LIBRDP_OPENSSL_DIR})
endif()
if(DEFINED LIBRDP_OPENSSL_ROOT_DIR AND NOT "${LIBRDP_OPENSSL_ROOT_DIR}" STREQUAL "")
    list(APPEND configure_common_args -DOPENSSL_ROOT_DIR=${LIBRDP_OPENSSL_ROOT_DIR})
endif()
if(DEFINED LIBRDP_OPENSSL_INCLUDE_DIR AND NOT "${LIBRDP_OPENSSL_INCLUDE_DIR}" STREQUAL "")
    list(APPEND configure_common_args
        -DOPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}
        -DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR})
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND}
        -S "${LIBRDP_SOURCE_DIR}"
        -B "${producer_build_dir}"
        ${configure_common_args}
        -DCMAKE_INSTALL_PREFIX=${prefix_dir}
        -DBUILD_SHARED_LIBS=ON
        -DLIBRDP_BUILD_TESTS=OFF
        -DLIBRDP_BUILD_FUZZ=OFF
        -DLIBRDP_BUILD_VIEWER=OFF
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
        -DLIBRDP_WITH_CAIRO=OFF
        -DLIBRDP_WITH_QUARTZ=OFF
        -DLIBRDP_WITH_PNG=OFF
        -DLIBRDP_WITH_PIPEWIRE=OFF
        -DLIBRDP_WITH_JPEG=OFF
        -DLIBRDP_WITH_XSHM=OFF
        -DLIBRDP_WITH_XRANDR=OFF
        -DLIBRDP_WITH_FUSE3=OFF
        -DLIBRDP_WITH_PAM=OFF
        -DLIBRDP_WITH_BSDAUTH=OFF
    RESULT_VARIABLE configure_result
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "installed consumer producer configure failed with ${configure_result}")
endif()

set(build_args --build "${producer_build_dir}" --target install)
if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
    list(APPEND build_args --config "${LIBRDP_BUILD_CONFIG}")
endif()
execute_process(
    COMMAND ${CMAKE_COMMAND} ${build_args}
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "installed consumer producer install failed with ${build_result}")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND}
        -S "${LIBRDP_SOURCE_DIR}/tests/install_consumer"
        -B "${consumer_build_dir}"
        ${configure_common_args}
        -DCMAKE_PREFIX_PATH=${prefix_dir}
    RESULT_VARIABLE consumer_configure_result
)
if(NOT consumer_configure_result EQUAL 0)
    message(FATAL_ERROR "installed consumer configure failed with ${consumer_configure_result}")
endif()

set(consumer_build_args --build "${consumer_build_dir}")
if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
    list(APPEND consumer_build_args --config "${LIBRDP_BUILD_CONFIG}")
endif()
execute_process(
    COMMAND ${CMAKE_COMMAND} ${consumer_build_args}
    RESULT_VARIABLE consumer_build_result
)
if(NOT consumer_build_result EQUAL 0)
    message(FATAL_ERROR "installed consumer build failed with ${consumer_build_result}")
endif()

set(consumer_binary "${consumer_build_dir}/librdp-installed-consumer")
if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
    set(configured_consumer_binary "${consumer_build_dir}/${LIBRDP_BUILD_CONFIG}/librdp-installed-consumer")
    if(EXISTS "${configured_consumer_binary}")
        set(consumer_binary "${configured_consumer_binary}")
    endif()
endif()

execute_process(
    COMMAND "${consumer_binary}"
    RESULT_VARIABLE consumer_run_result
)
if(NOT consumer_run_result EQUAL 0)
    message(FATAL_ERROR "installed consumer run failed with ${consumer_run_result}")
endif()
