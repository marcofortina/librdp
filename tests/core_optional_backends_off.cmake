# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT DEFINED LIBRDP_SOURCE_DIR)
    message(FATAL_ERROR "LIBRDP_SOURCE_DIR is required")
endif()
if(NOT DEFINED LIBRDP_BINARY_DIR)
    message(FATAL_ERROR "LIBRDP_BINARY_DIR is required")
endif()

set(configure_common_args
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
    -DLIBRDP_WITH_PIPEWIRE=OFF
    -DLIBRDP_WITH_JPEG=OFF
)

if(DEFINED LIBRDP_CMAKE_GENERATOR AND NOT "${LIBRDP_CMAKE_GENERATOR}" STREQUAL "")
    list(APPEND configure_common_args -G "${LIBRDP_CMAKE_GENERATOR}")
endif()
if(DEFINED LIBRDP_C_COMPILER AND NOT "${LIBRDP_C_COMPILER}" STREQUAL "")
    list(APPEND configure_common_args -DCMAKE_C_COMPILER=${LIBRDP_C_COMPILER})
endif()
if(DEFINED LIBRDP_BUILD_TYPE AND NOT "${LIBRDP_BUILD_TYPE}" STREQUAL "")
    list(APPEND configure_common_args -DCMAKE_BUILD_TYPE=${LIBRDP_BUILD_TYPE})
endif()

foreach(shared_mode IN ITEMS OFF ON)
    string(TOLOWER "${shared_mode}" shared_suffix)
    set(optional_off_binary_dir "${LIBRDP_BINARY_DIR}/core-optional-backends-off-${shared_suffix}")
    file(REMOVE_RECURSE "${optional_off_binary_dir}")

    set(configure_args
        -S "${LIBRDP_SOURCE_DIR}"
        -B "${optional_off_binary_dir}"
        -DBUILD_SHARED_LIBS=${shared_mode}
        ${configure_common_args}
    )

    execute_process(
        COMMAND "${CMAKE_COMMAND}" ${configure_args}
        RESULT_VARIABLE configure_result
    )
    if(NOT configure_result EQUAL 0)
        message(FATAL_ERROR "optional backend OFF configure failed for BUILD_SHARED_LIBS=${shared_mode} with ${configure_result}")
    endif()

    set(build_args --build "${optional_off_binary_dir}" --target librdp test_core)
    if(DEFINED LIBRDP_BUILD_CONFIG AND NOT "${LIBRDP_BUILD_CONFIG}" STREQUAL "")
        list(APPEND build_args --config "${LIBRDP_BUILD_CONFIG}")
    endif()

    execute_process(
        COMMAND "${CMAKE_COMMAND}" ${build_args}
        RESULT_VARIABLE build_result
    )
    if(NOT build_result EQUAL 0)
        message(FATAL_ERROR "optional backend OFF build failed for BUILD_SHARED_LIBS=${shared_mode} with ${build_result}")
    endif()
endforeach()
