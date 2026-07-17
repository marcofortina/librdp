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
if(NOT DEFINED LIBRDP_SHARED_LIBRARY_SUFFIX)
    message(FATAL_ERROR "LIBRDP_SHARED_LIBRARY_SUFFIX is required")
endif()
if(NOT DEFINED LIBRDP_STATIC_LIBRARY_SUFFIX)
    message(FATAL_ERROR "LIBRDP_STATIC_LIBRARY_SUFFIX is required")
endif()

set(work_dir "${LIBRDP_BINARY_DIR}/library-type-selection")
file(REMOVE_RECURSE "${work_dir}")

set(common_configure_args
    -S "${LIBRDP_SOURCE_DIR}"
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
    -DLIBRDP_WITH_CURL=OFF
    -DLIBRDP_WITH_LIBXML2=OFF
    -DLIBRDP_WITH_PNG=OFF
    -DLIBRDP_WITH_PIPEWIRE=OFF
    -DLIBRDP_WITH_JPEG=OFF
    -DLIBRDP_WITH_XSHM=OFF
    -DLIBRDP_WITH_XRANDR=OFF
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
if(DEFINED LIBRDP_OPENSSL_ROOT_DIR AND NOT "${LIBRDP_OPENSSL_ROOT_DIR}" STREQUAL "")
    list(APPEND common_configure_args -DOPENSSL_ROOT_DIR=${LIBRDP_OPENSSL_ROOT_DIR})
endif()
if(DEFINED LIBRDP_OPENSSL_INCLUDE_DIR AND NOT "${LIBRDP_OPENSSL_INCLUDE_DIR}" STREQUAL "")
    list(APPEND common_configure_args
        -DOPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}
        -DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR})
endif()

function(librdp_run_library_type_case name library_type build_shared expect_static expect_shared)
    set(case_dir "${work_dir}/${name}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            ${common_configure_args}
            -B "${case_dir}"
            -DLIBRDP_LIBRARY_TYPE=${library_type}
            -DBUILD_SHARED_LIBS=${build_shared}
        RESULT_VARIABLE configure_result
    )
    if(NOT configure_result EQUAL 0)
        message(FATAL_ERROR "${name} configure failed with ${configure_result}")
    endif()

    set(build_args --build "${case_dir}")
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

    file(GLOB static_outputs "${case_dir}/liblibrdp${LIBRDP_STATIC_LIBRARY_SUFFIX}")
    file(GLOB shared_outputs
        "${case_dir}/liblibrdp${LIBRDP_SHARED_LIBRARY_SUFFIX}"
        "${case_dir}/liblibrdp${LIBRDP_SHARED_LIBRARY_SUFFIX}.*"
    )

    if(expect_static AND NOT static_outputs)
        message(FATAL_ERROR "${name} did not produce a static library")
    endif()
    if(NOT expect_static AND static_outputs)
        message(FATAL_ERROR "${name} unexpectedly produced a static library")
    endif()
    if(expect_shared AND NOT shared_outputs)
        message(FATAL_ERROR "${name} did not produce a shared library")
    endif()
    if(NOT expect_shared AND shared_outputs)
        message(FATAL_ERROR "${name} unexpectedly produced a shared library")
    endif()
endfunction()

librdp_run_library_type_case(static-only STATIC OFF TRUE FALSE)
librdp_run_library_type_case(shared-only SHARED OFF FALSE TRUE)
librdp_run_library_type_case(both-static-primary BOTH OFF TRUE TRUE)
librdp_run_library_type_case(both-shared-primary BOTH ON TRUE TRUE)
