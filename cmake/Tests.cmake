# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter)
    set(LIBRDP_NESTED_CONFIGURE_ARGS)
    if(DEFINED OpenSSL_DIR AND NOT "${OpenSSL_DIR}" STREQUAL "")
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_DIR=${OpenSSL_DIR}"
        )
    endif()
    if(LIBRDP_OPENSSL_INCLUDE_DIR)
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}"
        )
    endif()
    function(librdp_configure_test_compile target)
        target_include_directories(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        librdp_apply_system_definitions(${target})
        librdp_apply_openssl_include_dirs(${target})
        librdp_apply_warning_options(${target})
        librdp_apply_sanitizer_compile_options(${target})
        if(LIBRDP_FFMPEG_AVC_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_FFMPEG_AVC=1)
        endif()
        if(LIBRDP_OPENH264_AVC_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_OPENH264_AVC=1)
        endif()
        if(LIBRDP_LIBUSB_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_LIBUSB=1)
            target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_LIBUSB)
        endif()
        if(LIBRDP_CURL_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_CURL=1)
        endif()
    endfunction()

    function(librdp_configure_test_executable target)
        librdp_configure_test_compile(${target})
        librdp_link_internal_runtime(${target})
        librdp_apply_sanitizer_link_options(${target})
    endfunction()

    add_library(test_core_units OBJECT tests/test_core.c)
    target_compile_definitions(test_core_units PRIVATE LIBRDP_TEST_NO_MAIN)
    librdp_configure_test_compile(test_core_units)

    add_library(test_core_device_units OBJECT tests/test_core_devices.c)
    target_compile_definitions(test_core_device_units PRIVATE LIBRDP_TEST_NO_MAIN)
    librdp_configure_test_compile(test_core_device_units)

    add_executable(test_common
        tests/test_common_main.c
        $<TARGET_OBJECTS:test_core_units>
        $<TARGET_OBJECTS:test_core_device_units>
    )
    librdp_configure_test_executable(test_common)

    add_executable(test_core
        tests/test_core_main.c
        $<TARGET_OBJECTS:test_core_units>
        $<TARGET_OBJECTS:test_core_device_units>
    )
    librdp_configure_test_executable(test_core)

    add_executable(test_protocol
        tests/test_protocol.c
        tests/test_protocol_channels.c
        tests/test_protocol_core.c
        tests/test_protocol_devices.c
        tests/test_protocol_graphics.c
        tests/test_protocol_transport.c
    )
    target_compile_definitions(test_protocol PRIVATE LIBRDP_TEST_PROTOCOL_MAIN)
    librdp_configure_test_executable(test_protocol)

    add_executable(test_transport tests/test_transport.c)
    target_compile_definitions(test_transport PRIVATE LIBRDP_TEST_TRANSPORT_MAIN)
    librdp_configure_test_executable(test_transport)

    add_executable(test_interop_smoke tests/interop_smoke.c)
    target_include_directories(test_interop_smoke PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_interop_smoke PRIVATE librdp)
    librdp_apply_warning_options(test_interop_smoke)
    librdp_apply_sanitizer_compile_options(test_interop_smoke)
    librdp_apply_sanitizer_link_options(test_interop_smoke)

    add_executable(test_optional_backend_probe tests/optional_backend_probe.c)
    librdp_configure_test_executable(test_optional_backend_probe)

    add_executable(test_viewer_backends
        tests/test_viewer_backends.c
        apps/x11-viewer/camera_v4l2.c
        apps/x11-viewer/device_backends.c
        apps/x11-viewer/viewer_trace.c
    )
    target_include_directories(test_viewer_backends PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_system_definitions(test_viewer_backends)
    target_link_libraries(test_viewer_backends PRIVATE librdp)
    librdp_apply_x11_camera_backends(test_viewer_backends)
    librdp_apply_x11_device_backends(test_viewer_backends)
    librdp_apply_warning_options(test_viewer_backends)
    librdp_apply_sanitizer_compile_options(test_viewer_backends)
    librdp_apply_sanitizer_link_options(test_viewer_backends)

    add_executable(test_viewer_cli
        tests/test_viewer_cli.c
        apps/x11-viewer/viewer_cli.c
        apps/x11-viewer/viewer_trace.c
    )
    target_include_directories(test_viewer_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_system_definitions(test_viewer_cli)
    target_link_libraries(test_viewer_cli PRIVATE librdp)
    librdp_apply_warning_options(test_viewer_cli)
    librdp_apply_sanitizer_compile_options(test_viewer_cli)
    librdp_apply_sanitizer_link_options(test_viewer_cli)

    add_executable(test_abi_probe tests/abi_probe.c)
    target_include_directories(test_abi_probe PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_warning_options(test_abi_probe)
    librdp_apply_sanitizer_compile_options(test_abi_probe)
    librdp_apply_sanitizer_link_options(test_abi_probe)

    add_custom_target(librdp_tests
        DEPENDS test_common test_core test_protocol test_transport test_interop_smoke test_optional_backend_probe test_viewer_backends test_viewer_cli test_abi_probe
    )

    add_test(NAME common COMMAND test_common)
    add_test(NAME core COMMAND test_core)
    add_test(NAME protocol COMMAND test_protocol)
    add_test(NAME transport COMMAND test_transport)
    add_test(NAME interop_smoke COMMAND test_interop_smoke)
    add_test(NAME viewer_backends COMMAND test_viewer_backends)
    add_test(NAME viewer_cli COMMAND test_viewer_cli)
    set_tests_properties(common transport PROPERTIES TIMEOUT 30)
    set_tests_properties(core PROPERTIES TIMEOUT 60)
    set_tests_properties(protocol PROPERTIES TIMEOUT 90)
    set_tests_properties(viewer_backends viewer_cli PROPERTIES TIMEOUT 30)
    set_tests_properties(interop_smoke PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77)
    add_test(NAME core_optional_backends_off
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_optional_backends_off.cmake)
    add_test(NAME optional_backend_matrix
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/optional_backend_matrix.cmake)
    set_tests_properties(optional_backend_matrix PROPERTIES TIMEOUT 180)
    add_test(NAME shared_symbol_visibility
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
            "-DLIBRDP_ABI_VERSION=${LIBRDP_ABI_VERSION}"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/shared_symbol_visibility.cmake)
    add_test(NAME library_type_selection
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
            "-DLIBRDP_STATIC_LIBRARY_SUFFIX=${CMAKE_STATIC_LIBRARY_SUFFIX}"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/library_type_selection.cmake)
    if(Python3_Interpreter_FOUND)
        add_test(NAME abi_baseline
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
                "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                ${LIBRDP_NESTED_CONFIGURE_ARGS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/abi_baseline.cmake)
    endif()
    add_test(NAME installed_public_api_consumer
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/install_consumer.cmake)
    if(LIBRDP_SANITIZER_ADDRESS_LINKS AND LIBRDP_SANITIZER_UNDEFINED_LINKS)
        add_test(NAME sanitizer_core
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
                ${LIBRDP_NESTED_CONFIGURE_ARGS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sanitizer_core.cmake)
    endif()
    if(Python3_Interpreter_FOUND)
        add_test(NAME license_headers
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-license-headers.py ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(license_headers PROPERTIES
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        add_test(NAME license_archive_fallback
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/license_archive_fallback.cmake)
        add_test(NAME public_api_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-public-api-docs.py)
        add_test(NAME source_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-comments.py)
        add_test(NAME internal_header_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-internal-header-comments.py)
        add_test(NAME test_fuzz_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-test-fuzz-comments.py)
        add_test(NAME viewer_public_includes
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-viewer-public-includes.py)
        add_test(NAME examples_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-examples.py)
        add_test(NAME docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-docs.py)
        add_test(NAME sbom_generation
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sbom_generation.cmake)
        if(DOXYGEN_FOUND)
            add_test(NAME doxygen_public_headers
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-doxygen.py)
        endif()
    endif()
endif()
