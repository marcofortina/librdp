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
    if(DEFINED OPENSSL_ROOT_DIR AND NOT "${OPENSSL_ROOT_DIR}" STREQUAL "")
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}"
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
        if(LIBRDP_LIBXML2_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_LIBXML2=1)
        endif()
        if(LIBRDP_CAIRO_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_CAIRO=1)
        endif()
        if(LIBRDP_PNG_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_PNG=1)
        endif()
        if(LIBRDP_JPEG_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_JPEG=1)
        endif()
        if(LIBRDP_QUARTZ_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_QUARTZ=1)
        endif()
    endfunction()

    function(librdp_configure_test_executable target)
        librdp_configure_test_compile(${target})
        librdp_link_internal_runtime(${target})
        librdp_apply_sanitizer_link_options(${target})
    endfunction()

    add_library(test_core_units OBJECT
        tests/test_core.c
        tests/test_core_channels.c
        tests/test_core_common.c
        tests/test_core_enterprise.c
        tests/test_core_features.c
        tests/test_core_graphics.c
        tests/test_core_licensing.c
        tests/test_core_settings.c
        tests/test_core_storage.c
        tests/test_core_support.c
    )
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
        tests/test_protocol_activation.c
        tests/test_protocol_authentication.c
        tests/test_protocol_channels.c
        tests/test_protocol_clipboard.c
        tests/test_protocol_codecs.c
        tests/test_protocol_core.c
        tests/test_protocol_devices.c
        tests/test_protocol_graphics.c
        tests/test_protocol_graphics_pipeline.c
        tests/test_protocol_interaction.c
        tests/test_protocol_security.c
        tests/test_protocol_transport.c
        tests/test_protocol_updates.c
    )
    target_compile_definitions(test_protocol PRIVATE LIBRDP_TEST_PROTOCOL_MAIN)
    librdp_configure_test_executable(test_protocol)

    add_executable(test_transport tests/test_transport.c)
    target_compile_definitions(test_transport PRIVATE LIBRDP_TEST_TRANSPORT_MAIN)
    librdp_configure_test_executable(test_transport)

    add_executable(test_server
        tests/test_server.c
        tests/test_server_config.c
        tests/test_server_features.c
        tests/test_server_focused.c
        tests/test_server_runtime.c
        tests/test_server_security.c
        tests/test_server_support.c
    )
    librdp_configure_test_executable(test_server)

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

    add_executable(test_app_client tests/test_app_client.c)
    target_include_directories(test_app_client PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_app_client PRIVATE librdp_app_common)
    librdp_apply_system_definitions(test_app_client)
    librdp_apply_warning_options(test_app_client)
    librdp_apply_sanitizer_compile_options(test_app_client)
    librdp_apply_sanitizer_link_options(test_app_client)

    add_executable(test_app_policy tests/test_app_policy.c)
    target_include_directories(test_app_policy PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_app_policy PRIVATE librdp_app_common)
    librdp_apply_system_definitions(test_app_policy)
    librdp_apply_warning_options(test_app_policy)
    librdp_apply_sanitizer_compile_options(test_app_policy)
    librdp_apply_sanitizer_link_options(test_app_policy)

    add_executable(test_app_server tests/test_app_server.c)
    target_include_directories(test_app_server PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_app_server PRIVATE librdp_app_common)
    librdp_apply_system_definitions(test_app_server)
    librdp_apply_warning_options(test_app_server)
    librdp_apply_sanitizer_compile_options(test_app_server)
    librdp_apply_sanitizer_link_options(test_app_server)

    add_executable(test_app_server_drive tests/test_app_server_drive.c)
    target_include_directories(test_app_server_drive PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_app_server_drive PRIVATE librdp_app_common)
    librdp_apply_system_definitions(test_app_server_drive)
    librdp_apply_warning_options(test_app_server_drive)
    librdp_apply_sanitizer_compile_options(test_app_server_drive)
    librdp_apply_sanitizer_link_options(test_app_server_drive)

    add_executable(test_viewer_backends
        tests/test_viewer_backends.c
        apps/x11/viewer/camera_v4l2.c
        apps/x11/viewer/device_backends.c
        apps/x11/viewer/viewer_trace.c
    )
    target_include_directories(test_viewer_backends PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
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
        apps/x11/viewer/viewer_cli.c
        apps/x11/viewer/viewer_trace.c
    )
    target_include_directories(test_viewer_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_system_definitions(test_viewer_cli)
    target_link_libraries(test_viewer_cli PRIVATE librdp_app_common)
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
        DEPENDS test_common test_core test_protocol test_transport test_server test_interop_smoke test_optional_backend_probe test_app_client test_app_policy test_app_server test_app_server_drive test_viewer_backends test_viewer_cli test_abi_probe
    )

    add_test(NAME common COMMAND test_common)
    add_test(NAME core COMMAND test_core)
    add_test(NAME core_settings_session_error_metrics COMMAND test_core settings)
    add_test(NAME core_features COMMAND test_core features)
    add_test(NAME core_channels COMMAND test_core channels)
    add_test(NAME core_storage_devices COMMAND test_core storage)
    add_test(NAME core_graphics COMMAND test_core graphics)
    add_test(NAME core_licensing COMMAND test_core licensing)
    add_test(NAME core_workspace_admin COMMAND test_core enterprise)
    add_test(NAME protocol COMMAND test_protocol)
    add_test(NAME protocol_core COMMAND test_protocol core)
    add_test(NAME protocol_channels COMMAND test_protocol channels)
    add_test(NAME protocol_updates COMMAND test_protocol updates)
    add_test(NAME protocol_codecs COMMAND test_protocol codecs)
    add_test(NAME protocol_activation COMMAND test_protocol activation)
    add_test(NAME protocol_security COMMAND test_protocol security)
    add_test(NAME protocol_interaction COMMAND test_protocol interaction)
    add_test(NAME protocol_graphics COMMAND test_protocol graphics)
    add_test(NAME protocol_graphics_pipeline COMMAND test_protocol graphics-pipeline)
    add_test(NAME protocol_clipboard COMMAND test_protocol clipboard)
    add_test(NAME protocol_authentication COMMAND test_protocol authentication)
    add_test(NAME protocol_devices COMMAND test_protocol devices)
    add_test(NAME protocol_transport COMMAND test_protocol transport)
    add_test(NAME transport COMMAND test_transport)
    add_test(NAME server COMMAND test_server)
    add_test(NAME server_config COMMAND test_server config)
    add_test(NAME server_feature_status COMMAND test_server features)
    add_test(NAME server_security COMMAND test_server security)
    add_test(NAME server_lifecycle COMMAND test_server lifecycle)
    add_test(NAME server_channels COMMAND test_server channels)
    add_test(NAME server_graphics COMMAND test_server graphics)
    add_test(NAME server_runtime COMMAND test_server runtime)
    add_test(NAME smoke_server_standard COMMAND test_server smoke-standard)
    add_test(NAME smoke_server_tls COMMAND test_server smoke-tls)
    add_test(NAME smoke_server_nla COMMAND test_server smoke-nla)
    add_test(NAME smoke_gateway COMMAND test_transport smoke-gateway)
    add_test(NAME smoke_workspace COMMAND test_core smoke-workspace)
    add_test(NAME smoke_admin COMMAND test_core smoke-admin)
    add_test(NAME interop_smoke COMMAND test_interop_smoke)
    add_test(NAME app_client COMMAND test_app_client)
    add_test(NAME app_policy COMMAND test_app_policy)
    add_test(NAME app_server COMMAND test_app_server)
    add_test(NAME app_server_drive COMMAND test_app_server_drive)
    add_test(NAME viewer_backends COMMAND test_viewer_backends)
    add_test(NAME viewer_cli COMMAND test_viewer_cli)
    set_tests_properties(common transport app_client app_policy app_server app_server_drive PROPERTIES TIMEOUT 30)
    set_tests_properties(
        server
        server_security
        server_runtime
        smoke_server_standard
        smoke_server_tls
        smoke_server_nla
        PROPERTIES TIMEOUT 60
    )
    set_tests_properties(
        server_config
        server_feature_status
        server_lifecycle
        server_channels
        server_graphics
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        core
        core_settings_session_error_metrics
        core_channels
        core_storage_devices
        core_graphics
        core_licensing
        core_workspace_admin
        PROPERTIES TIMEOUT 60
    )
    set_tests_properties(core_features PROPERTIES TIMEOUT 30)
    set_tests_properties(
        protocol
        protocol_codecs
        protocol_channels
        protocol_security
        protocol_graphics
        protocol_graphics_pipeline
        PROPERTIES TIMEOUT 90
    )
    set_tests_properties(
        protocol_core
        protocol_updates
        protocol_activation
        protocol_interaction
        protocol_clipboard
        protocol_authentication
        protocol_devices
        protocol_transport
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        smoke_gateway
        smoke_workspace
        smoke_admin
        PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77
    )
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
    set_tests_properties(core_optional_backends_off PROPERTIES TIMEOUT 300)
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
    set_tests_properties(shared_symbol_visibility PROPERTIES TIMEOUT 300)
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
    set_tests_properties(library_type_selection PROPERTIES TIMEOUT 300)
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
        set_tests_properties(abi_baseline PROPERTIES TIMEOUT 300)
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
    set_tests_properties(installed_public_api_consumer PROPERTIES TIMEOUT 300)
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
        set_tests_properties(sanitizer_core PROPERTIES TIMEOUT 300)
    endif()
    if(Python3_Interpreter_FOUND)
        add_test(NAME license_headers
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-license-headers.py ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(license_headers PROPERTIES
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            TIMEOUT 60
        )
        add_test(NAME license_archive_fallback
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/license_archive_fallback.cmake)
        set_tests_properties(license_archive_fallback PROPERTIES TIMEOUT 60)
        add_test(NAME public_api_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-public-api-docs.py)
        add_test(NAME source_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-comments.py)
        add_test(NAME source_size_advisory
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-size.py)
        add_test(NAME internal_header_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-internal-header-comments.py)
        add_test(NAME test_fuzz_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-test-fuzz-comments.py)
        add_test(NAME fuzz_corpus
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-fuzz-corpus.py)
        add_test(NAME feature_status_reasons
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-feature-status-reasons.py)
        add_test(NAME viewer_public_includes
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-viewer-public-includes.py)
        add_test(NAME examples_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-examples.py)
        add_test(NAME docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-docs.py)
        set_tests_properties(
            public_api_docs
            source_comments
            source_size_advisory
            internal_header_comments
            test_fuzz_comments
            fuzz_corpus
            feature_status_reasons
            viewer_public_includes
            examples_docs
            docs
            PROPERTIES TIMEOUT 60
        )
        add_test(NAME sbom_generation
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sbom_generation.cmake)
        set_tests_properties(sbom_generation PROPERTIES TIMEOUT 120)
        if(DOXYGEN_FOUND)
            add_test(NAME doxygen_public_headers
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-doxygen.py)
            set_tests_properties(doxygen_public_headers PROPERTIES TIMEOUT 180)
        endif()
    endif()
endif()
