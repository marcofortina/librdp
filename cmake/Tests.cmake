# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND AND
       TARGET librdp-session-broker AND
       TARGET librdp-session-agent AND
       TARGET librdp-session-supervisor)
        set(LIBRDP_APP_INSTALL_LAYOUT_ARGUMENTS)
        foreach(application IN ITEMS
                librdp-admin
                librdp-server
                librdp-viewer
                librdp-workspace)
            if(TARGET ${application})
                list(APPEND
                    LIBRDP_APP_INSTALL_LAYOUT_ARGUMENTS
                    --application ${application})
            endif()
        endforeach()
        add_test(NAME app_install_layout
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/check_app_install_layout.py
                --cmake ${CMAKE_COMMAND}
                --build-dir ${CMAKE_CURRENT_BINARY_DIR}
                --destdir ${CMAKE_CURRENT_BINARY_DIR}/app-install-layout
                --bindir ${CMAKE_INSTALL_FULL_BINDIR}
                --sbindir ${CMAKE_INSTALL_FULL_SBINDIR}
                --libexecdir ${LIBRDP_X11_SESSION_LIBEXEC_DIR}
                --datadir ${CMAKE_INSTALL_FULL_DATADIR}/librdp
                --mandir ${CMAKE_INSTALL_FULL_MANDIR}
                ${LIBRDP_APP_INSTALL_LAYOUT_ARGUMENTS}
                --config $<CONFIG>
        )
        set_tests_properties(app_install_layout PROPERTIES
            RUN_SERIAL TRUE
            TIMEOUT 60
        )
    endif()
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

    add_executable(test_viewer_common tests/test_viewer_common.c)
    target_include_directories(test_viewer_common PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_viewer_common PRIVATE librdp_viewer_common)
    librdp_apply_system_definitions(test_viewer_common)
    librdp_apply_warning_options(test_viewer_common)
    librdp_apply_sanitizer_compile_options(test_viewer_common)
    librdp_apply_sanitizer_link_options(test_viewer_common)

    add_executable(test_admin_workspace tests/test_admin_workspace.c)
    target_include_directories(test_admin_workspace PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/admin
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/workspace
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_admin_workspace PRIVATE
        librdp_admin_common
        librdp_workspace_common
    )
    librdp_apply_system_definitions(test_admin_workspace)
    if(LIBRDP_LIBXML2_FOUND)
        target_compile_definitions(test_admin_workspace PRIVATE
            RDP_HAVE_LIBXML2=1
        )
    endif()
    librdp_apply_warning_options(test_admin_workspace)
    librdp_apply_sanitizer_compile_options(test_admin_workspace)
    librdp_apply_sanitizer_link_options(test_admin_workspace)

    add_executable(test_server_host tests/test_server_host.c)
    target_include_directories(test_server_host PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_server_host PRIVATE librdp_server_common)
    librdp_apply_system_definitions(test_server_host)
    librdp_apply_warning_options(test_server_host)
    librdp_apply_sanitizer_compile_options(test_server_host)
    librdp_apply_sanitizer_link_options(test_server_host)

    add_executable(test_server_host_drive tests/test_server_host_drive.c)
    target_include_directories(test_server_host_drive PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_server_host_drive PRIVATE librdp_server_common)
    librdp_apply_system_definitions(test_server_host_drive)
    librdp_apply_warning_options(test_server_host_drive)
    librdp_apply_sanitizer_compile_options(test_server_host_drive)
    librdp_apply_sanitizer_link_options(test_server_host_drive)

    add_executable(test_server_client_smoke
        tests/test_server_client_smoke.c
        tests/test_server_support.c
    )
    target_include_directories(test_server_client_smoke PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/server
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_link_libraries(test_server_client_smoke PRIVATE
        "$<TARGET_FILE:librdp_server_common>"
        "$<TARGET_FILE:librdp_viewer_common>"
    )
    add_dependencies(test_server_client_smoke
        librdp_server_common
        librdp_viewer_common
    )
    librdp_configure_test_executable(test_server_client_smoke)

    add_executable(test_abi_probe tests/abi_probe.c)
    target_include_directories(test_abi_probe PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_warning_options(test_abi_probe)
    librdp_apply_sanitizer_compile_options(test_abi_probe)
    librdp_apply_sanitizer_link_options(test_abi_probe)

    add_dependencies(librdp_tests
        test_common
        test_core
        test_protocol
        test_transport
        test_server
        test_interop_smoke
        test_optional_backend_probe
        test_viewer_common
        test_admin_workspace
        test_server_host
        test_server_host_drive
        test_server_client_smoke
        test_abi_probe
    )
    foreach(LIBRDP_NATIVE_TEST_TARGET IN ITEMS
        test_x11_viewer_render
        test_x11_viewer_audio
        test_x11_viewer_camera
        test_x11_viewer_keyboard
        test_x11_viewer_clipboard
        test_x11_viewer_display
        test_x11_viewer_backends
        test_x11_viewer_cli
        test_cocoa_media
        test_cocoa_server_cli
        test_cocoa_server_input
        test_cocoa_server_capture
        test_cocoa_server_permission
        test_cocoa_server_clipboard
    )
        if(TARGET ${LIBRDP_NATIVE_TEST_TARGET})
            add_dependencies(librdp_tests ${LIBRDP_NATIVE_TEST_TARGET})
        endif()
    endforeach()

    add_test(NAME common COMMAND test_common)
    add_test(NAME core COMMAND test_core)
    add_test(NAME core_settings_session_error_metrics COMMAND test_core settings)
    add_test(NAME core_connect_timeout COMMAND test_core timeouts)
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
    add_test(NAME server_drive_metadata COMMAND test_server drive-metadata)
    add_test(NAME server_graphics COMMAND test_server graphics)
    add_test(NAME server_runtime COMMAND test_server runtime)
    add_test(NAME smoke_server_standard COMMAND test_server smoke-standard)
    add_test(NAME smoke_server_tls COMMAND test_server smoke-tls)
    add_test(NAME smoke_server_nla COMMAND test_server smoke-nla)
    add_test(NAME smoke_gateway COMMAND test_transport smoke-gateway)
    add_test(NAME smoke_workspace COMMAND test_core smoke-workspace)
    add_test(NAME smoke_admin COMMAND test_core smoke-admin)
    add_test(NAME interop_smoke COMMAND test_interop_smoke)
    add_test(NAME viewer_common COMMAND test_viewer_common)
    add_test(NAME admin_workspace COMMAND test_admin_workspace)
    add_test(NAME server_host COMMAND test_server_host)
    add_test(NAME server_host_drive COMMAND test_server_host_drive)
    add_test(NAME server_client_smoke_standard
        COMMAND test_server_client_smoke standard)
    add_test(NAME server_client_smoke_tls
        COMMAND test_server_client_smoke tls)
    add_test(NAME server_client_smoke_nla
             COMMAND test_server_client_smoke nla)
    add_test(NAME server_client_smoke_nla_invalid
             COMMAND test_server_client_smoke nla-invalid)
    add_test(NAME server_client_smoke_nla_expired
             COMMAND test_server_client_smoke nla-expired)
    add_test(NAME server_client_smoke_nla_locked
             COMMAND test_server_client_smoke nla-locked)
    set_tests_properties(
        common
        transport
        viewer_common
        admin_workspace
        server_host
        server_host_drive
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        server_client_smoke_standard
        server_client_smoke_tls
        server_client_smoke_nla
        server_client_smoke_nla_invalid
        server_client_smoke_nla_expired
        server_client_smoke_nla_locked
        PROPERTIES TIMEOUT 60
    )
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
        server_drive_metadata
        server_graphics
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        core
        core_settings_session_error_metrics
        core_connect_timeout
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
        add_test(NAME application_public_includes
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-app-public-includes.py)
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
            application_public_includes
            examples_docs
            docs
            PROPERTIES TIMEOUT 60
        )
        add_test(NAME sbom_generation
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                "-DLIBRDP_TEST_BUILD_ADMIN=${LIBRDP_BUILD_ADMIN}"
                "-DLIBRDP_TEST_BUILD_SERVER=${LIBRDP_BUILD_SERVER}"
                "-DLIBRDP_TEST_BUILD_VIEWER=${LIBRDP_BUILD_VIEWER}"
                "-DLIBRDP_TEST_BUILD_WORKSPACE=${LIBRDP_BUILD_WORKSPACE}"
                "-DLIBRDP_TEST_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sbom_generation.cmake)
        set_tests_properties(sbom_generation PROPERTIES TIMEOUT 120)
        if(DOXYGEN_FOUND)
            add_test(NAME doxygen_public_headers
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-doxygen.py)
            set_tests_properties(doxygen_public_headers PROPERTIES TIMEOUT 180)
        endif()
    endif()
endif()
