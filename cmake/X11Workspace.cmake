# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_X11_WORKSPACE)
    find_package(X11 REQUIRED)
    add_executable(librdp-x11-workspace
        apps/x11/workspace/main.c
    )
    target_include_directories(librdp-x11-workspace PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${X11_INCLUDE_DIR}
    )
    target_link_libraries(librdp-x11-workspace PRIVATE
        librdp
        ${X11_LIBRARIES}
    )
    librdp_apply_system_definitions(librdp-x11-workspace)
    get_target_property(LIBRDP_X11_WORKSPACE_INCLUDES librdp-x11-workspace INCLUDE_DIRECTORIES)
    foreach(LIBRDP_X11_WORKSPACE_INCLUDE IN LISTS LIBRDP_X11_WORKSPACE_INCLUDES)
        if(NOT IS_ABSOLUTE "${LIBRDP_X11_WORKSPACE_INCLUDE}")
            continue()
        endif()
        file(REAL_PATH "${LIBRDP_X11_WORKSPACE_INCLUDE}" LIBRDP_X11_WORKSPACE_INCLUDE_REAL)
        file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src" LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL)
        string(FIND "${LIBRDP_X11_WORKSPACE_INCLUDE_REAL}/"
            "${LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL}/" LIBRDP_X11_WORKSPACE_PRIVATE_INCLUDE_INDEX)
        if(LIBRDP_X11_WORKSPACE_PRIVATE_INCLUDE_INDEX EQUAL 0)
            message(FATAL_ERROR "librdp-x11-workspace must not include private src headers")
        endif()
    endforeach()
    librdp_apply_warning_options(librdp-x11-workspace)
    librdp_apply_sanitizer_compile_options(librdp-x11-workspace)
    librdp_apply_sanitizer_link_options(librdp-x11-workspace)
    install(TARGETS librdp-x11-workspace
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME x11_workspace_cli COMMAND librdp-x11-workspace --help)
        set_tests_properties(x11_workspace_cli PROPERTIES TIMEOUT 10)
    endif()
endif()
