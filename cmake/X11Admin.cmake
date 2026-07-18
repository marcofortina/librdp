# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_X11_ADMIN)
    find_package(X11 REQUIRED)
    add_executable(librdp-x11-admin
        apps/x11/admin/main.c
    )
    target_include_directories(librdp-x11-admin PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${X11_INCLUDE_DIR}
    )
    target_link_libraries(librdp-x11-admin PRIVATE
        librdp_app_common
        ${X11_LIBRARIES}
    )
    librdp_apply_system_definitions(librdp-x11-admin)
    get_target_property(LIBRDP_X11_ADMIN_INCLUDES librdp-x11-admin INCLUDE_DIRECTORIES)
    foreach(LIBRDP_X11_ADMIN_INCLUDE IN LISTS LIBRDP_X11_ADMIN_INCLUDES)
        if(NOT IS_ABSOLUTE "${LIBRDP_X11_ADMIN_INCLUDE}")
            continue()
        endif()
        file(REAL_PATH "${LIBRDP_X11_ADMIN_INCLUDE}" LIBRDP_X11_ADMIN_INCLUDE_REAL)
        file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src" LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL)
        string(FIND "${LIBRDP_X11_ADMIN_INCLUDE_REAL}/"
            "${LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL}/" LIBRDP_X11_ADMIN_PRIVATE_INCLUDE_INDEX)
        if(LIBRDP_X11_ADMIN_PRIVATE_INCLUDE_INDEX EQUAL 0)
            message(FATAL_ERROR "librdp-x11-admin must not include private src headers")
        endif()
    endforeach()
    librdp_apply_warning_options(librdp-x11-admin)
    librdp_apply_sanitizer_compile_options(librdp-x11-admin)
    librdp_apply_sanitizer_link_options(librdp-x11-admin)
    install(TARGETS librdp-x11-admin
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_test(NAME x11_admin_cli COMMAND librdp-x11-admin --help)
        set_tests_properties(x11_admin_cli PROPERTIES TIMEOUT 10)
    endif()
endif()
