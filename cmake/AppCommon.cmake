# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

set(LIBRDP_APP_COMMON_REQUIRED 0)
if(LIBRDP_BUILD_TESTS OR
   LIBRDP_BUILD_VIEWER OR
   LIBRDP_BUILD_SERVER OR
   LIBRDP_BUILD_ADMIN OR
   LIBRDP_BUILD_WORKSPACE)
    set(LIBRDP_APP_COMMON_REQUIRED 1)
endif()

if(LIBRDP_APP_COMMON_REQUIRED)
    add_library(librdp_app_common STATIC
        apps/admin/admin_app.c
        apps/admin/admin_options.c
        apps/viewer/client_callbacks.c
        apps/viewer/client_credentials.c
        apps/viewer/client_options.c
        apps/viewer/client_providers.c
        apps/viewer/client_runtime.c
        apps/viewer/client_tls.c
        apps/server/server_clipboard.c
        apps/server/server_clipboard_files.c
        apps/server/server_dirty.c
        apps/server/server_drive.c
        apps/server/server_host.c
        apps/server/server_host_loop.c
        apps/server/server_host_trace.c
        apps/server/server_options.c
        apps/server/server_platform.c
        apps/workspace/workspace_app.c
        apps/workspace/workspace_options.c
    )
    target_include_directories(librdp_app_common
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/common
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(librdp_app_common PUBLIC librdp)
    librdp_apply_system_definitions(librdp_app_common)
    librdp_apply_warning_options(librdp_app_common)
    librdp_apply_sanitizer_compile_options(librdp_app_common)
    librdp_apply_sanitizer_link_options(librdp_app_common)
endif()
