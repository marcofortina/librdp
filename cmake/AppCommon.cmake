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
        apps/common/admin_options.c
        apps/common/client_callbacks.c
        apps/common/client_credentials.c
        apps/common/client_options.c
        apps/common/client_providers.c
        apps/common/client_runtime.c
        apps/common/client_tls.c
        apps/common/server_clipboard.c
        apps/common/server_clipboard_files.c
        apps/common/server_dirty.c
        apps/common/server_drive.c
        apps/common/server_host.c
        apps/common/server_host_loop.c
        apps/common/server_host_trace.c
        apps/common/server_options.c
        apps/common/server_platform.c
        apps/common/workspace_options.c
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
