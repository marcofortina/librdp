# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(LIBRDP_BUILD_EXAMPLES)
    function(add_librdp_example name source)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE librdp)
        librdp_apply_warning_options(${name})
        librdp_apply_sanitizer_compile_options(${name})
        librdp_apply_sanitizer_link_options(${name})
    endfunction()

    add_librdp_example(librdp-example-minimal-session examples/minimal_session.c)
    add_librdp_example(librdp-example-surface-blit examples/surface_blit.c)
    add_librdp_example(librdp-example-input-events examples/input_events.c)
    add_librdp_example(librdp-example-event-loop-pollfds examples/event_loop_pollfds.c)
    add_librdp_example(librdp-example-clipboard-data examples/clipboard_data.c)
    add_librdp_example(librdp-example-dynamic-channels examples/dynamic_channels.c)
    add_librdp_example(librdp-example-device-redirection examples/device_redirection.c)
    add_librdp_example(librdp-example-media-devices examples/media_devices.c)
    add_librdp_example(librdp-example-trace-tls-policy examples/trace_tls_policy.c)
    add_librdp_example(librdp-example-workspace-list examples/workspace_list.c)
endif()
