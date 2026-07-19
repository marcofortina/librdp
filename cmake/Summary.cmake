# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

message(STATUS "librdp feature summary begin")
string(REPLACE ";" "+" LIBRDP_LIBRARY_TARGETS_SUMMARY "${LIBRDP_LIBRARY_TARGETS}")
librdp_summary_line(library "${LIBRDP_LIBRARY_TYPE}" not-applicable "${LIBRDP_LIBRARY_TARGETS_SUMMARY}" yes "primary-${LIBRDP_PRIMARY_LIBRARY_KIND}")
if(LIBRDP_ENABLE_WERROR)
    librdp_summary_line(werror ON not-applicable project-targets yes enabled)
else()
    librdp_summary_line(werror OFF not-applicable project-targets no disabled-by-user)
endif()
if(LIBRDP_ENABLE_SANITIZERS)
    librdp_summary_line(sanitizers ON not-applicable project-targets yes "${LIBRDP_SANITIZER_FLAG_VALUE}")
else()
    librdp_summary_line(sanitizers OFF not-applicable project-targets no disabled-by-user)
endif()
librdp_summary_build_target(tests LIBRDP_BUILD_TESTS librdp_tests)
librdp_summary_build_target(examples LIBRDP_BUILD_EXAMPLES examples)
librdp_summary_build_target(fuzz LIBRDP_BUILD_FUZZ fuzz-targets)
if(LIBRDP_NATIVE_APP_BACKEND STREQUAL "cocoa")
    set(LIBRDP_BUILD_X11_VIEWER_NATIVE OFF)
    set(LIBRDP_BUILD_X11_SERVER_NATIVE OFF)
    set(LIBRDP_BUILD_COCOA_SERVER_NATIVE ${LIBRDP_BUILD_SERVER})
elseif(LIBRDP_NATIVE_APP_BACKEND STREQUAL "x11")
    set(LIBRDP_BUILD_X11_VIEWER_NATIVE ${LIBRDP_BUILD_VIEWER})
    set(LIBRDP_BUILD_X11_SERVER_NATIVE ${LIBRDP_BUILD_SERVER})
    set(LIBRDP_BUILD_COCOA_SERVER_NATIVE OFF)
else()
    set(LIBRDP_BUILD_X11_VIEWER_NATIVE OFF)
    set(LIBRDP_BUILD_X11_SERVER_NATIVE OFF)
    set(LIBRDP_BUILD_COCOA_SERVER_NATIVE OFF)
endif()

foreach(LIBRDP_APP_NAME IN ITEMS admin server viewer workspace)
    string(TOUPPER "${LIBRDP_APP_NAME}" LIBRDP_APP_NAME_UPPER)
    set(LIBRDP_APP_OPTION "LIBRDP_BUILD_${LIBRDP_APP_NAME_UPPER}")
    if(${LIBRDP_APP_OPTION})
        librdp_summary_line(
            "${LIBRDP_APP_NAME}"
            ON
            "backend-${LIBRDP_NATIVE_APP_BACKEND}"
            "librdp-${LIBRDP_APP_NAME}"
            yes
            enabled
        )
    else()
        librdp_summary_line(
            "${LIBRDP_APP_NAME}"
            OFF
            not-searched
            "librdp-${LIBRDP_APP_NAME}"
            no
            disabled-by-user
        )
    endif()
endforeach()
if(DOXYGEN_FOUND)
    librdp_summary_line(docs-api AUTO found docs-api yes enabled)
else()
    librdp_summary_line(docs-api AUTO missing docs-api no dependency-not-found)
endif()
if(LIBRDP_BUILD_X11_VIEWER_NATIVE)
    set(LIBRDP_DEVICE_BACKEND_TARGETS librdp+librdp-viewer)
else()
    set(LIBRDP_DEVICE_BACKEND_TARGETS librdp)
endif()
librdp_summary_optional_backend(ffmpeg-avc LIBRDP_WITH_FFMPEG_AVC LIBRDP_FFMPEG_AVC_FOUND librdp)
librdp_summary_optional_backend(openh264-avc LIBRDP_WITH_OPENH264_AVC LIBRDP_OPENH264_AVC_FOUND librdp)
librdp_summary_optional_backend(pcsc LIBRDP_WITH_PCSC LIBRDP_PCSC_FOUND "${LIBRDP_DEVICE_BACKEND_TARGETS}")
librdp_summary_optional_backend(libusb LIBRDP_WITH_LIBUSB LIBRDP_LIBUSB_FOUND "${LIBRDP_DEVICE_BACKEND_TARGETS}")
librdp_summary_optional_backend(fido2 LIBRDP_WITH_FIDO2 LIBRDP_FIDO2_FOUND "${LIBRDP_DEVICE_BACKEND_TARGETS}")
librdp_summary_optional_backend(cbor LIBRDP_WITH_CBOR LIBRDP_CBOR_FOUND librdp)
librdp_summary_optional_backend(cups LIBRDP_WITH_CUPS LIBRDP_CUPS_FOUND librdp_backend_objects)
librdp_summary_optional_backend(acl LIBRDP_WITH_ACL LIBRDP_ACL_FOUND librdp)
librdp_summary_optional_backend(attr LIBRDP_WITH_ATTR LIBRDP_ATTR_FOUND librdp)
librdp_summary_optional_backend(archive LIBRDP_WITH_ARCHIVE LIBRDP_ARCHIVE_FOUND librdp)
librdp_summary_optional_backend(curl LIBRDP_WITH_CURL LIBRDP_CURL_FOUND librdp)
librdp_summary_optional_backend(libxml2 LIBRDP_WITH_LIBXML2 LIBRDP_LIBXML2_FOUND librdp)
librdp_summary_optional_backend(cairo LIBRDP_WITH_CAIRO LIBRDP_CAIRO_FOUND librdp)
librdp_summary_optional_backend(quartz LIBRDP_WITH_QUARTZ LIBRDP_QUARTZ_FOUND librdp)
librdp_summary_optional_backend(png LIBRDP_WITH_PNG LIBRDP_PNG_FOUND librdp)
librdp_summary_viewer_backend(pipewire LIBRDP_WITH_PIPEWIRE LIBRDP_PIPEWIRE_FOUND)
librdp_summary_optional_backend(jpeg LIBRDP_WITH_JPEG LIBRDP_JPEG_FOUND librdp)
librdp_summary_viewer_backend(xshm LIBRDP_WITH_XSHM LIBRDP_XSHM_FOUND)
librdp_summary_target_backend(
    xshm-server LIBRDP_WITH_XSHM LIBRDP_X11_SERVER_XSHM_FOUND
    LIBRDP_BUILD_X11_SERVER_NATIVE librdp-server
)
librdp_summary_viewer_backend(xrandr LIBRDP_WITH_XRANDR LIBRDP_XRANDR_FOUND)
librdp_summary_target_backend(
    fuse3-x11-server LIBRDP_WITH_FUSE3 LIBRDP_FUSE3_FOUND
    LIBRDP_BUILD_X11_SERVER_NATIVE librdp-server
)
librdp_summary_target_backend(
    fuse3-cocoa-server LIBRDP_WITH_FUSE3 LIBRDP_FUSE3_FOUND
    LIBRDP_BUILD_COCOA_SERVER_NATIVE librdp-server
)
librdp_summary_target_backend(
    pam-managed-server LIBRDP_WITH_PAM LIBRDP_PAM_FOUND
    LIBRDP_BUILD_X11_SERVER_NATIVE librdp-session-supervisor
)
librdp_summary_target_backend(
    bsdauth-managed-server LIBRDP_WITH_BSDAUTH LIBRDP_BSDAUTH_FOUND
    LIBRDP_BUILD_X11_SERVER_NATIVE librdp-session-supervisor
)
message(STATUS "librdp feature summary end")
