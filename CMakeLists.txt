# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)

project(librdp VERSION 0.1.0 LANGUAGES C)

option(LIBRDP_BUILD_TESTS "Build unit tests" ON)
option(LIBRDP_BUILD_FUZZ "Build fuzz targets" OFF)
option(LIBRDP_BUILD_X11_VIEWER "Build X11 viewer" OFF)
option(LIBRDP_BUILD_EXAMPLES "Build example programs" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(LIBRDP_OPTION_VALUES AUTO ON OFF)

function(librdp_feature_option name description)
    set(${name} "AUTO" CACHE STRING "${description} (AUTO, ON, OFF)")
    set_property(CACHE ${name} PROPERTY STRINGS ${LIBRDP_OPTION_VALUES})
    string(TOUPPER "${${name}}" value)
    list(FIND LIBRDP_OPTION_VALUES "${value}" index)
    if(index EQUAL -1)
        message(FATAL_ERROR "${name} must be AUTO, ON, or OFF")
    endif()
    if(NOT "${${name}}" STREQUAL "${value}")
        set(${name} "${value}" CACHE STRING "${description} (AUTO, ON, OFF)" FORCE)
    endif()
endfunction()

function(librdp_pkg_dependency option prefix)
    set(${prefix}_FOUND 0 PARENT_SCOPE)
    if("${${option}}" STREQUAL "OFF")
        return()
    endif()
    if(NOT PkgConfig_FOUND)
        if("${${option}}" STREQUAL "ON")
            message(FATAL_ERROR "${option}=ON requires pkg-config")
        endif()
        return()
    endif()
    if("${${option}}" STREQUAL "ON")
        pkg_check_modules(${prefix} REQUIRED IMPORTED_TARGET ${ARGN})
    else()
        pkg_check_modules(${prefix} QUIET IMPORTED_TARGET ${ARGN})
    endif()
    set(${prefix}_FOUND "${${prefix}_FOUND}" PARENT_SCOPE)
endfunction()

librdp_feature_option(LIBRDP_WITH_FFMPEG_AVC "Use FFmpeg for AVC decoding")
librdp_feature_option(LIBRDP_WITH_OPENH264_AVC "Use OpenH264 for AVC decoding")
librdp_feature_option(LIBRDP_WITH_PCSC "Use PC/SC smartcard backend")
librdp_feature_option(LIBRDP_WITH_LIBUSB "Use libusb device backend")
librdp_feature_option(LIBRDP_WITH_FIDO2 "Use FIDO2 authenticator backend")
librdp_feature_option(LIBRDP_WITH_CBOR "Use CBOR helpers for WebAuthn data")
librdp_feature_option(LIBRDP_WITH_CUPS "Use CUPS printer backend")
librdp_feature_option(LIBRDP_WITH_ACL "Use POSIX ACL filesystem metadata backend")
librdp_feature_option(LIBRDP_WITH_ATTR "Use extended attribute filesystem metadata backend")
librdp_feature_option(LIBRDP_WITH_ARCHIVE "Use archive-backed print payload support")
librdp_feature_option(LIBRDP_WITH_PIPEWIRE "Use PipeWire audio backend in the X11 viewer")
librdp_feature_option(LIBRDP_WITH_JPEG "Use JPEG camera conversion backend in the X11 viewer")

find_package(OpenSSL 3.0 REQUIRED)
find_package(Iconv REQUIRED)
find_package(Doxygen QUIET)
find_package(PkgConfig QUIET)

librdp_pkg_dependency(LIBRDP_WITH_FFMPEG_AVC LIBRDP_FFMPEG_AVC libavcodec libavutil libswscale)
librdp_pkg_dependency(LIBRDP_WITH_OPENH264_AVC LIBRDP_OPENH264_AVC openh264)
librdp_pkg_dependency(LIBRDP_WITH_PCSC LIBRDP_PCSC libpcsclite)
librdp_pkg_dependency(LIBRDP_WITH_LIBUSB LIBRDP_LIBUSB libusb-1.0)
librdp_pkg_dependency(LIBRDP_WITH_FIDO2 LIBRDP_FIDO2 libfido2)
librdp_pkg_dependency(LIBRDP_WITH_CBOR LIBRDP_CBOR libcbor)
librdp_pkg_dependency(LIBRDP_WITH_ACL LIBRDP_ACL libacl)
librdp_pkg_dependency(LIBRDP_WITH_ATTR LIBRDP_ATTR libattr)
librdp_pkg_dependency(LIBRDP_WITH_ARCHIVE LIBRDP_ARCHIVE libarchive)
librdp_pkg_dependency(LIBRDP_WITH_PIPEWIRE LIBRDP_PIPEWIRE libpipewire-0.3)
librdp_pkg_dependency(LIBRDP_WITH_JPEG LIBRDP_JPEG libjpeg)

set(LIBRDP_CUPS_FOUND 0)
if(NOT "${LIBRDP_WITH_CUPS}" STREQUAL "OFF")
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBRDP_CUPS QUIET IMPORTED_TARGET cups)
    endif()
endif()
if(NOT LIBRDP_CUPS_FOUND AND NOT "${LIBRDP_WITH_CUPS}" STREQUAL "OFF")
    find_path(LIBRDP_CUPS_INCLUDE_DIR NAMES cups/cups.h PATHS
        /usr/local/include
        /usr/include
        /opt/local/include
    )
    find_library(LIBRDP_CUPS_LIBRARY NAMES cups PATHS
        /usr/local/lib
        /usr/lib
        /usr/lib/${CMAKE_LIBRARY_ARCHITECTURE}
        /opt/local/lib
    )
    if(LIBRDP_CUPS_INCLUDE_DIR AND LIBRDP_CUPS_LIBRARY)
        set(LIBRDP_CUPS_FOUND 1)
    endif()
endif()
if("${LIBRDP_WITH_CUPS}" STREQUAL "ON" AND NOT LIBRDP_CUPS_FOUND)
    message(FATAL_ERROR "LIBRDP_WITH_CUPS=ON requires cups")
endif()

add_library(librdp
    src/client/error.c
    src/client/settings.c
    src/client/session.c
    src/channels/audio_format.c
    src/channels/audio_input.c
    src/channels/audio_output.c
    src/channels/auth_redirection.c
    src/channels/composited_remoting.c
    src/channels/core_input.c
    src/channels/device_redirection.c
    src/channels/desktop_composition.c
    src/channels/display_control.c
    src/channels/dynamic_channel.c
    src/channels/echo_channel.c
    src/channels/filesystem_redirection.c
    src/channels/graphics_pipeline.c
    src/channels/input_channel.c
    src/channels/mouse_cursor.c
    src/channels/multiparty.c
    src/channels/port_redirection.c
    src/channels/printer_redirection.c
    src/channels/remote_programs.c
    src/channels/pnp_redirection.c
    src/channels/smartcard_redirection.c
    src/channels/telemetry.c
    src/channels/usb_redirection.c
    src/channels/video_capture.c
    src/channels/video_optimized.c
    src/channels/video_redirection.c
    src/channels/virtual_channel.c
    src/channels/webauthn_channel.c
    src/channels/xps_print.c
    src/clipboard/clipboard.c
    src/common/buffer.c
    src/common/charset.c
    src/common/stream.c
    src/common/trace.c
    src/graphics/avc.c
    src/graphics/bitmap.c
    src/graphics/clearcodec.c
    src/graphics/gdi_orders.c
    src/graphics/gdi_render.c
    src/graphics/nscodec.c
    src/graphics/planar.c
    src/graphics/rfx_codec.c
    src/graphics/rfx_stream.c
    src/graphics/surface.c
    src/graphics/surface_commands.c
    src/input/input.c
    src/licensing/licensing.c
    src/nla/credssp.c
    src/platform/socket.c
    src/protocol/capabilities.c
    src/protocol/bulk.c
    src/protocol/fastpath.c
    src/protocol/gcc.c
    src/protocol/mcs.c
    src/protocol/pointer.c
    src/protocol/session_selection.c
    src/protocol/slowpath.c
    src/protocol/tpkt.c
    src/protocol/x224.c
    src/security/certificate.c
    src/security/security.c
    src/transport/tcp.c
    src/transport/multitransport.c
    src/transport/transport.c
    src/transport/udp_transport.c
)

target_include_directories(librdp
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(librdp PUBLIC _POSIX_C_SOURCE=200809L)
target_link_libraries(librdp PRIVATE OpenSSL::SSL OpenSSL::Crypto Iconv::Iconv)
if(LIBRDP_FFMPEG_AVC_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_FFMPEG_AVC=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_FFMPEG_AVC)
endif()
if(LIBRDP_OPENH264_AVC_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_OPENH264_AVC=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_OPENH264_AVC)
endif()
if(LIBRDP_PCSC_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_PCSC=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_PCSC)
endif()
if(LIBRDP_LIBUSB_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_LIBUSB=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_LIBUSB)
endif()
if(LIBRDP_FIDO2_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_FIDO2=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_FIDO2)
endif()
if(LIBRDP_CBOR_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_CBOR=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_CBOR)
endif()
if(LIBRDP_CUPS_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_CUPS=1)
    if(TARGET PkgConfig::LIBRDP_CUPS)
        target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_CUPS)
    else()
        target_include_directories(librdp PRIVATE ${LIBRDP_CUPS_INCLUDE_DIR})
        target_link_libraries(librdp PRIVATE ${LIBRDP_CUPS_LIBRARY})
    endif()
endif()
if(LIBRDP_ACL_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_ACL=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_ACL)
endif()
if(LIBRDP_ATTR_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_ATTR=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_ATTR)
endif()
if(LIBRDP_ARCHIVE_FOUND)
    target_compile_definitions(librdp PRIVATE RDP_HAVE_ARCHIVE=1)
    target_link_libraries(librdp PRIVATE PkgConfig::LIBRDP_ARCHIVE)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(librdp PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

if(LIBRDP_BUILD_EXAMPLES)
    function(add_librdp_example name source)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE librdp)
        if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
            target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
        endif()
    endfunction()

    add_librdp_example(librdp-example-minimal-session examples/minimal_session.c)
    add_librdp_example(librdp-example-surface-blit examples/surface_blit.c)
    add_librdp_example(librdp-example-input-events examples/input_events.c)
endif()

if(DOXYGEN_FOUND)
    add_custom_target(docs-api
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Build public API reference"
        VERBATIM)
endif()

if(LIBRDP_BUILD_TESTS)
    enable_testing()
    find_package(Python3 COMPONENTS Interpreter)
    add_executable(test_core
        tests/test_core.c
        tests/test_protocol.c
        tests/test_transport.c
    )
    target_include_directories(test_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(test_core PRIVATE librdp OpenSSL::SSL OpenSSL::Crypto)
    if(LIBRDP_FFMPEG_AVC_FOUND)
        target_compile_definitions(test_core PRIVATE RDP_HAVE_FFMPEG_AVC=1)
    endif()
    if(LIBRDP_OPENH264_AVC_FOUND)
        target_compile_definitions(test_core PRIVATE RDP_HAVE_OPENH264_AVC=1)
    endif()
    add_test(NAME core COMMAND test_core)
    if(Python3_Interpreter_FOUND)
        add_test(NAME public_api_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-public-api-docs.py)
        add_test(NAME source_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-comments.py)
        add_test(NAME internal_header_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-internal-header-comments.py)
        add_test(NAME test_fuzz_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-test-fuzz-comments.py)
        add_test(NAME examples_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-examples.py)
        add_test(NAME docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-docs.py)
        if(DOXYGEN_FOUND)
            add_test(NAME doxygen_public_headers
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-doxygen.py)
        endif()
    endif()
endif()

if(LIBRDP_BUILD_FUZZ)
    function(add_librdp_fuzzer name source)
        add_executable(${name} ${source})
        target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(${name} PRIVATE librdp)
        if(LIBRDP_FFMPEG_AVC_FOUND)
            target_compile_definitions(${name} PRIVATE RDP_HAVE_FFMPEG_AVC=1)
        endif()
        if(LIBRDP_OPENH264_AVC_FOUND)
            target_compile_definitions(${name} PRIVATE RDP_HAVE_OPENH264_AVC=1)
        endif()
        if(CMAKE_C_COMPILER_ID MATCHES "Clang")
            target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
            target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
        else()
            target_sources(${name} PRIVATE fuzz/fuzz_main.c)
        endif()
    endfunction()

    add_librdp_fuzzer(fuzz_x224 fuzz/x224_fuzzer.c)
    add_librdp_fuzzer(fuzz_stream fuzz/stream_fuzzer.c)
    add_librdp_fuzzer(fuzz_charset fuzz/charset_fuzzer.c)
    add_librdp_fuzzer(fuzz_session_selection fuzz/session_selection_fuzzer.c)
    add_librdp_fuzzer(fuzz_mcs fuzz/mcs_fuzzer.c)
    add_librdp_fuzzer(fuzz_pointer fuzz/pointer_fuzzer.c)
    add_librdp_fuzzer(fuzz_gcc fuzz/gcc_fuzzer.c)
    add_librdp_fuzzer(fuzz_capabilities fuzz/capabilities_fuzzer.c)
    add_librdp_fuzzer(fuzz_fastpath fuzz/fastpath_fuzzer.c)
    add_librdp_fuzzer(fuzz_slowpath fuzz/slowpath_fuzzer.c)
    add_librdp_fuzzer(fuzz_tpkt fuzz/tpkt_fuzzer.c)
    add_librdp_fuzzer(fuzz_bulk fuzz/bulk_fuzzer.c)
    add_librdp_fuzzer(fuzz_bitmap fuzz/bitmap_fuzzer.c)
    add_librdp_fuzzer(fuzz_virtual_channel fuzz/virtual_channel_fuzzer.c)
    add_librdp_fuzzer(fuzz_dynamic_channel fuzz/dynamic_channel_fuzzer.c)
    add_librdp_fuzzer(fuzz_echo_channel fuzz/echo_channel_fuzzer.c)
    add_librdp_fuzzer(fuzz_audio_format fuzz/audio_format_fuzzer.c)
    add_librdp_fuzzer(fuzz_audio_output fuzz/audio_output_fuzzer.c)
    add_librdp_fuzzer(fuzz_audio_input fuzz/audio_input_fuzzer.c)
    add_librdp_fuzzer(fuzz_composited_remoting fuzz/composited_remoting_fuzzer.c)
    add_librdp_fuzzer(fuzz_display_control fuzz/display_control_fuzzer.c)
    add_librdp_fuzzer(fuzz_device_redirection fuzz/device_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_desktop_composition fuzz/desktop_composition_fuzzer.c)
    add_librdp_fuzzer(fuzz_filesystem_redirection fuzz/filesystem_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_port_redirection fuzz/port_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_printer_redirection fuzz/printer_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_remote_programs fuzz/remote_programs_fuzzer.c)
    add_librdp_fuzzer(fuzz_pnp_redirection fuzz/pnp_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_usb_redirection fuzz/usb_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_core_input fuzz/core_input_fuzzer.c)
    add_librdp_fuzzer(fuzz_input_channel fuzz/input_channel_fuzzer.c)
    add_librdp_fuzzer(fuzz_graphics_pipeline fuzz/graphics_pipeline_fuzzer.c)
    add_librdp_fuzzer(fuzz_avc fuzz/avc_fuzzer.c)
    add_librdp_fuzzer(fuzz_mouse_cursor fuzz/mouse_cursor_fuzzer.c)
    add_librdp_fuzzer(fuzz_multiparty fuzz/multiparty_fuzzer.c)
    add_librdp_fuzzer(fuzz_telemetry fuzz/telemetry_fuzzer.c)
    add_librdp_fuzzer(fuzz_clearcodec fuzz/clearcodec_fuzzer.c)
    add_librdp_fuzzer(fuzz_nscodec fuzz/nscodec_fuzzer.c)
    add_librdp_fuzzer(fuzz_planar fuzz/planar_fuzzer.c)
    add_librdp_fuzzer(fuzz_rfx_codec fuzz/rfx_codec_fuzzer.c)
    add_librdp_fuzzer(fuzz_rfx_stream fuzz/rfx_stream_fuzzer.c)
    add_librdp_fuzzer(fuzz_surface_commands fuzz/surface_commands_fuzzer.c)
    add_librdp_fuzzer(fuzz_clipboard fuzz/clipboard_fuzzer.c)
    add_librdp_fuzzer(fuzz_security fuzz/security_fuzzer.c)
    add_librdp_fuzzer(fuzz_licensing fuzz/licensing_fuzzer.c)
    add_librdp_fuzzer(fuzz_credssp fuzz/credssp_fuzzer.c)
    add_librdp_fuzzer(fuzz_udp_transport fuzz/udp_transport_fuzzer.c)
    add_librdp_fuzzer(fuzz_multitransport fuzz/multitransport_fuzzer.c)
    add_librdp_fuzzer(fuzz_xps_print fuzz/xps_print_fuzzer.c)
    add_librdp_fuzzer(fuzz_auth_redirection fuzz/auth_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_smartcard_redirection fuzz/smartcard_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_video_capture fuzz/video_capture_fuzzer.c)
    add_librdp_fuzzer(fuzz_video_redirection fuzz/video_redirection_fuzzer.c)
    add_librdp_fuzzer(fuzz_video_optimized fuzz/video_optimized_fuzzer.c)
    add_librdp_fuzzer(fuzz_gdi_orders fuzz/gdi_orders_fuzzer.c)
    add_librdp_fuzzer(fuzz_webauthn_channel fuzz/webauthn_channel_fuzzer.c)
endif()

if(LIBRDP_BUILD_X11_VIEWER)
    find_package(X11 REQUIRED COMPONENTS Xcursor Xfixes)
    find_package(PkgConfig REQUIRED)
    find_package(Threads REQUIRED)
    pkg_check_modules(XKBCOMMON REQUIRED xkbcommon)
    add_executable(librdp-x11-viewer
        apps/x11-viewer/audio_pipewire.c
        apps/x11-viewer/camera_v4l2.c
        apps/x11-viewer/device_backends.c
        apps/x11-viewer/main.c
    )
    target_include_directories(librdp-x11-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${X11_INCLUDE_DIR}
        ${XKBCOMMON_INCLUDE_DIRS}
    )
    target_link_libraries(librdp-x11-viewer PRIVATE
        librdp
        ${X11_LIBRARIES}
        X11::Xcursor
        X11::Xfixes
        ${XKBCOMMON_LIBRARIES}
        Threads::Threads
    )
    if(LIBRDP_PIPEWIRE_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_PIPEWIRE=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_PIPEWIRE)
    endif()
    if(LIBRDP_LIBUSB_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_LIBUSB=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_LIBUSB)
    endif()
    if(LIBRDP_PCSC_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_PCSC=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_PCSC)
    endif()
    if(LIBRDP_FIDO2_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_FIDO2=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_FIDO2)
    endif()
    if(LIBRDP_JPEG_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_JPEG=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_JPEG)
    endif()
endif()
