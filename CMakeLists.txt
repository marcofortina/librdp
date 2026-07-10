cmake_minimum_required(VERSION 3.16)

project(librdp VERSION 0.1.0 LANGUAGES C)

option(LIBRDP_BUILD_TESTS "Build unit tests" ON)
option(LIBRDP_BUILD_FUZZ "Build fuzz targets" OFF)
option(LIBRDP_BUILD_X11_VIEWER "Build X11 viewer" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(LIBRDP_FFMPEG_AVC QUIET IMPORTED_TARGET libavcodec libavutil libswscale)
    pkg_check_modules(LIBRDP_OPENH264_AVC QUIET IMPORTED_TARGET openh264)
    pkg_check_modules(LIBRDP_PCSC QUIET IMPORTED_TARGET libpcsclite)
    pkg_check_modules(LIBRDP_LIBUSB QUIET IMPORTED_TARGET libusb-1.0)
    pkg_check_modules(LIBRDP_FIDO2 QUIET IMPORTED_TARGET libfido2)
    pkg_check_modules(LIBRDP_CBOR QUIET IMPORTED_TARGET libcbor)
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
    src/graphics/surface.c
    src/input/input.c
    src/licensing/licensing.c
    src/nla/credssp.c
    src/platform/socket.c
    src/protocol/capabilities.c
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
target_link_libraries(librdp PRIVATE OpenSSL::SSL OpenSSL::Crypto)
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

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(librdp PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

if(LIBRDP_BUILD_TESTS)
    enable_testing()
    add_executable(test_core
        tests/test_core.c
        tests/test_protocol.c
        tests/test_transport.c
    )
    target_include_directories(test_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(test_core PRIVATE librdp OpenSSL::SSL OpenSSL::Crypto)
    add_test(NAME core COMMAND test_core)
endif()

if(LIBRDP_BUILD_FUZZ)
    function(add_librdp_fuzzer name source)
        add_executable(${name} ${source})
        target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
        target_link_libraries(${name} PRIVATE librdp)
        if(CMAKE_C_COMPILER_ID MATCHES "Clang")
            target_compile_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
            target_link_options(${name} PRIVATE -fsanitize=fuzzer,address,undefined)
        else()
            target_sources(${name} PRIVATE fuzz/fuzz_main.c)
        endif()
    endfunction()

    add_librdp_fuzzer(fuzz_x224 fuzz/x224_fuzzer.c)
    add_librdp_fuzzer(fuzz_session_selection fuzz/session_selection_fuzzer.c)
    add_librdp_fuzzer(fuzz_mcs fuzz/mcs_fuzzer.c)
    add_librdp_fuzzer(fuzz_pointer fuzz/pointer_fuzzer.c)
    add_librdp_fuzzer(fuzz_gcc fuzz/gcc_fuzzer.c)
    add_librdp_fuzzer(fuzz_capabilities fuzz/capabilities_fuzzer.c)
    add_librdp_fuzzer(fuzz_fastpath fuzz/fastpath_fuzzer.c)
    add_librdp_fuzzer(fuzz_slowpath fuzz/slowpath_fuzzer.c)
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
    add_librdp_fuzzer(fuzz_mouse_cursor fuzz/mouse_cursor_fuzzer.c)
    add_librdp_fuzzer(fuzz_multiparty fuzz/multiparty_fuzzer.c)
    add_librdp_fuzzer(fuzz_telemetry fuzz/telemetry_fuzzer.c)
    add_librdp_fuzzer(fuzz_clearcodec fuzz/clearcodec_fuzzer.c)
    add_librdp_fuzzer(fuzz_nscodec fuzz/nscodec_fuzzer.c)
    add_librdp_fuzzer(fuzz_planar fuzz/planar_fuzzer.c)
    add_librdp_fuzzer(fuzz_rfx_codec fuzz/rfx_codec_fuzzer.c)
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
    pkg_check_modules(LIBRDP_PIPEWIRE QUIET IMPORTED_TARGET libpipewire-0.3)
    pkg_check_modules(LIBRDP_VIEWER_LIBUSB QUIET IMPORTED_TARGET libusb-1.0)
    pkg_check_modules(LIBRDP_VIEWER_PCSC QUIET IMPORTED_TARGET libpcsclite)
    pkg_check_modules(LIBRDP_VIEWER_FIDO2 QUIET IMPORTED_TARGET libfido2)
    pkg_check_modules(LIBRDP_VIEWER_JPEG QUIET IMPORTED_TARGET libjpeg)
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
    if(LIBRDP_VIEWER_LIBUSB_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_LIBUSB=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_VIEWER_LIBUSB)
    endif()
    if(LIBRDP_VIEWER_PCSC_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_PCSC=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_VIEWER_PCSC)
    endif()
    if(LIBRDP_VIEWER_FIDO2_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_FIDO2=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_VIEWER_FIDO2)
    endif()
    if(LIBRDP_VIEWER_JPEG_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_JPEG=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_VIEWER_JPEG)
    endif()
endif()
