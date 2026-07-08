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
endif()

add_library(librdp
    src/client/error.c
    src/client/settings.c
    src/client/session.c
    src/channels/audio_format.c
    src/channels/audio_input.c
    src/channels/audio_output.c
    src/channels/core_input.c
    src/channels/display_control.c
    src/channels/dynamic_channel.c
    src/channels/graphics_pipeline.c
    src/channels/input_channel.c
    src/channels/mouse_cursor.c
    src/channels/virtual_channel.c
    src/clipboard/clipboard.c
    src/common/buffer.c
    src/common/stream.c
    src/common/trace.c
    src/graphics/avc.c
    src/graphics/bitmap.c
    src/graphics/clearcodec.c
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
    src/protocol/slowpath.c
    src/protocol/tpkt.c
    src/protocol/x224.c
    src/security/certificate.c
    src/security/security.c
    src/transport/tcp.c
    src/transport/transport.c
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
    add_librdp_fuzzer(fuzz_mcs fuzz/mcs_fuzzer.c)
    add_librdp_fuzzer(fuzz_pointer fuzz/pointer_fuzzer.c)
    add_librdp_fuzzer(fuzz_gcc fuzz/gcc_fuzzer.c)
    add_librdp_fuzzer(fuzz_capabilities fuzz/capabilities_fuzzer.c)
    add_librdp_fuzzer(fuzz_fastpath fuzz/fastpath_fuzzer.c)
    add_librdp_fuzzer(fuzz_slowpath fuzz/slowpath_fuzzer.c)
    add_librdp_fuzzer(fuzz_bitmap fuzz/bitmap_fuzzer.c)
    add_librdp_fuzzer(fuzz_virtual_channel fuzz/virtual_channel_fuzzer.c)
    add_librdp_fuzzer(fuzz_dynamic_channel fuzz/dynamic_channel_fuzzer.c)
    add_librdp_fuzzer(fuzz_display_control fuzz/display_control_fuzzer.c)
    add_librdp_fuzzer(fuzz_core_input fuzz/core_input_fuzzer.c)
    add_librdp_fuzzer(fuzz_input_channel fuzz/input_channel_fuzzer.c)
    add_librdp_fuzzer(fuzz_graphics_pipeline fuzz/graphics_pipeline_fuzzer.c)
    add_librdp_fuzzer(fuzz_mouse_cursor fuzz/mouse_cursor_fuzzer.c)
    add_librdp_fuzzer(fuzz_clearcodec fuzz/clearcodec_fuzzer.c)
    add_librdp_fuzzer(fuzz_planar fuzz/planar_fuzzer.c)
    add_librdp_fuzzer(fuzz_rfx_codec fuzz/rfx_codec_fuzzer.c)
    add_librdp_fuzzer(fuzz_clipboard fuzz/clipboard_fuzzer.c)
    add_librdp_fuzzer(fuzz_security fuzz/security_fuzzer.c)
    add_librdp_fuzzer(fuzz_credssp fuzz/credssp_fuzzer.c)
endif()

if(LIBRDP_BUILD_X11_VIEWER)
    find_package(X11 REQUIRED COMPONENTS Xcursor Xfixes)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(XKBCOMMON REQUIRED xkbcommon)
    add_executable(librdp-x11-viewer apps/x11-viewer/main.c)
    target_include_directories(librdp-x11-viewer PRIVATE
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
    )
endif()
