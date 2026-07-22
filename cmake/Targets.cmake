# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

set(LIBRDP_CLIENT_SOURCES
    src/client/client.c
    src/client/error.c
    src/client/settings.c
    src/client/session.c
    src/client/session_activation.c
    src/client/session_autodetect.c
    src/client/session_audio.c
    src/client/session_camera.c
    src/client/session_channels.c
    src/client/session_clipboard.c
    src/client/session_device.c
    src/client/session_filesystem.c
    src/client/session_gdi.c
    src/client/session_graphics.c
    src/client/session_graphics_pipeline.c
    src/client/session_input.c
    src/client/session_lifecycle.c
    src/client/session_message_channel.c
    src/client/session_multitransport.c
    src/client/session_ports.c
    src/client/session_printer.c
    src/client/session_protocol_io.c
    src/client/session_redirection.c
    src/client/session_runtime.c
    src/client/session_smartcard.c
    src/client/session_usb.c
    src/client/session_video.c
    src/client/smartcard_backend.c
)

set(LIBRDP_PUBLIC_SERVICE_SOURCES
    src/admin/admin.c
    src/clipboard/clipboard.c
    src/workspace/workspace.c
)

set(LIBRDP_CHANNEL_SOURCES
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
    src/channels/geometry_tracking.c
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
)

set(LIBRDP_COMMON_SOURCES
    src/common/buffer.c
    src/common/charset.c
    src/common/fault_injection.c
    src/common/stream.c
    src/common/trace.c
    src/input/input.c
    src/platform/socket.c
)

set(LIBRDP_GRAPHICS_SOURCES
    src/graphics/avc.c
    src/graphics/bitmap.c
    src/graphics/clearcodec.c
    src/graphics/gdi_backend.c
    src/graphics/gdi_backend_cairo.c
    src/graphics/gdi_backend_quartz.c
    src/graphics/gdi_image.c
    src/graphics/gdi_image_quartz.c
    src/graphics/gdi_orders.c
    src/graphics/gdi_render.c
    src/graphics/nscodec.c
    src/graphics/planar.c
    src/graphics/rfx_codec.c
    src/graphics/rfx_stream.c
    src/graphics/surface.c
    src/graphics/surface_commands.c
)

set(LIBRDP_GATEWAY_SOURCES
    src/gateway/gateway.c
    src/gateway/rdg_http.c
)

set(LIBRDP_SECURITY_SOURCES
    src/nla/credssp.c
    src/security/certificate.c
    src/security/security.c
    src/security/tls_io.c
)

set(LIBRDP_PROTOCOL_SOURCES
    src/licensing/licensing.c
    src/protocol/capabilities.c
    src/protocol/bulk.c
    src/protocol/fastpath.c
    src/protocol/gcc.c
    src/protocol/mcs.c
    src/protocol/network_autodetect.c
    src/protocol/pointer.c
    src/protocol/session_selection.c
    src/protocol/slowpath.c
    src/protocol/tpkt.c
    src/protocol/x224.c
)

set(LIBRDP_TRANSPORT_SOURCES
    src/transport/tcp.c
    src/transport/multitransport.c
    src/transport/transport.c
    src/transport/udp_transport.c
)

set(LIBRDP_SERVER_SOURCES
    src/server/server.c
    src/server/server_autodetect.c
    src/server/server_channels.c
    src/server/server_drive.c
    src/server/server_extensions.c
    src/server/server_features.c
    src/server/server_graphics.c
    src/server/server_peer.c
    src/server/server_protocol.c
    src/server/server_security.c
)

set(LIBRDP_SOURCES
    ${LIBRDP_CLIENT_SOURCES}
    ${LIBRDP_PUBLIC_SERVICE_SOURCES}
    ${LIBRDP_CHANNEL_SOURCES}
    ${LIBRDP_COMMON_SOURCES}
    ${LIBRDP_GRAPHICS_SOURCES}
    ${LIBRDP_GATEWAY_SOURCES}
    ${LIBRDP_SECURITY_SOURCES}
    ${LIBRDP_PROTOCOL_SOURCES}
    ${LIBRDP_TRANSPORT_SOURCES}
    ${LIBRDP_SERVER_SOURCES}
)

set(LIBRDP_BACKEND_SOURCES
    src/client/printer_backend.c
    src/client/webauthn_backend.c
)
if(LIBRDP_LIBUSB_FOUND)
    list(APPEND LIBRDP_BACKEND_SOURCES
        src/client/usb_backend.c
    )
endif()

add_library(librdp_objects OBJECT ${LIBRDP_SOURCES})
add_library(librdp_backend_objects OBJECT ${LIBRDP_BACKEND_SOURCES})
if(LIBRDP_BUILD_TESTS)
    target_compile_definitions(librdp_objects PRIVATE RDP_ENABLE_TEST_FAULTS=1)
    target_compile_definitions(librdp_backend_objects PRIVATE RDP_ENABLE_TEST_FAULTS=1)
endif()
if(LIBRDP_LIBRARY_TYPE STREQUAL "AUTO")
    if(BUILD_SHARED_LIBS)
        set(LIBRDP_PRIMARY_LIBRARY_KIND SHARED)
    else()
        set(LIBRDP_PRIMARY_LIBRARY_KIND STATIC)
    endif()
elseif(LIBRDP_LIBRARY_TYPE STREQUAL "SHARED")
    set(LIBRDP_PRIMARY_LIBRARY_KIND SHARED)
elseif(LIBRDP_LIBRARY_TYPE STREQUAL "STATIC")
    set(LIBRDP_PRIMARY_LIBRARY_KIND STATIC)
elseif(BUILD_SHARED_LIBS)
    set(LIBRDP_PRIMARY_LIBRARY_KIND SHARED)
    set(LIBRDP_SECONDARY_LIBRARY_TARGET librdp_static)
    set(LIBRDP_SECONDARY_LIBRARY_KIND STATIC)
else()
    set(LIBRDP_PRIMARY_LIBRARY_KIND STATIC)
    set(LIBRDP_SECONDARY_LIBRARY_TARGET librdp_shared)
    set(LIBRDP_SECONDARY_LIBRARY_KIND SHARED)
endif()

add_library(librdp ${LIBRDP_PRIMARY_LIBRARY_KIND} $<TARGET_OBJECTS:librdp_objects> $<TARGET_OBJECTS:librdp_backend_objects>)
set(LIBRDP_LIBRARY_TARGETS librdp)
set(LIBRDP_SHARED_LIBRARY_TARGETS "")
if(LIBRDP_PRIMARY_LIBRARY_KIND STREQUAL "SHARED")
    list(APPEND LIBRDP_SHARED_LIBRARY_TARGETS librdp)
endif()
if(DEFINED LIBRDP_SECONDARY_LIBRARY_TARGET)
    add_library(${LIBRDP_SECONDARY_LIBRARY_TARGET} ${LIBRDP_SECONDARY_LIBRARY_KIND} $<TARGET_OBJECTS:librdp_objects> $<TARGET_OBJECTS:librdp_backend_objects>)
    set_target_properties(${LIBRDP_SECONDARY_LIBRARY_TARGET} PROPERTIES OUTPUT_NAME librdp)
    list(APPEND LIBRDP_LIBRARY_TARGETS ${LIBRDP_SECONDARY_LIBRARY_TARGET})
    if(LIBRDP_SECONDARY_LIBRARY_KIND STREQUAL "SHARED")
        list(APPEND LIBRDP_SHARED_LIBRARY_TARGETS ${LIBRDP_SECONDARY_LIBRARY_TARGET})
    endif()
endif()

function(librdp_configure_library_target target kind)
    target_include_directories(${target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    set_target_properties(${target} PROPERTIES
        C_VISIBILITY_PRESET hidden
    )
    if(kind STREQUAL "SHARED")
        set_target_properties(${target} PROPERTIES
            VERSION ${PROJECT_VERSION}
            SOVERSION ${LIBRDP_ABI_VERSION}
        )
        if(APPLE)
            set(LIBRDP_EXPORT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/librdp.exports)
            target_link_options(${target} PRIVATE "LINKER:-exported_symbols_list,${LIBRDP_EXPORT_FILE}")
            set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS ${LIBRDP_EXPORT_FILE})
        elseif(UNIX)
            set(LIBRDP_EXPORT_MAP_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/librdp.exports.map)
            set(LIBRDP_EXPORT_MAP ${LIBRDP_EXPORT_MAP_SOURCE})
            if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
                file(READ ${LIBRDP_EXPORT_MAP_SOURCE} LIBRDP_EXPORT_MAP_CONTENT)
                string(FIND "${LIBRDP_EXPORT_MAP_CONTENT}" "LIBRDP_" LIBRDP_EXPORT_MAP_OFFSET)
                if(LIBRDP_EXPORT_MAP_OFFSET EQUAL -1)
                    message(FATAL_ERROR "librdp export map has no version block")
                endif()
                string(SUBSTRING
                    "${LIBRDP_EXPORT_MAP_CONTENT}"
                    ${LIBRDP_EXPORT_MAP_OFFSET}
                    -1
                    LIBRDP_EXPORT_MAP_CONTENT)
                set(LIBRDP_EXPORT_MAP ${CMAKE_CURRENT_BINARY_DIR}/${target}.exports.map)
                file(WRITE ${LIBRDP_EXPORT_MAP} "${LIBRDP_EXPORT_MAP_CONTENT}")
                set_property(DIRECTORY APPEND PROPERTY
                    CMAKE_CONFIGURE_DEPENDS ${LIBRDP_EXPORT_MAP_SOURCE})
                target_link_options(${target} PRIVATE "LINKER:-z,gnu-version-script-compat")
            endif()
            target_link_options(${target} PRIVATE "LINKER:--version-script=${LIBRDP_EXPORT_MAP}")
            set_property(TARGET ${target} APPEND PROPERTY
                LINK_DEPENDS ${LIBRDP_EXPORT_MAP_SOURCE} ${LIBRDP_EXPORT_MAP})
        endif()
    endif()
    librdp_apply_system_definitions(${target})
    target_link_libraries(${target} PUBLIC OpenSSL::SSL ${LIBRDP_ICONV_LINK_LIBRARIES} Threads::Threads)
endfunction()

function(librdp_link_library_targets)
    foreach(target IN LISTS LIBRDP_LIBRARY_TARGETS)
        target_link_libraries(${target} PUBLIC ${ARGN})
    endforeach()
endfunction()

function(librdp_apply_warning_options target)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
        if(LIBRDP_ENABLE_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

function(librdp_apply_sanitizer_compile_options target)
    if(LIBRDP_ENABLE_SANITIZERS)
        target_compile_options(${target} PRIVATE -fsanitize=${LIBRDP_SANITIZER_FLAG_VALUE} -fno-omit-frame-pointer)
    endif()
endfunction()

function(librdp_apply_sanitizer_link_options target)
    if(NOT LIBRDP_ENABLE_SANITIZERS)
        return()
    endif()
    get_target_property(target_type ${target} TYPE)
    if(NOT target_type STREQUAL "STATIC_LIBRARY" AND NOT target_type STREQUAL "OBJECT_LIBRARY")
        target_link_options(${target} PRIVATE -fsanitize=${LIBRDP_SANITIZER_FLAG_VALUE})
    endif()
endfunction()

target_include_directories(librdp_objects
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_include_directories(librdp_backend_objects
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)
librdp_apply_openssl_include_dirs(librdp_objects)
librdp_apply_openssl_include_dirs(librdp_backend_objects)
librdp_apply_iconv_include_dirs(librdp_objects)
librdp_apply_iconv_include_dirs(librdp_backend_objects)

set_target_properties(librdp_objects PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
)
set_target_properties(librdp_backend_objects PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
)
librdp_apply_system_definitions(librdp_objects)
librdp_apply_system_definitions(librdp_backend_objects)
librdp_apply_warning_options(librdp_objects)
librdp_apply_warning_options(librdp_backend_objects)
librdp_apply_sanitizer_compile_options(librdp_objects)
librdp_apply_sanitizer_compile_options(librdp_backend_objects)
foreach(target IN LISTS LIBRDP_LIBRARY_TARGETS)
    if(target IN_LIST LIBRDP_SHARED_LIBRARY_TARGETS)
        librdp_configure_library_target(${target} SHARED)
    else()
        librdp_configure_library_target(${target} STATIC)
    endif()
    librdp_apply_sanitizer_link_options(${target})
endforeach()
if(LIBRDP_FFMPEG_AVC_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_FFMPEG_AVC=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_FFMPEG_AVC)
    librdp_link_library_targets(PkgConfig::LIBRDP_FFMPEG_AVC)
endif()
if(LIBRDP_OPENH264_AVC_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_OPENH264_AVC=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_OPENH264_AVC)
    librdp_link_library_targets(PkgConfig::LIBRDP_OPENH264_AVC)
endif()
if(LIBRDP_PCSC_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_PCSC=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_PCSC)
    librdp_link_library_targets(PkgConfig::LIBRDP_PCSC)
endif()
if(LIBRDP_LIBUSB_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_LIBUSB=1)
    target_compile_definitions(librdp_backend_objects PRIVATE RDP_HAVE_LIBUSB=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_LIBUSB)
    target_link_libraries(librdp_backend_objects PRIVATE PkgConfig::LIBRDP_LIBUSB)
    librdp_link_library_targets(PkgConfig::LIBRDP_LIBUSB)
endif()
if(LIBRDP_FIDO2_FOUND)
    target_compile_definitions(librdp_backend_objects PRIVATE RDP_HAVE_FIDO2=1)
    target_link_libraries(librdp_backend_objects PRIVATE PkgConfig::LIBRDP_FIDO2)
    librdp_link_library_targets(PkgConfig::LIBRDP_FIDO2)
endif()
if(LIBRDP_CBOR_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_CBOR=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_CBOR)
    librdp_link_library_targets(PkgConfig::LIBRDP_CBOR)
endif()
if(LIBRDP_CUPS_FOUND)
    target_compile_definitions(librdp_backend_objects PRIVATE RDP_HAVE_CUPS=1)
    if(TARGET PkgConfig::LIBRDP_CUPS)
        target_link_libraries(librdp_backend_objects PRIVATE PkgConfig::LIBRDP_CUPS)
        librdp_link_library_targets(PkgConfig::LIBRDP_CUPS)
    else()
        target_include_directories(librdp_backend_objects PRIVATE ${LIBRDP_CUPS_INCLUDE_DIR})
        target_link_libraries(librdp_backend_objects PRIVATE ${LIBRDP_CUPS_LIBRARY})
        librdp_link_library_targets(${LIBRDP_CUPS_LIBRARY})
    endif()
endif()
if(LIBRDP_ACL_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_ACL=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_ACL)
    librdp_link_library_targets(PkgConfig::LIBRDP_ACL)
endif()
if(LIBRDP_ATTR_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_ATTR=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_ATTR)
    librdp_link_library_targets(PkgConfig::LIBRDP_ATTR)
endif()
if(LIBRDP_ARCHIVE_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_ARCHIVE=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_ARCHIVE)
    librdp_link_library_targets(PkgConfig::LIBRDP_ARCHIVE)
endif()
if(LIBRDP_CURL_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_CURL=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_CURL)
    librdp_link_library_targets(PkgConfig::LIBRDP_CURL)
endif()
if(LIBRDP_LIBXML2_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_LIBXML2=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_LIBXML2)
    librdp_link_library_targets(PkgConfig::LIBRDP_LIBXML2)
endif()
if(LIBRDP_CAIRO_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_CAIRO=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_CAIRO)
    librdp_link_library_targets(PkgConfig::LIBRDP_CAIRO)
endif()
if(LIBRDP_PNG_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_PNG=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_PNG)
    librdp_link_library_targets(PkgConfig::LIBRDP_PNG)
endif()
if(LIBRDP_JPEG_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_JPEG=1)
    target_link_libraries(librdp_objects PRIVATE PkgConfig::LIBRDP_JPEG)
    librdp_link_library_targets(PkgConfig::LIBRDP_JPEG)
endif()
if(LIBRDP_QUARTZ_FOUND)
    target_compile_definitions(librdp_objects PRIVATE RDP_HAVE_QUARTZ=1)
    target_link_libraries(librdp_objects PRIVATE
        ${LIBRDP_QUARTZ_COREFOUNDATION_LIBRARY}
        ${LIBRDP_QUARTZ_COREGRAPHICS_LIBRARY}
        ${LIBRDP_QUARTZ_IMAGEIO_LIBRARY}
    )
    librdp_link_library_targets(
        ${LIBRDP_QUARTZ_COREFOUNDATION_LIBRARY}
        ${LIBRDP_QUARTZ_COREGRAPHICS_LIBRARY}
        ${LIBRDP_QUARTZ_IMAGEIO_LIBRARY}
    )
endif()

function(librdp_link_internal_runtime target)
    librdp_apply_system_definitions(${target})
    librdp_apply_openssl_include_dirs(${target})
    target_link_libraries(${target} PRIVATE librdp_objects librdp_backend_objects OpenSSL::SSL ${LIBRDP_ICONV_LINK_LIBRARIES} Threads::Threads)
    if(LIBRDP_FFMPEG_AVC_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_FFMPEG_AVC)
    endif()
    if(LIBRDP_OPENH264_AVC_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_OPENH264_AVC)
    endif()
    if(LIBRDP_PCSC_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_PCSC)
    endif()
    if(LIBRDP_LIBUSB_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_LIBUSB)
    endif()
    if(LIBRDP_FIDO2_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_FIDO2)
    endif()
    if(LIBRDP_CBOR_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_CBOR)
    endif()
    if(LIBRDP_CUPS_FOUND)
        if(TARGET PkgConfig::LIBRDP_CUPS)
            target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_CUPS)
        else()
            target_link_libraries(${target} PRIVATE ${LIBRDP_CUPS_LIBRARY})
        endif()
    endif()
    if(LIBRDP_ACL_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_ACL)
    endif()
    if(LIBRDP_ATTR_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_ATTR)
    endif()
    if(LIBRDP_ARCHIVE_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_ARCHIVE)
    endif()
    if(LIBRDP_CURL_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_CURL)
    endif()
    if(LIBRDP_LIBXML2_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_LIBXML2)
    endif()
    if(LIBRDP_CAIRO_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_CAIRO)
    endif()
    if(LIBRDP_PNG_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_PNG)
    endif()
    if(LIBRDP_JPEG_FOUND)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_JPEG)
    endif()
    if(LIBRDP_QUARTZ_FOUND)
        target_link_libraries(${target} PRIVATE
            ${LIBRDP_QUARTZ_COREFOUNDATION_LIBRARY}
            ${LIBRDP_QUARTZ_COREGRAPHICS_LIBRARY}
            ${LIBRDP_QUARTZ_IMAGEIO_LIBRARY}
        )
    endif()
endfunction()
