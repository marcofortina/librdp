# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)

project(librdp VERSION 0.1.0 LANGUAGES C)

include(CMakePackageConfigHelpers)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

set(LIBRDP_ABI_VERSION 0 CACHE STRING "Shared-library ABI version")
set(LIBRDP_LIBRARY_TYPE "AUTO" CACHE STRING "Library type to build (AUTO, STATIC, SHARED, BOTH)")
set(LIBRDP_OPENSSL_INCLUDE_DIR "" CACHE PATH "Additional OpenSSL include directory for platform package layouts")
set_property(CACHE LIBRDP_LIBRARY_TYPE PROPERTY STRINGS AUTO STATIC SHARED BOTH)
string(TOUPPER "${LIBRDP_LIBRARY_TYPE}" LIBRDP_LIBRARY_TYPE)
set(LIBRDP_LIBRARY_TYPE "${LIBRDP_LIBRARY_TYPE}" CACHE STRING "Library type to build (AUTO, STATIC, SHARED, BOTH)" FORCE)
if(NOT LIBRDP_LIBRARY_TYPE MATCHES "^(AUTO|STATIC|SHARED|BOTH)$")
    message(FATAL_ERROR "LIBRDP_LIBRARY_TYPE must be AUTO, STATIC, SHARED, or BOTH")
endif()

option(LIBRDP_BUILD_TESTS "Build unit tests" ON)
option(LIBRDP_BUILD_FUZZ "Build fuzz targets" OFF)
option(LIBRDP_BUILD_X11_VIEWER "Build X11 viewer" OFF)
option(LIBRDP_BUILD_EXAMPLES "Build example programs" ON)
option(LIBRDP_ENABLE_WERROR "Treat project compiler warnings as errors" OFF)
option(LIBRDP_ENABLE_SANITIZERS "Enable selected compiler sanitizers on project targets" OFF)
set(LIBRDP_SANITIZERS "address;undefined" CACHE STRING "Sanitizers enabled when LIBRDP_ENABLE_SANITIZERS is ON")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

function(librdp_check_sanitizer_support flag result_var)
    set(saved_required_flags "")
    set(saved_required_link_options "")
    if(DEFINED CMAKE_REQUIRED_FLAGS)
        set(saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
    endif()
    if(DEFINED CMAKE_REQUIRED_LINK_OPTIONS)
        set(saved_required_link_options "${CMAKE_REQUIRED_LINK_OPTIONS}")
    endif()
    if(saved_required_flags)
        set(CMAKE_REQUIRED_FLAGS "${saved_required_flags} ${flag}")
    else()
        set(CMAKE_REQUIRED_FLAGS "${flag}")
    endif()
    list(APPEND CMAKE_REQUIRED_LINK_OPTIONS "${flag}")
    check_c_source_compiles("int main(void) { return 0; }" ${result_var})
    set(CMAKE_REQUIRED_FLAGS "${saved_required_flags}")
    set(CMAKE_REQUIRED_LINK_OPTIONS "${saved_required_link_options}")
endfunction()

set(LIBRDP_SANITIZER_FLAG_VALUE "")
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    librdp_check_sanitizer_support("-fsanitize=address" LIBRDP_SANITIZER_ADDRESS_LINKS)
    librdp_check_sanitizer_support("-fsanitize=undefined" LIBRDP_SANITIZER_UNDEFINED_LINKS)
else()
    set(LIBRDP_SANITIZER_ADDRESS_LINKS 0)
    set(LIBRDP_SANITIZER_UNDEFINED_LINKS 0)
endif()
if(LIBRDP_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        message(FATAL_ERROR "LIBRDP_ENABLE_SANITIZERS requires GCC or Clang")
    endif()
    string(REPLACE "," ";" LIBRDP_SANITIZER_LIST "${LIBRDP_SANITIZERS}")
    set(LIBRDP_SANITIZER_FLAGS "")
    foreach(sanitizer IN LISTS LIBRDP_SANITIZER_LIST)
        string(TOLOWER "${sanitizer}" sanitizer_name)
        if(NOT sanitizer_name MATCHES "^(address|undefined)$")
            message(FATAL_ERROR "LIBRDP_SANITIZERS entries must be address or undefined")
        endif()
        if(sanitizer_name STREQUAL "address" AND NOT LIBRDP_SANITIZER_ADDRESS_LINKS)
            message(FATAL_ERROR "address sanitizer is not supported by this compiler")
        endif()
        if(sanitizer_name STREQUAL "undefined" AND NOT LIBRDP_SANITIZER_UNDEFINED_LINKS)
            message(FATAL_ERROR "undefined sanitizer is not supported by this compiler")
        endif()
        list(APPEND LIBRDP_SANITIZER_FLAGS "${sanitizer_name}")
    endforeach()
    list(REMOVE_DUPLICATES LIBRDP_SANITIZER_FLAGS)
    if(NOT LIBRDP_SANITIZER_FLAGS)
        message(FATAL_ERROR "LIBRDP_ENABLE_SANITIZERS requires at least one sanitizer")
    endif()
    list(JOIN LIBRDP_SANITIZER_FLAGS "," LIBRDP_SANITIZER_FLAG_VALUE)
endif()

set(LIBRDP_SYSTEM_COMPILE_DEFINITIONS)
if(APPLE)
    list(APPEND LIBRDP_SYSTEM_COMPILE_DEFINITIONS _DARWIN_C_SOURCE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "NetBSD")
    list(APPEND LIBRDP_SYSTEM_COMPILE_DEFINITIONS _NETBSD_SOURCE)
elseif(NOT CMAKE_SYSTEM_NAME MATCHES "^(FreeBSD|OpenBSD)$")
    list(APPEND LIBRDP_SYSTEM_COMPILE_DEFINITIONS _POSIX_C_SOURCE=200809L)
endif()

function(librdp_apply_system_definitions target)
    if(LIBRDP_SYSTEM_COMPILE_DEFINITIONS)
        target_compile_definitions(${target} PRIVATE ${LIBRDP_SYSTEM_COMPILE_DEFINITIONS})
    endif()
endfunction()

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

function(librdp_summary_line name requested dependency target_name compiled reason)
    message(STATUS "librdp feature name=${name} requested=${requested} dependency=${dependency} target=${target_name} compiled=${compiled} reason=${reason}")
endfunction()

function(librdp_summary_build_target name option target_name)
    if(${option})
        librdp_summary_line(${name} ON not-applicable ${target_name} yes enabled)
    else()
        librdp_summary_line(${name} OFF not-applicable ${target_name} no disabled-by-user)
    endif()
endfunction()

function(librdp_summary_optional_backend name option found target_name)
    if("${${option}}" STREQUAL "OFF")
        librdp_summary_line(${name} "${${option}}" not-searched "${target_name}" no disabled-by-user)
    elseif(${found})
        librdp_summary_line(${name} "${${option}}" found "${target_name}" yes enabled)
    else()
        librdp_summary_line(${name} "${${option}}" missing "${target_name}" no dependency-not-found)
    endif()
endfunction()

function(librdp_summary_viewer_backend name option found)
    if("${${option}}" STREQUAL "OFF")
        librdp_summary_line(${name} "${${option}}" not-searched librdp-x11-viewer no disabled-by-user)
    elseif(NOT LIBRDP_BUILD_X11_VIEWER)
        if(${found})
            set(dependency found)
        else()
            set(dependency missing)
        endif()
        librdp_summary_line(${name} "${${option}}" ${dependency} librdp-x11-viewer no parent-target-disabled)
    elseif(${found})
        librdp_summary_line(${name} "${${option}}" found librdp-x11-viewer yes enabled)
    else()
        librdp_summary_line(${name} "${${option}}" missing librdp-x11-viewer no dependency-not-found)
    endif()
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
librdp_feature_option(LIBRDP_WITH_XSHM "Use MIT-SHM presentation path in the X11 viewer")
librdp_feature_option(LIBRDP_WITH_XRANDR "Use XRandR monitor layout bridge in the X11 viewer")

if(NOT DEFINED OPENSSL_INCLUDE_DIR AND DEFINED ENV{OPENSSL_INCLUDE_DIR})
    set(OPENSSL_INCLUDE_DIR "$ENV{OPENSSL_INCLUDE_DIR}" CACHE PATH "OpenSSL include directory")
endif()
find_package(OpenSSL 3.0 CONFIG QUIET)
if(NOT OpenSSL_FOUND)
    find_package(OpenSSL 3.0 REQUIRED)
endif()
find_package(Iconv REQUIRED)
find_package(Doxygen QUIET)
find_package(PkgConfig QUIET)
find_package(Threads REQUIRED)

set(LIBRDP_ICONV_LINK_LIBRARIES Iconv::Iconv)
find_library(LIBRDP_ICONV_EXTRA_LIBRARY NAMES iconv)
if(LIBRDP_ICONV_EXTRA_LIBRARY)
    list(APPEND LIBRDP_ICONV_LINK_LIBRARIES ${LIBRDP_ICONV_EXTRA_LIBRARY})
endif()

set(LIBRDP_OPENSSL_INCLUDE_DIRECTORIES)
if(LIBRDP_OPENSSL_INCLUDE_DIR AND EXISTS "${LIBRDP_OPENSSL_INCLUDE_DIR}/openssl/types.h")
    list(APPEND LIBRDP_OPENSSL_INCLUDE_DIRECTORIES "${LIBRDP_OPENSSL_INCLUDE_DIR}")
endif()
foreach(var OPENSSL_INCLUDE_DIR OpenSSL_INCLUDE_DIR OPENSSL_INCLUDE_DIRS OpenSSL_INCLUDE_DIRS)
    if(DEFINED ${var})
        foreach(include_dir IN LISTS ${var})
            if(include_dir AND EXISTS "${include_dir}/openssl/types.h")
                list(APPEND LIBRDP_OPENSSL_INCLUDE_DIRECTORIES "${include_dir}")
            endif()
        endforeach()
    endif()
endforeach()
if(LIBRDP_OPENSSL_INCLUDE_DIRECTORIES)
    list(REMOVE_DUPLICATES LIBRDP_OPENSSL_INCLUDE_DIRECTORIES)
endif()

function(librdp_apply_openssl_include_dirs target)
    if(LIBRDP_OPENSSL_INCLUDE_DIRECTORIES)
        target_include_directories(${target} SYSTEM PRIVATE ${LIBRDP_OPENSSL_INCLUDE_DIRECTORIES})
    endif()
endfunction()

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

set(LIBRDP_XSHM_FOUND 0 CACHE INTERNAL "MIT-SHM support found for the X11 viewer" FORCE)
set(LIBRDP_XRANDR_FOUND 0 CACHE INTERNAL "XRandR support found for the X11 viewer" FORCE)

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
set(LIBRDP_CUPS_USES_PKG_CONFIG 0)
if(LIBRDP_CUPS_FOUND AND TARGET PkgConfig::LIBRDP_CUPS)
    set(LIBRDP_CUPS_USES_PKG_CONFIG 1)
endif()

function(librdp_apply_x11_camera_backends target)
    if(LIBRDP_JPEG_FOUND)
        target_compile_definitions(${target} PRIVATE LIBRDP_HAVE_JPEG=1)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_JPEG)
    endif()
endfunction()

function(librdp_apply_x11_device_backends target)
    if(LIBRDP_LIBUSB_FOUND)
        target_compile_definitions(${target} PRIVATE LIBRDP_HAVE_LIBUSB=1)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_LIBUSB)
    endif()
    if(LIBRDP_PCSC_FOUND)
        target_compile_definitions(${target} PRIVATE LIBRDP_HAVE_PCSC=1)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_PCSC)
    endif()
    if(LIBRDP_FIDO2_FOUND)
        target_compile_definitions(${target} PRIVATE LIBRDP_HAVE_FIDO2=1)
        target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_FIDO2)
    endif()
endfunction()

set(LIBRDP_SOURCES
    src/client/client.c
    src/client/error.c
    src/client/settings.c
    src/client/session.c
    src/client/session_activation.c
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
    src/client/session_ports.c
    src/client/session_printer.c
    src/client/session_protocol_io.c
    src/client/session_runtime.c
    src/client/session_smartcard.c
    src/client/session_usb.c
    src/client/session_video.c
    src/client/smartcard_backend.c
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

set(LIBRDP_BACKEND_SOURCES
    src/client/printer_backend.c
    src/client/usb_backend.c
    src/client/webauthn_backend.c
)

add_library(librdp_objects OBJECT ${LIBRDP_SOURCES})
add_library(librdp_backend_objects OBJECT ${LIBRDP_BACKEND_SOURCES})
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
            set(LIBRDP_EXPORT_MAP ${CMAKE_CURRENT_SOURCE_DIR}/cmake/librdp.exports.map)
            target_link_options(${target} PRIVATE "LINKER:--version-script=${LIBRDP_EXPORT_MAP}")
            set_property(TARGET ${target} APPEND PROPERTY LINK_DEPENDS ${LIBRDP_EXPORT_MAP})
        endif()
    endif()
    librdp_apply_system_definitions(${target})
    target_link_libraries(${target} PUBLIC OpenSSL::SSL OpenSSL::Crypto ${LIBRDP_ICONV_LINK_LIBRARIES} Threads::Threads)
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
target_link_libraries(librdp_objects PRIVATE OpenSSL::SSL OpenSSL::Crypto ${LIBRDP_ICONV_LINK_LIBRARIES} Threads::Threads)
target_link_libraries(librdp_backend_objects PRIVATE OpenSSL::SSL OpenSSL::Crypto ${LIBRDP_ICONV_LINK_LIBRARIES} Threads::Threads)
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

set(LIBRDP_PC_REQUIRES_PRIVATE openssl)
set(LIBRDP_PC_LIBS_PRIVATE "")
if(LIBRDP_FFMPEG_AVC_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libavcodec libavutil libswscale)
endif()
if(LIBRDP_OPENH264_AVC_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE openh264)
endif()
if(LIBRDP_PCSC_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libpcsclite)
endif()
if(LIBRDP_LIBUSB_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libusb-1.0)
endif()
if(LIBRDP_FIDO2_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libfido2)
endif()
if(LIBRDP_CBOR_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libcbor)
endif()
if(LIBRDP_CUPS_FOUND AND TARGET PkgConfig::LIBRDP_CUPS)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE cups)
elseif(LIBRDP_CUPS_FOUND)
    list(APPEND LIBRDP_PC_LIBS_PRIVATE -lcups)
endif()
if(LIBRDP_ACL_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libacl)
endif()
if(LIBRDP_ATTR_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libattr)
endif()
if(LIBRDP_ARCHIVE_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libarchive)
endif()
list(REMOVE_DUPLICATES LIBRDP_PC_REQUIRES_PRIVATE)
list(JOIN LIBRDP_PC_REQUIRES_PRIVATE " " LIBRDP_PC_REQUIRES_PRIVATE)
list(REMOVE_DUPLICATES LIBRDP_PC_LIBS_PRIVATE)
list(JOIN LIBRDP_PC_LIBS_PRIVATE " " LIBRDP_PC_LIBS_PRIVATE)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/librdpConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/librdpConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/librdp
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/librdpConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/librdp.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/librdp.pc
    @ONLY
)

install(TARGETS ${LIBRDP_LIBRARY_TARGETS}
    EXPORT librdpTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/librdp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h"
)
install(EXPORT librdpTargets
    NAMESPACE librdp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/librdp
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/librdpConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/librdpConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/librdp
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/librdp.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/COPYING
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs/
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    FILES_MATCHING
        PATTERN "*.md"
        PATTERN "man" EXCLUDE
        PATTERN "requirements.txt" EXCLUDE
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-x11-viewer.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp.7
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-api.7
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-tracing.7
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man7
)

function(librdp_link_internal_runtime target)
    librdp_apply_system_definitions(${target})
    librdp_apply_openssl_include_dirs(${target})
    target_link_libraries(${target} PRIVATE librdp_objects librdp_backend_objects OpenSSL::SSL OpenSSL::Crypto ${LIBRDP_ICONV_LINK_LIBRARIES})
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
endfunction()

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
endif()

if(DOXYGEN_FOUND)
    add_custom_target(docs-api
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Build public API reference"
        VERBATIM)
endif()

if(LIBRDP_BUILD_TESTS OR LIBRDP_BUILD_FUZZ)
    enable_testing()
endif()

if(LIBRDP_BUILD_TESTS)
    find_package(Python3 COMPONENTS Interpreter)
    set(LIBRDP_NESTED_CONFIGURE_ARGS)
    if(DEFINED OpenSSL_DIR AND NOT "${OpenSSL_DIR}" STREQUAL "")
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_DIR=${OpenSSL_DIR}"
        )
    endif()
    if(LIBRDP_OPENSSL_INCLUDE_DIR)
        list(APPEND LIBRDP_NESTED_CONFIGURE_ARGS
            "-DLIBRDP_OPENSSL_INCLUDE_DIR=${LIBRDP_OPENSSL_INCLUDE_DIR}"
        )
    endif()
    function(librdp_configure_test_compile target)
        target_include_directories(${target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        librdp_apply_system_definitions(${target})
        librdp_apply_openssl_include_dirs(${target})
        target_link_libraries(${target} PRIVATE OpenSSL::SSL OpenSSL::Crypto ${LIBRDP_ICONV_LINK_LIBRARIES} Threads::Threads)
        librdp_apply_warning_options(${target})
        librdp_apply_sanitizer_compile_options(${target})
        if(LIBRDP_FFMPEG_AVC_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_FFMPEG_AVC=1)
        endif()
        if(LIBRDP_OPENH264_AVC_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_OPENH264_AVC=1)
        endif()
        if(LIBRDP_LIBUSB_FOUND)
            target_compile_definitions(${target} PRIVATE RDP_HAVE_LIBUSB=1)
            target_link_libraries(${target} PRIVATE PkgConfig::LIBRDP_LIBUSB)
        endif()
    endfunction()

    function(librdp_configure_test_executable target)
        librdp_configure_test_compile(${target})
        librdp_link_internal_runtime(${target})
        librdp_apply_sanitizer_link_options(${target})
    endfunction()

    add_library(test_core_units OBJECT tests/test_core.c)
    target_compile_definitions(test_core_units PRIVATE LIBRDP_TEST_NO_MAIN)
    librdp_configure_test_compile(test_core_units)

    add_executable(test_common
        tests/test_common_main.c
        $<TARGET_OBJECTS:test_core_units>
    )
    librdp_configure_test_executable(test_common)

    add_executable(test_core
        tests/test_core_main.c
        $<TARGET_OBJECTS:test_core_units>
    )
    librdp_configure_test_executable(test_core)

    add_executable(test_protocol tests/test_protocol.c)
    target_compile_definitions(test_protocol PRIVATE LIBRDP_TEST_PROTOCOL_MAIN)
    librdp_configure_test_executable(test_protocol)

    add_executable(test_transport tests/test_transport.c)
    target_compile_definitions(test_transport PRIVATE LIBRDP_TEST_TRANSPORT_MAIN)
    librdp_configure_test_executable(test_transport)

    add_executable(test_interop_smoke tests/interop_smoke.c)
    target_include_directories(test_interop_smoke PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(test_interop_smoke PRIVATE librdp)
    librdp_apply_warning_options(test_interop_smoke)
    librdp_apply_sanitizer_compile_options(test_interop_smoke)
    librdp_apply_sanitizer_link_options(test_interop_smoke)

    add_executable(test_optional_backend_probe tests/optional_backend_probe.c)
    librdp_configure_test_executable(test_optional_backend_probe)

    add_executable(test_viewer_backends
        tests/test_viewer_backends.c
        apps/x11-viewer/camera_v4l2.c
        apps/x11-viewer/device_backends.c
        apps/x11-viewer/viewer_trace.c
    )
    target_include_directories(test_viewer_backends PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_system_definitions(test_viewer_backends)
    target_link_libraries(test_viewer_backends PRIVATE librdp)
    librdp_apply_x11_camera_backends(test_viewer_backends)
    librdp_apply_x11_device_backends(test_viewer_backends)
    librdp_apply_warning_options(test_viewer_backends)
    librdp_apply_sanitizer_compile_options(test_viewer_backends)
    librdp_apply_sanitizer_link_options(test_viewer_backends)

    add_executable(test_viewer_cli
        tests/test_viewer_cli.c
        apps/x11-viewer/viewer_cli.c
        apps/x11-viewer/viewer_trace.c
    )
    target_include_directories(test_viewer_cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_system_definitions(test_viewer_cli)
    target_link_libraries(test_viewer_cli PRIVATE librdp)
    librdp_apply_warning_options(test_viewer_cli)
    librdp_apply_sanitizer_compile_options(test_viewer_cli)
    librdp_apply_sanitizer_link_options(test_viewer_cli)

    add_executable(test_abi_probe tests/abi_probe.c)
    target_include_directories(test_abi_probe PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    librdp_apply_warning_options(test_abi_probe)
    librdp_apply_sanitizer_compile_options(test_abi_probe)
    librdp_apply_sanitizer_link_options(test_abi_probe)

    add_custom_target(librdp_tests
        DEPENDS test_common test_core test_protocol test_transport test_interop_smoke test_optional_backend_probe test_viewer_backends test_viewer_cli test_abi_probe
    )

    add_test(NAME common COMMAND test_common)
    add_test(NAME core COMMAND test_core)
    add_test(NAME protocol COMMAND test_protocol)
    add_test(NAME transport COMMAND test_transport)
    add_test(NAME interop_smoke COMMAND test_interop_smoke)
    add_test(NAME viewer_backends COMMAND test_viewer_backends)
    add_test(NAME viewer_cli COMMAND test_viewer_cli)
    set_tests_properties(common transport PROPERTIES TIMEOUT 30)
    set_tests_properties(core PROPERTIES TIMEOUT 60)
    set_tests_properties(protocol PROPERTIES TIMEOUT 90)
    set_tests_properties(viewer_backends viewer_cli PROPERTIES TIMEOUT 30)
    set_tests_properties(interop_smoke PROPERTIES TIMEOUT 180 SKIP_RETURN_CODE 77)
    add_test(NAME core_optional_backends_off
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/core_optional_backends_off.cmake)
    add_test(NAME optional_backend_matrix
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/optional_backend_matrix.cmake)
    set_tests_properties(optional_backend_matrix PROPERTIES TIMEOUT 180)
    add_test(NAME shared_symbol_visibility
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
            "-DLIBRDP_ABI_VERSION=${LIBRDP_ABI_VERSION}"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/shared_symbol_visibility.cmake)
    add_test(NAME library_type_selection
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
            "-DLIBRDP_STATIC_LIBRARY_SUFFIX=${CMAKE_STATIC_LIBRARY_SUFFIX}"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/library_type_selection.cmake)
    if(Python3_Interpreter_FOUND)
        add_test(NAME abi_baseline
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
                "-DLIBRDP_SHARED_LIBRARY_SUFFIX=${CMAKE_SHARED_LIBRARY_SUFFIX}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                ${LIBRDP_NESTED_CONFIGURE_ARGS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/abi_baseline.cmake)
    endif()
    add_test(NAME installed_public_api_consumer
        COMMAND ${CMAKE_COMMAND}
            "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
            "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
            "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
            "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
            ${LIBRDP_NESTED_CONFIGURE_ARGS}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/install_consumer.cmake)
    if(LIBRDP_SANITIZER_ADDRESS_LINKS AND LIBRDP_SANITIZER_UNDEFINED_LINKS)
        add_test(NAME sanitizer_core
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
                "-DLIBRDP_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DLIBRDP_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
                "-DLIBRDP_BUILD_CONFIG=$<CONFIG>"
                ${LIBRDP_NESTED_CONFIGURE_ARGS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sanitizer_core.cmake)
    endif()
    if(Python3_Interpreter_FOUND)
        add_test(NAME license_headers
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-license-headers.py ${CMAKE_CURRENT_SOURCE_DIR})
        set_tests_properties(license_headers PROPERTIES
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        )
        add_test(NAME license_archive_fallback
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/license_archive_fallback.cmake)
        add_test(NAME public_api_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-public-api-docs.py)
        add_test(NAME source_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-source-comments.py)
        add_test(NAME internal_header_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-internal-header-comments.py)
        add_test(NAME test_fuzz_comments
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-test-fuzz-comments.py)
        add_test(NAME viewer_public_includes
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-viewer-public-includes.py)
        add_test(NAME examples_docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-examples.py)
        add_test(NAME docs
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-docs.py)
        add_test(NAME sbom_generation
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
                "-DLIBRDP_PYTHON_EXECUTABLE=${Python3_EXECUTABLE}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/sbom_generation.cmake)
        if(DOXYGEN_FOUND)
            add_test(NAME doxygen_public_headers
                COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check-doxygen.py)
        endif()
    endif()
endif()

if(LIBRDP_BUILD_FUZZ)
    function(add_librdp_fuzzer name source)
        add_executable(${name} ${source})
        target_include_directories(${name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        )
        librdp_link_internal_runtime(${name})
        librdp_apply_warning_options(${name})
        if(LIBRDP_FFMPEG_AVC_FOUND)
            target_compile_definitions(${name} PRIVATE RDP_HAVE_FFMPEG_AVC=1)
        endif()
        if(LIBRDP_OPENH264_AVC_FOUND)
            target_compile_definitions(${name} PRIVATE RDP_HAVE_OPENH264_AVC=1)
        endif()
        set(librdp_fuzzer_uses_libfuzzer 0)
        if(CMAKE_C_COMPILER_ID MATCHES "Clang")
            set(librdp_fuzzer_uses_libfuzzer 1)
            set(fuzzer_sanitizers fuzzer)
            if(LIBRDP_ENABLE_SANITIZERS)
                list(APPEND fuzzer_sanitizers ${LIBRDP_SANITIZER_FLAGS})
            else()
                list(APPEND fuzzer_sanitizers address undefined)
            endif()
            list(REMOVE_DUPLICATES fuzzer_sanitizers)
            list(JOIN fuzzer_sanitizers "," fuzzer_sanitizer_value)
            target_compile_options(${name} PRIVATE -fsanitize=${fuzzer_sanitizer_value})
            target_link_options(${name} PRIVATE -fsanitize=${fuzzer_sanitizer_value})
        else()
            target_sources(${name} PRIVATE fuzz/fuzz_main.c)
            librdp_apply_sanitizer_compile_options(${name})
            librdp_apply_sanitizer_link_options(${name})
        endif()
        add_test(NAME ${name}_seed_smoke
            COMMAND ${CMAKE_COMMAND}
                "-DLIBRDP_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
                "-DLIBRDP_FUZZ_TARGET=${name}"
                "-DLIBRDP_FUZZ_EXECUTABLE=$<TARGET_FILE:${name}>"
                "-DLIBRDP_FUZZ_USES_LIBFUZZER=${librdp_fuzzer_uses_libfuzzer}"
                -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/fuzz_seed_smoke.cmake)
        set_tests_properties(${name}_seed_smoke PROPERTIES TIMEOUT 20)
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
    if(NOT "${LIBRDP_WITH_XSHM}" STREQUAL "OFF")
        find_package(X11 QUIET COMPONENTS Xext)
        if(X11_Xext_FOUND OR X11_Xext_LIB)
            set(LIBRDP_XSHM_FOUND 1 CACHE INTERNAL "MIT-SHM support found for the X11 viewer" FORCE)
        elseif("${LIBRDP_WITH_XSHM}" STREQUAL "ON")
            message(FATAL_ERROR "LIBRDP_WITH_XSHM=ON requires Xext")
        endif()
    endif()
    if(NOT "${LIBRDP_WITH_XRANDR}" STREQUAL "OFF")
        find_package(X11 QUIET COMPONENTS Xrandr)
        if(X11_Xrandr_FOUND OR X11_Xrandr_LIB)
            set(LIBRDP_XRANDR_FOUND 1 CACHE INTERNAL "XRandR support found for the X11 viewer" FORCE)
        elseif("${LIBRDP_WITH_XRANDR}" STREQUAL "ON")
            message(FATAL_ERROR "LIBRDP_WITH_XRANDR=ON requires Xrandr")
        endif()
    endif()
    find_package(PkgConfig REQUIRED)
    find_package(Threads REQUIRED)
    pkg_check_modules(XKBCOMMON REQUIRED xkbcommon)
    add_executable(librdp-x11-viewer
        apps/x11-viewer/audio_pipewire.c
        apps/x11-viewer/camera_v4l2.c
        apps/x11-viewer/device_backends.c
        apps/x11-viewer/main.c
        apps/x11-viewer/viewer_clipboard.c
        apps/x11-viewer/viewer_cli.c
        apps/x11-viewer/viewer_display.c
        apps/x11-viewer/viewer_input.c
        apps/x11-viewer/viewer_keyboard.c
        apps/x11-viewer/viewer_lifecycle.c
        apps/x11-viewer/viewer_render.c
        apps/x11-viewer/viewer_trace.c
        apps/x11-viewer/viewer_window.c
    )
    target_include_directories(librdp-x11-viewer PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${X11_INCLUDE_DIR}
        ${XKBCOMMON_INCLUDE_DIRS}
    )
    target_link_libraries(librdp-x11-viewer PRIVATE
        librdp
        Iconv::Iconv
        ${X11_LIBRARIES}
        X11::Xcursor
        X11::Xfixes
        ${XKBCOMMON_LIBRARIES}
        Threads::Threads
    )
    librdp_apply_system_definitions(librdp-x11-viewer)
    get_target_property(LIBRDP_X11_VIEWER_INCLUDES librdp-x11-viewer INCLUDE_DIRECTORIES)
    foreach(LIBRDP_X11_VIEWER_INCLUDE IN LISTS LIBRDP_X11_VIEWER_INCLUDES)
        if(NOT IS_ABSOLUTE "${LIBRDP_X11_VIEWER_INCLUDE}")
            continue()
        endif()
        file(REAL_PATH "${LIBRDP_X11_VIEWER_INCLUDE}" LIBRDP_X11_VIEWER_INCLUDE_REAL)
        file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src" LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL)
        string(FIND "${LIBRDP_X11_VIEWER_INCLUDE_REAL}/"
            "${LIBRDP_SOURCE_PRIVATE_INCLUDE_REAL}/" LIBRDP_X11_VIEWER_PRIVATE_INCLUDE_INDEX)
        if(LIBRDP_X11_VIEWER_PRIVATE_INCLUDE_INDEX EQUAL 0)
            message(FATAL_ERROR "librdp-x11-viewer must not include private src headers")
        endif()
    endforeach()
    librdp_apply_warning_options(librdp-x11-viewer)
    librdp_apply_sanitizer_compile_options(librdp-x11-viewer)
    librdp_apply_sanitizer_link_options(librdp-x11-viewer)
    if(LIBRDP_PIPEWIRE_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_PIPEWIRE=1)
        target_link_libraries(librdp-x11-viewer PRIVATE PkgConfig::LIBRDP_PIPEWIRE)
    endif()
    librdp_apply_x11_device_backends(librdp-x11-viewer)
    librdp_apply_x11_camera_backends(librdp-x11-viewer)
    if(LIBRDP_XSHM_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_XSHM=1)
        if(TARGET X11::Xext)
            target_link_libraries(librdp-x11-viewer PRIVATE X11::Xext)
        else()
            target_link_libraries(librdp-x11-viewer PRIVATE ${X11_Xext_LIB})
        endif()
    endif()
    if(LIBRDP_XRANDR_FOUND)
        target_compile_definitions(librdp-x11-viewer PRIVATE LIBRDP_HAVE_XRANDR=1)
        if(TARGET X11::Xrandr)
            target_link_libraries(librdp-x11-viewer PRIVATE X11::Xrandr)
        else()
            target_link_libraries(librdp-x11-viewer PRIVATE ${X11_Xrandr_LIB})
        endif()
    endif()
    install(TARGETS librdp-x11-viewer
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
    if(LIBRDP_BUILD_TESTS)
        add_executable(test_viewer_render
            tests/test_viewer_render.c
            apps/x11-viewer/viewer_render.c
            apps/x11-viewer/viewer_trace.c
            apps/x11-viewer/viewer_window.c
        )
        target_include_directories(test_viewer_render PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
        )
        librdp_apply_system_definitions(test_viewer_render)
        target_link_libraries(test_viewer_render PRIVATE librdp ${X11_LIBRARIES})
        if(LIBRDP_XSHM_FOUND)
            target_compile_definitions(test_viewer_render PRIVATE LIBRDP_HAVE_XSHM=1)
            if(TARGET X11::Xext)
                target_link_libraries(test_viewer_render PRIVATE X11::Xext)
            else()
                target_link_libraries(test_viewer_render PRIVATE ${X11_Xext_LIB})
            endif()
        endif()
        librdp_apply_warning_options(test_viewer_render)
        librdp_apply_sanitizer_compile_options(test_viewer_render)
        librdp_apply_sanitizer_link_options(test_viewer_render)
        add_test(NAME viewer_render COMMAND test_viewer_render)
        set_tests_properties(viewer_render PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_audio
            tests/test_viewer_audio.c
            apps/x11-viewer/audio_pipewire.c
            apps/x11-viewer/viewer_trace.c
        )
        target_include_directories(test_viewer_audio PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(test_viewer_audio PRIVATE
            LIBRDP_X11_AUDIO_TESTING=1
        )
        librdp_apply_system_definitions(test_viewer_audio)
        librdp_apply_warning_options(test_viewer_audio)
        librdp_apply_sanitizer_compile_options(test_viewer_audio)
        librdp_apply_sanitizer_link_options(test_viewer_audio)
        add_test(NAME viewer_audio COMMAND test_viewer_audio)
        set_tests_properties(viewer_audio PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_camera
            tests/test_viewer_camera.c
            apps/x11-viewer/camera_v4l2.c
            apps/x11-viewer/viewer_trace.c
        )
        target_include_directories(test_viewer_camera PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(test_viewer_camera PRIVATE
            LIBRDP_X11_CAMERA_TESTING=1
        )
        librdp_apply_system_definitions(test_viewer_camera)
        librdp_apply_x11_camera_backends(test_viewer_camera)
        librdp_apply_warning_options(test_viewer_camera)
        librdp_apply_sanitizer_compile_options(test_viewer_camera)
        librdp_apply_sanitizer_link_options(test_viewer_camera)
        add_test(NAME viewer_camera COMMAND test_viewer_camera)
        set_tests_properties(viewer_camera PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_keyboard
            tests/test_viewer_keyboard.c
            apps/x11-viewer/viewer_keyboard.c
            apps/x11-viewer/viewer_trace.c
            apps/x11-viewer/viewer_window.c
        )
        target_include_directories(test_viewer_keyboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
            ${XKBCOMMON_INCLUDE_DIRS}
        )
        librdp_apply_system_definitions(test_viewer_keyboard)
        target_link_libraries(test_viewer_keyboard PRIVATE
            librdp
            ${X11_LIBRARIES}
            ${XKBCOMMON_LIBRARIES}
        )
        librdp_apply_warning_options(test_viewer_keyboard)
        librdp_apply_sanitizer_compile_options(test_viewer_keyboard)
        librdp_apply_sanitizer_link_options(test_viewer_keyboard)
        add_test(NAME viewer_keyboard COMMAND test_viewer_keyboard)
        set_tests_properties(viewer_keyboard PROPERTIES TIMEOUT 30)
        add_executable(test_viewer_clipboard
            tests/test_viewer_clipboard.c
            apps/x11-viewer/viewer_clipboard.c
            apps/x11-viewer/viewer_trace.c
        )
        target_include_directories(test_viewer_clipboard PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${X11_INCLUDE_DIR}
        )
        librdp_apply_system_definitions(test_viewer_clipboard)
        target_link_libraries(test_viewer_clipboard PRIVATE
            librdp
            Iconv::Iconv
            ${X11_LIBRARIES}
            X11::Xfixes
        )
        librdp_apply_warning_options(test_viewer_clipboard)
        librdp_apply_sanitizer_compile_options(test_viewer_clipboard)
        librdp_apply_sanitizer_link_options(test_viewer_clipboard)
        add_test(NAME viewer_clipboard COMMAND test_viewer_clipboard)
        set_tests_properties(viewer_clipboard PROPERTIES TIMEOUT 30)
        if(LIBRDP_XRANDR_FOUND)
            add_executable(test_viewer_display
                tests/test_viewer_display.c
                apps/x11-viewer/viewer_display.c
                apps/x11-viewer/viewer_trace.c
            )
            target_include_directories(test_viewer_display PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/apps/x11-viewer
                ${CMAKE_CURRENT_SOURCE_DIR}/include
                ${X11_INCLUDE_DIR}
            )
            target_compile_definitions(test_viewer_display PRIVATE
                LIBRDP_HAVE_XRANDR=1
            )
            librdp_apply_system_definitions(test_viewer_display)
            target_link_libraries(test_viewer_display PRIVATE librdp ${X11_LIBRARIES})
            if(TARGET X11::Xrandr)
                target_link_libraries(test_viewer_display PRIVATE X11::Xrandr)
            else()
                target_link_libraries(test_viewer_display PRIVATE ${X11_Xrandr_LIB})
            endif()
            librdp_apply_warning_options(test_viewer_display)
            librdp_apply_sanitizer_compile_options(test_viewer_display)
            librdp_apply_sanitizer_link_options(test_viewer_display)
            add_test(NAME viewer_display COMMAND test_viewer_display)
            set_tests_properties(viewer_display PROPERTIES TIMEOUT 30)
        endif()
    endif()
endif()

set(CPACK_PACKAGE_NAME "librdp")
set(CPACK_PACKAGE_VENDOR "Marco Fortina")
set(CPACK_PACKAGE_CONTACT "Marco Fortina <marco_fortina@hotmail.it>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "RDP client library and optional X11 viewer")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/marcofortina/librdp")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_VERBATIM_VARIABLES YES)
set(CPACK_GENERATOR TGZ)

find_program(LIBRDP_DPKG_DEB_EXECUTABLE dpkg-deb)
if(LIBRDP_DPKG_DEB_EXECUTABLE)
    list(APPEND CPACK_GENERATOR DEB)
    set(CPACK_DEBIAN_PACKAGE_NAME "librdp")
    set(CPACK_DEBIAN_PACKAGE_SECTION "libs")
    set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Marco Fortina <marco_fortina@hotmail.it>")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
endif()

find_program(LIBRDP_RPMBUILD_EXECUTABLE rpmbuild)
if(LIBRDP_RPMBUILD_EXECUTABLE)
    list(APPEND CPACK_GENERATOR RPM)
    set(CPACK_RPM_PACKAGE_NAME "librdp")
    set(CPACK_RPM_PACKAGE_GROUP "System/Libraries")
    set(CPACK_RPM_PACKAGE_LICENSE "AGPL-3.0-or-later")
    set(CPACK_RPM_PACKAGE_RELEASE "1")
endif()

if(APPLE)
    find_program(LIBRDP_PRODUCTBUILD_EXECUTABLE productbuild)
    if(LIBRDP_PRODUCTBUILD_EXECUTABLE)
        list(APPEND CPACK_GENERATOR productbuild)
        set(CPACK_PRODUCTBUILD_IDENTIFIER "org.marcofortina.librdp")
    endif()
endif()
include(CPack)

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
if(LIBRDP_BUILD_X11_VIEWER)
    librdp_summary_line(x11-viewer ON found librdp-x11-viewer yes enabled)
else()
    librdp_summary_line(x11-viewer OFF not-searched librdp-x11-viewer no disabled-by-user)
endif()
if(DOXYGEN_FOUND)
    librdp_summary_line(docs-api AUTO found docs-api yes enabled)
else()
    librdp_summary_line(docs-api AUTO missing docs-api no dependency-not-found)
endif()
if(LIBRDP_BUILD_X11_VIEWER)
    set(LIBRDP_DEVICE_BACKEND_TARGETS librdp+librdp-x11-viewer)
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
librdp_summary_viewer_backend(pipewire LIBRDP_WITH_PIPEWIRE LIBRDP_PIPEWIRE_FOUND)
librdp_summary_viewer_backend(jpeg LIBRDP_WITH_JPEG LIBRDP_JPEG_FOUND)
librdp_summary_viewer_backend(xshm LIBRDP_WITH_XSHM LIBRDP_XSHM_FOUND)
librdp_summary_viewer_backend(xrandr LIBRDP_WITH_XRANDR LIBRDP_XRANDR_FOUND)
message(STATUS "librdp feature summary end")
