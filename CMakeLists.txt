cmake_minimum_required(VERSION 3.16)

project(librdp VERSION 0.1.0 LANGUAGES C)

option(LIBRDP_BUILD_TESTS "Build unit tests" ON)
option(LIBRDP_BUILD_FUZZ "Build fuzz targets" OFF)
option(LIBRDP_BUILD_X11_VIEWER "Build X11 viewer" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(librdp
    src/client/error.c
    src/client/settings.c
    src/client/session.c
    src/channels/virtual_channel.c
    src/clipboard/clipboard.c
    src/common/buffer.c
    src/common/stream.c
    src/common/trace.c
    src/graphics/surface.c
    src/input/input.c
    src/licensing/licensing.c
    src/nla/credssp.c
    src/platform/socket.c
    src/protocol/capabilities.c
    src/protocol/fastpath.c
    src/protocol/gcc.c
    src/protocol/mcs.c
    src/protocol/slowpath.c
    src/protocol/tpkt.c
    src/protocol/x224.c
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
    target_link_libraries(test_core PRIVATE librdp)
    add_test(NAME core COMMAND test_core)
endif()

if(LIBRDP_BUILD_X11_VIEWER)
    find_package(X11 REQUIRED)
    add_executable(librdp-x11-viewer apps/x11-viewer/main.c)
    target_link_libraries(librdp-x11-viewer PRIVATE librdp X11::X11)
endif()
