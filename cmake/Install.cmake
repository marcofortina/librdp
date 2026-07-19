# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

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
if(LIBRDP_CURL_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libcurl)
endif()
if(LIBRDP_LIBXML2_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libxml-2.0)
endif()
if(LIBRDP_CAIRO_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE cairo)
endif()
if(LIBRDP_PNG_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libpng)
endif()
if(LIBRDP_JPEG_FOUND)
    list(APPEND LIBRDP_PC_REQUIRES_PRIVATE libjpeg)
endif()
if(LIBRDP_QUARTZ_FOUND)
    list(APPEND LIBRDP_PC_LIBS_PRIVATE
        "-framework CoreFoundation"
        "-framework CoreGraphics"
        "-framework ImageIO"
    )
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
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/packaging/librdp-session-broker.conf.example
    DESTINATION ${CMAKE_INSTALL_DATADIR}/librdp
)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs/
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
    FILES_MATCHING
        PATTERN "*.md"
        PATTERN "man" EXCLUDE
        PATTERN "requirements.txt" EXCLUDE
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-cocoa-admin.1
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-cocoa-server.1
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-cocoa-workspace.1
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-cocoa-viewer.1
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-x11-viewer.1
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-x11-admin.1
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-x11-server.1
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-x11-workspace.1
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man1
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-x11-session-broker.8
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man8
)
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp.7
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-api.7
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-server.7
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-tracing.7
    ${CMAKE_CURRENT_SOURCE_DIR}/docs/man/librdp-workspace.7
    DESTINATION ${CMAKE_INSTALL_MANDIR}/man7
)
