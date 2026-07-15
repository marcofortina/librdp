# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)

project(librdp VERSION 0.1.0 LANGUAGES C)

include(CMakePackageConfigHelpers)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

include(cmake/Options.cmake)
include(cmake/Dependencies.cmake)
include(cmake/Targets.cmake)
include(cmake/Install.cmake)
include(cmake/Examples.cmake)
include(cmake/Documentation.cmake)
if(LIBRDP_BUILD_TESTS OR LIBRDP_BUILD_FUZZ)
    enable_testing()
endif()

include(cmake/Tests.cmake)
include(cmake/Fuzz.cmake)
include(cmake/X11Viewer.cmake)
include(cmake/CocoaViewer.cmake)
include(cmake/X11Admin.cmake)
include(cmake/X11Workspace.cmake)
include(cmake/Packaging.cmake)
include(cmake/Summary.cmake)
