# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.16)

project(librdp_installed_consumer LANGUAGES C)

find_package(librdp REQUIRED CONFIG)

add_executable(librdp-installed-consumer main.c)
target_link_libraries(librdp-installed-consumer PRIVATE librdp::librdp)
