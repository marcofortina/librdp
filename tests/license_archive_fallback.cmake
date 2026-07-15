# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT DEFINED LIBRDP_SOURCE_DIR)
    message(FATAL_ERROR "LIBRDP_SOURCE_DIR is required")
endif()
if(NOT DEFINED LIBRDP_BINARY_DIR)
    message(FATAL_ERROR "LIBRDP_BINARY_DIR is required")
endif()
if(NOT DEFINED LIBRDP_PYTHON_EXECUTABLE)
    message(FATAL_ERROR "LIBRDP_PYTHON_EXECUTABLE is required")
endif()

set(archive_dir "${LIBRDP_BINARY_DIR}/license-archive-fallback")
file(REMOVE_RECURSE "${archive_dir}")
file(MAKE_DIRECTORY "${archive_dir}")

find_program(GIT_EXECUTABLE NAMES git)
if(GIT_EXECUTABLE)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${LIBRDP_SOURCE_DIR}" ls-files
        RESULT_VARIABLE git_result
        OUTPUT_VARIABLE git_output
    )
    if(NOT git_result EQUAL 0)
        message(FATAL_ERROR "git ls-files failed while preparing source-archive fixture")
    endif()
    string(REPLACE "\n" ";" tracked_files "${git_output}")
else()
    file(GLOB_RECURSE tracked_files
        LIST_DIRECTORIES false
        RELATIVE "${LIBRDP_SOURCE_DIR}"
        "${LIBRDP_SOURCE_DIR}/*"
        "${LIBRDP_SOURCE_DIR}/.github/*"
        "${LIBRDP_SOURCE_DIR}/.gitignore"
    )
    list(FILTER tracked_files EXCLUDE REGEX "(^|/)\\.git(/|$)")
    list(FILTER tracked_files EXCLUDE REGEX "(^|/)__pycache__(/|$)")
    list(FILTER tracked_files EXCLUDE REGEX "^build(/|$)")
    list(FILTER tracked_files EXCLUDE REGEX "^build-[^/]*(/|$)")
    list(SORT tracked_files)
endif()

foreach(rel IN LISTS tracked_files)
    if(rel STREQUAL "")
        continue()
    endif()
    if(NOT EXISTS "${LIBRDP_SOURCE_DIR}/${rel}")
        continue()
    endif()
    get_filename_component(parent "${rel}" DIRECTORY)
    if(parent)
        file(MAKE_DIRECTORY "${archive_dir}/${parent}")
    endif()
    file(COPY_FILE "${LIBRDP_SOURCE_DIR}/${rel}" "${archive_dir}/${rel}" ONLY_IF_DIFFERENT)
endforeach()

execute_process(
    COMMAND "${LIBRDP_PYTHON_EXECUTABLE}" "${archive_dir}/scripts/check-license-headers.py" "${archive_dir}"
    RESULT_VARIABLE positive_result
)
if(NOT positive_result EQUAL 0)
    message(FATAL_ERROR "license checker failed in source-archive fallback mode")
endif()

file(WRITE "${archive_dir}/bad-license.c"
    "/*\n"
    " * Copyright (C) 2026 Marco Fortina\n"
    " * SPDX-License"
    "-Identifier: AGPL-3.0"
    "-only\n"
    " */\n"
    "int bad_license_fixture(void) { return 0; }\n"
)

execute_process(
    COMMAND "${LIBRDP_PYTHON_EXECUTABLE}" "${archive_dir}/scripts/check-license-headers.py" "${archive_dir}"
    RESULT_VARIABLE negative_result
    OUTPUT_QUIET
    ERROR_QUIET
)
if(negative_result EQUAL 0)
    message(FATAL_ERROR "license checker accepted a wrong SPDX identifier in fallback mode")
endif()
