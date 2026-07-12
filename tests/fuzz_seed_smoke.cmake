# Copyright (C) 2026 Marco Fortina
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT DEFINED LIBRDP_SOURCE_DIR)
    message(FATAL_ERROR "LIBRDP_SOURCE_DIR is required")
endif()
if(NOT DEFINED LIBRDP_FUZZ_TARGET)
    message(FATAL_ERROR "LIBRDP_FUZZ_TARGET is required")
endif()
if(NOT DEFINED LIBRDP_FUZZ_EXECUTABLE)
    message(FATAL_ERROR "LIBRDP_FUZZ_EXECUTABLE is required")
endif()
if(NOT DEFINED LIBRDP_FUZZ_USES_LIBFUZZER)
    set(LIBRDP_FUZZ_USES_LIBFUZZER 0)
endif()

set(corpus_dir "${LIBRDP_SOURCE_DIR}/fuzz/corpus/${LIBRDP_FUZZ_TARGET}")
if(NOT IS_DIRECTORY "${corpus_dir}")
    message(FATAL_ERROR "missing fuzz corpus directory for ${LIBRDP_FUZZ_TARGET}: ${corpus_dir}")
endif()

file(GLOB seed_files "${corpus_dir}/*.bin")
list(SORT seed_files)
if(NOT seed_files)
    message(FATAL_ERROR "missing fuzz seed files for ${LIBRDP_FUZZ_TARGET}")
endif()

set(dictionary "${LIBRDP_SOURCE_DIR}/fuzz/dictionaries/librdp.dict")
foreach(seed IN LISTS seed_files)
    set(command_args "${LIBRDP_FUZZ_EXECUTABLE}")
    if(LIBRDP_FUZZ_USES_LIBFUZZER)
        list(APPEND command_args "-runs=1" "-max_total_time=10")
        if(EXISTS "${dictionary}")
            list(APPEND command_args "-dict=${dictionary}")
        endif()
        list(APPEND command_args "${seed}")
    else()
        list(APPEND command_args "${seed}")
    endif()
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1"
            "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"
            ${command_args}
        RESULT_VARIABLE seed_result
        OUTPUT_QUIET
        ERROR_QUIET
    )
    if(NOT seed_result EQUAL 0)
        message(FATAL_ERROR "${LIBRDP_FUZZ_TARGET} failed on seed ${seed} with ${seed_result}")
    endif()
endforeach()
