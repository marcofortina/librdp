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

set(output_dir "${LIBRDP_BINARY_DIR}/sbom-generation")
file(MAKE_DIRECTORY "${output_dir}")
set(sbom_one "${output_dir}/librdp-sbom-1.cdx.json")
set(sbom_two "${output_dir}/librdp-sbom-2.cdx.json")

foreach(output IN ITEMS "${sbom_one}" "${sbom_two}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env SOURCE_DATE_EPOCH=0
                "${LIBRDP_PYTHON_EXECUTABLE}"
                "${LIBRDP_SOURCE_DIR}/scripts/generate-sbom.py"
                "--source-dir" "${LIBRDP_SOURCE_DIR}"
                "--build-dir" "${LIBRDP_BINARY_DIR}"
                "--output" "${output}"
        RESULT_VARIABLE generate_result
        OUTPUT_VARIABLE generate_stdout
        ERROR_VARIABLE generate_stderr
    )
    if(NOT generate_result EQUAL 0)
        message(FATAL_ERROR "SBOM generation failed with ${generate_result}\n${generate_stdout}\n${generate_stderr}")
    endif()

    execute_process(
        COMMAND "${LIBRDP_PYTHON_EXECUTABLE}"
                "${LIBRDP_SOURCE_DIR}/scripts/generate-sbom.py"
                "--validate" "${output}"
        RESULT_VARIABLE validate_result
        OUTPUT_VARIABLE validate_stdout
        ERROR_VARIABLE validate_stderr
    )
    if(NOT validate_result EQUAL 0)
        message(FATAL_ERROR "SBOM validation failed with ${validate_result}\n${validate_stdout}\n${validate_stderr}")
    endif()
endforeach()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E compare_files "${sbom_one}" "${sbom_two}"
    RESULT_VARIABLE compare_result
)
if(NOT compare_result EQUAL 0)
    message(FATAL_ERROR "SBOM generation is not deterministic")
endif()

file(READ "${sbom_one}" sbom_content)
foreach(required IN ITEMS
        "librdp:cmake:LIBRDP_BUILD_ADMIN"
        "librdp:cmake:LIBRDP_BUILD_SERVER"
        "librdp:cmake:LIBRDP_BUILD_VIEWER"
        "librdp:cmake:LIBRDP_BUILD_WORKSPACE"
        "librdp:application-backend"
        "librdp:install:application-directory")
    string(FIND "${sbom_content}" "\"${required}\"" required_position)
    if(required_position EQUAL -1)
        message(FATAL_ERROR "SBOM is missing ${required}")
    endif()
endforeach()

foreach(application IN ITEMS ADMIN SERVER VIEWER WORKSPACE)
    if(LIBRDP_TEST_BUILD_${application})
        string(TOLOWER "${application}" application_name)
        set(required "librdp-${application_name}")
        string(FIND "${sbom_content}" "\"${required}\"" required_position)
        if(required_position EQUAL -1)
            message(FATAL_ERROR "SBOM is missing ${required}")
        endif()
    endif()
endforeach()

if(LIBRDP_TEST_BUILD_SERVER AND
   LIBRDP_TEST_SYSTEM_NAME MATCHES "^(Linux|FreeBSD|OpenBSD|NetBSD|SunOS)$")
    foreach(required IN ITEMS
            "librdp:install:session-broker"
            "librdp:install:session-agent"
            "librdp:install:session-supervisor"
            "librdp:install:session-broker-config-example"
            "librdp-session-broker"
            "librdp-session-agent"
            "librdp-session-supervisor")
        string(FIND "${sbom_content}" "\"${required}\"" required_position)
        if(required_position EQUAL -1)
            message(FATAL_ERROR "SBOM is missing ${required}")
        endif()
    endforeach()
endif()
