cmake_minimum_required(VERSION 3.24)

foreach(argument SHELL SOURCE OUTPUT TABLE)
    if(NOT DEFINED ${argument} OR "${${argument}}" STREQUAL "")
        message(FATAL_ERROR "Missing mksh generator argument: ${argument}")
    endif()
endforeach()

# A native Windows CMake/Ninja process does not acquire the MSYS2 tool PATH.
# Keep shell companions (not Windows sort.exe) ahead of the inherited tools.
get_filename_component(shell_directory "${SHELL}" DIRECTORY)
if(CMAKE_HOST_WIN32)
    set(ENV{PATH} "${shell_directory};$ENV{PATH}")
else()
    set(ENV{PATH} "${shell_directory}:$ENV{PATH}")
endif()
execute_process(COMMAND "${SHELL}" "${SOURCE}/Build.sh" -G "${SOURCE}/${TABLE}.opt"
    WORKING_DIRECTORY "${OUTPUT}"
    RESULT_VARIABLE result)
if(NOT result STREQUAL "0")
    message(FATAL_ERROR "mksh ${TABLE} generation failed: ${result}")
endif()
if(NOT EXISTS "${OUTPUT}/${TABLE}.gen")
    message(FATAL_ERROR "mksh generator did not produce ${TABLE}.gen")
endif()
