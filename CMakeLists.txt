#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.12)
project(pwcrypt C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(${PROJECT_NAME}_MAJOR 4)
set(${PROJECT_NAME}_MINOR 2)
set(${PROJECT_NAME}_PATCH 1)
set(${PROJECT_NAME}_VERSION_STRING "${${PROJECT_NAME}_MAJOR}.${${PROJECT_NAME}_MINOR}.${${PROJECT_NAME}_PATCH}")

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)
option(USE_SHARED_MBEDTLS_LIBRARY "Statically link MbedTLS if possible." OFF)

option(${PROJECT_NAME}_DLL "Use as a DLL." OFF)
option(${PROJECT_NAME}_BUILD_DLL "Build as a DLL." OFF)
option(${PROJECT_NAME}_ENABLE_TESTS "Build unit tests." OFF)
option(${PROJECT_NAME}_PACKAGE "Build the library and package it into a .tar.gz after successfully building." OFF)
option(${PROJECT_NAME}_ONLY_BUILD_LIB "Don't build the pwcrypt executable, but just its library for use in other C projects." OFF)

if (${${PROJECT_NAME}_BUILD_DLL})
    add_compile_definitions("PWCRYPT_BUILD_DLL=1")
    set(${PROJECT_NAME}_DLL ON)
endif ()

if (${${PROJECT_NAME}_DLL})
    add_compile_definitions("PWCRYPT_DLL=1")
endif ()

set(${PROJECT_NAME}_ARGON2_IMPL ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/ref.c)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
    set(${PROJECT_NAME}_ARGON2_IMPL ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/opt.c)
endif ()

set(${PROJECT_NAME}_SRC_FILES
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blake2b.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/argon2.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/core.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/encoding.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/thread.c
        ${${PROJECT_NAME}_ARGON2_IMPL}
        ${CMAKE_CURRENT_LIST_DIR}/src/pwcrypt.c
        )

add_library(${PROJECT_NAME} ${${PROJECT_NAME}_SRC_FILES})

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

if (${${PROJECT_NAME}_BUILD_DLL} OR BUILD_SHARED_LIBS)
    set_property(TARGET mbedtls PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedx509 PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_target_properties(${PROJECT_NAME}
            PROPERTIES
            VERSION ${${PROJECT_NAME}_VERSION_STRING}
            SOVERSION ${${PROJECT_NAME}_MAJOR}
            )
endif ()

set(${PROJECT_NAME}_PREV_BUILD_SHARED_LIBS BUILD_SHARED_LIBS)

if (BUILD_SHARED_LIBS)
    set(BUILD_SHARED_LIBS Off)
endif ()

if (NOT TARGET ccrush)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/ccrush ccrush)
endif ()

set_property(TARGET ccrush PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(${PROJECT_NAME}
        PUBLIC ccrush
        PUBLIC mbedcrypto
        )

if (UNIX AND NOT ANDROID)
    target_link_libraries(${PROJECT_NAME} PRIVATE -lpthread)
endif ()

if (WIN32)
    add_compile_definitions("_CRT_SECURE_NO_WARNINGS=1")
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
endif ()

target_include_directories(${PROJECT_NAME}
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/ccrush/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        )

get_target_property(${PROJECT_NAME}_DEPS_TARGETS ${PROJECT_NAME} LINK_LIBRARIES)

if (NOT ${${PROJECT_NAME}_ONLY_BUILD_LIB})

    add_executable(${PROJECT_NAME}_cli
            ${CMAKE_CURRENT_LIST_DIR}/src/main.c
            ${${PROJECT_NAME}_SRC_FILES}
            )

    target_include_directories(${PROJECT_NAME}_cli
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
            PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/ccrush/include
            PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/include
            PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
            )

    target_link_libraries(${PROJECT_NAME}_cli
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            )

    set_target_properties(${PROJECT_NAME}_cli PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    add_dependencies(${PROJECT_NAME}_cli ${PROJECT_NAME})
endif ()

if (${${PROJECT_NAME}_ENABLE_TESTS})

    add_executable(run_tests
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            )

    target_link_libraries(run_tests
            PUBLIC ${PROJECT_NAME}
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            )

    target_include_directories(run_tests
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/acutest/include
            )

    if (ENABLE_COVERAGE)
        find_package(codecov)
        add_coverage(${PROJECT_NAME})
        add_coverage(run_tests)
        coverage_evaluate()
    endif ()
endif ()

if (${${PROJECT_NAME}_PACKAGE})

    if (NOT ${PROJECT_NAME}_SYSNAME)
        set(${PROJECT_NAME}_SYSNAME ${CMAKE_SYSTEM_NAME})
    endif ()

    if (${${PROJECT_NAME}_ONLY_BUILD_LIB})
        set(${PROJECT_NAME}_PKG ${PROJECT_NAME})
    else ()
        set(${PROJECT_NAME}_PKG ${PROJECT_NAME}_cli)
    endif ()

    set_target_properties(${PROJECT_NAME} PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"

            ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"

            ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    string(TOLOWER "${PROJECT_NAME}-${${PROJECT_NAME}_VERSION_STRING}-${${PROJECT_NAME}_SYSNAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz" ${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME)

    add_custom_command(TARGET ${${PROJECT_NAME}_PKG}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy ${CMAKE_CURRENT_LIST_DIR}/NOTICE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/NOTICE"
            )

    add_custom_command(TARGET ${${PROJECT_NAME}_PKG}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/include "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/include"
            )

    add_custom_command(TARGET ${${PROJECT_NAME}_PKG}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E tar "czvf" ${${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME} ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}
            )
endif ()

set(BUILD_SHARED_LIBS ${${PROJECT_NAME}_PREV_BUILD_SHARED_LIBS})
