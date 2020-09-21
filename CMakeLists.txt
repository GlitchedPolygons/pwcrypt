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

cmake_minimum_required(VERSION 3.7)
project(pwcrypt C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(PWCRYPT_MAJOR 3)
set(PWCRYPT_MINOR 1)
set(PWCRYPT_PATCH 1)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)
option(USE_SHARED_MBEDTLS_LIBRARY "Statically link MbedTLS if possible." OFF)

option(PWCRYPT_ENABLE_TESTS "Build unit tests." OFF)
option(PWCRYPT_ONLY_BUILD_LIB "Don't build the pwcrypt executable, but just its library for use in other C projects." OFF)
option(PWCRYPT_DLL "Use pwcrypt as a DLL." OFF)
option(PWCRYPT_BUILD_DLL "Build pwcrypt as a DLL." OFF)

if (PWCRYPT_BUILD_DLL)
    add_compile_definitions("PWCRYPT_BUILD_DLL=1")
    set(PWCRYPT_DLL ON)
endif ()

if (PWCRYPT_DLL)
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

set(CCRUSH_PREV_BUILD_SHARED_LIBS BUILD_SHARED_LIBS)

if (BUILD_SHARED_LIBS)
    set (BUILD_SHARED_LIBS Off)
endif ()

if (NOT TARGET ccrush)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/ccrush ccrush)
endif ()

if (PWCRYPT_BUILD_DLL OR BUILD_SHARED_LIBS)
    set_property(TARGET ccrush PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedtls PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedx509 PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${PWCRYPT_MAJOR}.${PWCRYPT_MINOR}.${PWCRYPT_PATCH}
            SOVERSION ${PWCRYPT_MAJOR}
            )
endif ()

target_link_libraries(${PROJECT_NAME}
        PUBLIC ccrush
        PUBLIC mbedcrypto
        )

if (UNIX AND NOT ANDROID)
    target_link_libraries(${PROJECT_NAME} PRIVATE -lpthread)
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
endif ()

target_include_directories(${PROJECT_NAME}
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/ccrush/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        )

get_target_property(${PROJECT_NAME}_DEPS_TARGETS ${PROJECT_NAME} LINK_LIBRARIES)

if (NOT PWCRYPT_ONLY_BUILD_LIB)

    add_executable(${PROJECT_NAME}_cli
            ${CMAKE_CURRENT_LIST_DIR}/src/main.c
            )

    target_link_libraries(${PROJECT_NAME}_cli
            PUBLIC ${PROJECT_NAME}
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            )
endif ()

if (PWCRYPT_ENABLE_TESTS)

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

set (BUILD_SHARED_LIBS CCRUSH_PREV_BUILD_SHARED_LIBS)
