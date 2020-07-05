cmake_minimum_required(VERSION 3.16)
project(pwcrypt C)

set(CMAKE_C_STANDARD 11)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)
option(USE_SHARED_MBEDTLS_LIBRARY "Statically link MbedTLS if possible." OFF)

set(ARGON2_SRC
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blake2.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blake2-impl.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blake2b.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blamka-round-opt.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/blake2/blamka-round-ref.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/argon2.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/core.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/core.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/encoding.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/encoding.h
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/opt.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/thread.c
        ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/src/thread.h
        )

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

add_executable(${PROJECT_NAME} main.c ${ARGON2_SRC})

target_link_libraries(${PROJECT_NAME}
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto
        )

if (UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
endif ()

target_include_directories(${PROJECT_NAME}
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/argon2/include
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        )