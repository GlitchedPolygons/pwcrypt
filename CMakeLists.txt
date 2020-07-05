cmake_minimum_required(VERSION 3.16)
project(pwcrypt C)

set(CMAKE_C_STANDARD 11)

option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)
option(USE_SHARED_MBEDTLS_LIBRARY "Statically link MbedTLS if possible." OFF)

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

add_executable(${PROJECT_NAME} main.c)

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
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        )