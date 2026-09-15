cmake_minimum_required(VERSION 3.16)

project(DNSense
    VERSION 1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
)

# Dependencies
find_package(yaml-cpp REQUIRED)
find_package(spdlog REQUIRED)
find_package(GTest REQUIRED)

find_package(SQLite3 REQUIRED)

# Source files
file(GLOB_RECURSE SOURCES
    ${PROJECT_SOURCE_DIR}/src/*.cpp
)

# Main executable
add_executable(dnsense ${SOURCES})

# Include directories
target_include_directories(dnsense
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(dnsense
    PRIVATE
        yaml-cpp
        spdlog::spdlog
        SQLite::SQLite3
)

# Tests
enable_testing()

file(GLOB TEST_SOURCES
    ${PROJECT_SOURCE_DIR}/tests/*.cpp
)

add_executable(dnsense_tests ${TEST_SOURCES})

target_include_directories(dnsense_tests
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(dnsense_tests
    PRIVATE
        GTest::gtest
        GTest::gtest_main
        yaml-cpp
        spdlog::spdlog
        SQLite::SQLite3
)

include(GoogleTest)
gtest_discover_tests(dnsense_tests)