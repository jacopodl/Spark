cmake_minimum_required(VERSION 2.8)
project(LibSpark)

set (VERSION_MAJOR 1)
set (VERSION_MINOR 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --std=gnu11 --pedantic")

set(LIBRARY_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/bin")
set(PUBLIC_SRC_HEADERS "${PROJECT_SOURCE_DIR}/src/*.h")
set(INCLUDE_PATH "${PROJECT_SOURCE_DIR}/include")

add_subdirectory(src)
