cmake_minimum_required(VERSION 2.8)
project(LibSpark)

set (VERSION_NAME  "\"Novirec\"")
set (VERSION_MAJOR 1)
set (VERSION_MINOR 3)
set (VERSION_PATCH 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --std=gnu11 --pedantic")

set(PUBLIC_SRC_HEADERS "${PROJECT_SOURCE_DIR}/src/*.h")

set(DEFAULT_INSTALL_PATH "${PROJECT_SOURCE_DIR}/bin")
set(LIBRARY_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/bin")
set(INCLUDE_PATH "${PROJECT_SOURCE_DIR}/include")

add_subdirectory(src)
