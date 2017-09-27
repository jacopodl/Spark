cmake_minimum_required(VERSION 2.8)
project(LibSpark)

set(VERSION_MAJOR 3)
set(VERSION_MINOR 0)
set(VERSION_PATCH 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --std=gnu11 --pedantic")

set(SPARK_USE_STATIC_LIB ON)

set(LIBRARY_OUTPUT_PATH "${PROJECT_SOURCE_DIR}/bin")
set(INCLUDE_PATH "${PROJECT_SOURCE_DIR}/include")

include_directories(include)
add_subdirectory(src)
