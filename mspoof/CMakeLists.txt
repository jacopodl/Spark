cmake_minimum_required(VERSION 3.3)
project(Flame)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --pedantic")

set(SOURCE_FILES mspoof.c mspoof.h ${CMAKE_SOURCE_DIR}/lib/argsx.c ${CMAKE_SOURCE_DIR}/lib/netdhelper.c)
add_executable(mspoof ${SOURCE_FILES})
