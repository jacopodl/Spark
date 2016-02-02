cmake_minimum_required(VERSION 3.3)
project(Flame)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --pedantic -pthread")

set(SOURCE_FILES dstar.c dstar.h ${CMAKE_SOURCE_DIR}/lib/argsx.c ${CMAKE_SOURCE_DIR}/lib/netdhelper.c ${CMAKE_SOURCE_DIR}/lib/ipv4helper.c
        ${CMAKE_SOURCE_DIR}/lib/dhcphelper.c ${CMAKE_SOURCE_DIR}/lib/udphelper.h ${CMAKE_SOURCE_DIR}/lib/udphelper.c)
add_executable(dstar ${SOURCE_FILES})
