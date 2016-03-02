cmake_minimum_required(VERSION 2.8)
project(Flame)

set(SOURCE_FILES mspoof.c)
add_executable(mspoof ${SOURCE_FILES})
target_link_libraries(mspoof LINK_PUBLIC Argsx)
target_link_libraries(mspoof LINK_PUBLIC NetdHelper)