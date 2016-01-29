cmake_minimum_required(VERSION 3.3)
project(Flame)

add_subdirectory(mspoof)
add_subdirectory(dstar)

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --pedantic")
#set(SOURCE_FILES_MSPOOF lib/netdhelper.c lib/netdhelper.h lib/argsx.c lib/argsx.h mspoof/mspoof.c mspoof/mspoof.h)
#add_executable(mspoof ${SOURCE_FILES_MSPOOF})
