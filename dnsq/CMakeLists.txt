cmake_minimum_required(VERSION 2.8)
project(Flame)

set(SOURCE_FILES dnsq.c)
add_executable(dnsq ${SOURCE_FILES})
target_link_libraries(dnsq LINK_PUBLIC Argsx)
target_link_libraries(dnsq LINK_PUBLIC IpHelper)
target_link_libraries(dnsq LINK_PUBLIC DnsHelper)