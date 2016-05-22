cmake_minimum_required(VERSION 3.0)
project(LibSpark)

add_library(Spark netdevice.c ethernet.c arp.c ipv4.c routev4.c icmp4.c dhcp.c tcp.c udp.c)

file(GLOB HEADERS ${PUBLIC_SRC_HEADERS})
file(COPY ${HEADERS} DESTINATION "${INCLUDE_PATH}" PATTERN "spark.h" EXCLUDE)
configure_file("${PROJECT_SOURCE_DIR}/spark.h" "${INCLUDE_PATH}/spark.h")
