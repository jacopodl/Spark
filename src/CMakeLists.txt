cmake_minimum_required(VERSION 2.8)
project(LibSpark)

set(LIB_FILE
        socket/spksock.c
        ethernet.c
        arp.c
        ipv4.c
        routev4.c
        icmp4.c
        tcp.c
        udp.c
        dhcp.c)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LIB_FILE ${LIB_FILE}
            socket/spksock_linux.c
            netdevice/ntdev_linux.c)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    set(LIB_FILE ${LIB_FILE}
            socket/spksock_bpf.c
            netdevice/ntdev_bsd.c)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "BSD")
    set(LIB_FILE ${LIB_FILE}
            socket/spksock_bpf.c
            netdevice/ntdev_bsd.c)
else()
    set(LIB_FILE ${LIB_FILE}
            socket/spksock_null.c
            netdevice/ntdev_null.c)
endif()

add_library(Spark ${LIB_FILE})
configure_file("${INCLUDE_PATH}/spark.h.in" "${INCLUDE_PATH}/spark.h")