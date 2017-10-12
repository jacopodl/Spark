cmake_minimum_required(VERSION 2.8)
project(LibSpark)

set(LIB_FILE
        spkerr.c
        socket/spksock.c
        netdevice/netdev.c
        pcap/pcap.c
        ethernet.c
        arp.c
        ip.c
        icmp.c
        tcp.c
        udp.c
        dhcp.c
        dns.c)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LIB_FILE ${LIB_FILE} socket/spksock_linux.c netdevice/ntdev_linux.c)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin" OR ${CMAKE_SYSTEM_NAME} MATCHES "BSD")
    set(LIB_FILE ${LIB_FILE} socket/spksock_bpf.c netdevice/ntdev_bsd.c)
else ()
    set(LIB_FILE ${LIB_FILE} socket/spksock_null.c netdevice/ntdev_null.c)
endif ()

configure_file("${INCLUDE_PATH}/spark.h.in" "${INCLUDE_PATH}/spark.h")

if (SPARK_USE_STATIC_LIB)
    add_library(Spark STATIC ${LIB_FILE})
else ()
    add_library(Spark SHARED ${LIB_FILE})
endif ()