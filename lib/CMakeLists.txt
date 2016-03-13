cmake_minimum_required(VERSION 2.8)
project(Flame)

add_library(Argsx argsx.c)
add_library(Spark ipv4.c netdevice.c ethernet.c udp.c dhcp.c dns.c)
