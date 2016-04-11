cmake_minimum_required(VERSION 2.8)
project(Flame)

add_library(Argsx argsx.c)
add_library(Spark netdevice.c ethernet.c arp.c ipv4.c icmp4.c tcp.c udp.c)
