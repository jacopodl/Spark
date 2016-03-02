cmake_minimum_required(VERSION 2.8)
project(Flame)

add_library(Argsx argsx.c)
add_library(IpHelper ipv4.c)
add_library(NetdHelper netdevice.c ethernet.c)
add_library(UdpHelper udp.c)
add_library(DhcpHelper dhcp.c)
add_library(DnsHelper dns.c)
