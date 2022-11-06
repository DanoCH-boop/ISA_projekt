// nazov: isa_netgen.h
// popis: Generování NetFlow dat ze zachycené síťové komunikace
// autor: Daniel Chudý, xchudy06, VUT FIT Brno
// 21.10.2022

#ifndef ISA_PROJEKT_ISA_NETGEN_H
#define ISA_PROJEKT_ISA_NETGEN_H

#define __FAVOR_BSD
#include <pcap.h>
#include <cstdio>
#include <string>
#include <cstring>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>
#include <tuple> // for tuple
#include <iostream>
#include <map> // for map
#include <algorithm>

#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#define SIZE_ETHERNET 14
#define IPV4_T 2048
#define IPV6_T 34525


struct NETFLOW_HEADER{
  uint16_t version = htons(5), count;
  uint32_t SysUptime, unix_secs, unix_nsecs;
  uint32_t flow_sequnce = htonl(0);
  uint8_t engine_type{}, engine_id{};
  uint16_t sampling_interval{};
};

struct NETFLOW_FLOW{
    uint32_t  srcaddr, dstaddr;
    uint32_t nexthop = htonl(0);
    uint16_t input{}, output{};
    uint32_t dPkts, dOctets;
    uint32_t  First, Last;
    uint16_t srcport, dstport;
    uint8_t pad1{};
    uint8_t tcp_flags, prot, tos;
    uint16_t src_as{}, dst_as{};
    uint8_t src_mask{}, dst_mask{};
    uint16_t pad2{};
};

void udp_export(NETFLOW_FLOW flow, NETFLOW_HEADER header);

struct Args {
    const char* filename = "-";
    const char* netflow_collector = "127.0.0.1";
    uint32_t active_timer = 60;
    uint32_t inactive_timer = 10;
    int count = 1024;
    const char* port = "2055";
};

typedef std::tuple<uint32_t, uint32_t, uint16_t, uint16_t,uint8_t> mytuple_t;

extern NETFLOW_HEADER Nf_header;
extern NETFLOW_FLOW Nf_flow;
extern Args args;

#endif //ISA_PROJEKT_ISA_NETGEN_H
