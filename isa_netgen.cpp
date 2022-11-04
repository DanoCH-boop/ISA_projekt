// nazov: isa_netgen.cpp
// popis: Generování NetFlow dat ze zachycené síťové komunikace
// autor: Daniel Chudý, xchudy06, VUT FIT Brno
// 20.10.2022

#include "isa_netgen.h"

char errbuff[PCAP_ERRBUF_SIZE];	// Error string
using namespace std;

NETFLOW_HEADER Nf_header;
NETFLOW_FLOW Nf_flow;
Args args;
uint32_t SysStarttime;
std::map<mytuple_t, NETFLOW_FLOW> flow_map;
unsigned int ipv4_hl;
uint8_t tcp_flags;


/**
 * @brief gets the timestamp in ms
 *
 * @param ts Structure cotaining sec and usec in unixtime
 * @return void
*/
uint32_t get_ts(timeval ts) {
    return ts.tv_sec*1000 + ts.tv_usec/1000;
}

/**
 * @brief prints ports of a tcp packet
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @return std::pair<uint16_t,uint16_t>
*/
pair<uint16_t,uint16_t> tpc_fun(const u_char *packet, unsigned int ip_hl) {
    auto _tcp = (tcphdr*)(packet + SIZE_ETHERNET + ip_hl);

    tcp_flags= _tcp->th_flags;
    uint16_t srcport = ntohs(_tcp->th_sport);
    uint16_t dstport = ntohs(_tcp->th_dport);
    return make_pair(srcport,dstport);
}

/**
 * @brief prints ports of a udp packet
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @return std::pair<uint16_t,uint16_t>
*/
pair<uint16_t,uint16_t> udp_fun(const u_char *packet, unsigned int ip_hl) {
    auto _udp = (udphdr*)(packet + SIZE_ETHERNET + ip_hl);

    uint16_t srcport = ntohs(_udp->uh_sport);
    uint16_t dstport = ntohs(_udp->uh_dport);
    return make_pair(srcport,dstport);
}

/**
 * @brief helper function for printing icmp packet data
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @return uint16_t
*/
uint16_t icmp_fun(const u_char *packet, unsigned int ip_hl) {
    auto _icmp = (icmphdr*)(packet + SIZE_ETHERNET + ip_hl);

    uint8_t code = _icmp->code;
    uint8_t type = _icmp->type;

    uint16_t dstport = type * 256 + code; //discord
    return dstport;
}

/**
 * @brief prints ipv4 adresses, determines the transport layer protocol
 *
 * @param packet pointer to the packet data
 * @note https://stackoverflow.com/a/5328184, Milan
 * @return std::tuple<uint32_t, uint32_t, uint16_t, uint16_t,uint8_t>
*/
mytuple_t ipv4_fun(const u_char *packet) {
    auto ipv4 = (iphdr *)(packet + SIZE_ETHERNET);
    ipv4_hl = ipv4->ihl * (unsigned)4;

    Nf_flow.srcaddr = ipv4->saddr;
    Nf_flow.dstaddr = ipv4->daddr;
    Nf_flow.tos = ipv4->tos;
    Nf_flow.prot = ipv4->protocol;
    pair<uint16_t,uint16_t> ports;

    // determine protocol
    switch (ipv4->protocol) {
        case IPPROTO_TCP:
            ports = tpc_fun(packet, ipv4_hl);
            break;
        case IPPROTO_UDP:
            ports = udp_fun(packet, ipv4_hl);
            break;
        case IPPROTO_ICMP:
            ports = make_pair(icmp_fun(packet, ipv4_hl),0);
            break;
        default:
            fprintf(stderr,"Unrecognized protocol\n");
            exit(1);
    }

    Nf_flow.srcport = ports.first;
    Nf_flow.dstport = ports.second;

    return forward_as_tuple(Nf_flow.srcaddr, Nf_flow.dstaddr, Nf_flow.srcport,  Nf_flow.dstport,  Nf_flow.prot);
}

bool time_control(uint32_t curr, uint32_t first, uint32_t last) {

    if(curr - first > args.active_timer*1000){
        return true;
    }
    if(curr - last > args.inactive_timer*1000){
        return true;
    }
    return false;
}

/**
 * @brief callback function, prints MAC adresses, determines the network layer protocol
 *
 * @param packet pointer to the packet data
 * @param header pcap packet header
 * @return void
*/
void returned_packet(u_char *fargs, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int n = 0;
    mytuple_t five_tuple;
    //print timtestamp in RFC3339
    if(n == 0){
        SysStarttime = get_ts(header->ts);
    }
    auto currTime = get_ts(header->ts);
    // define ethernet header
    auto ethernet = (ether_header*)(packet);

    switch (ntohs(ethernet->ether_type)) {
        case IPV4_T :
            five_tuple = ipv4_fun(packet);
            break;
        case IPV6_T :
            fprintf(stderr,"IPv6 ether type is not supported by NetFlow v5\n");
            break;
        default:
            fprintf(stderr,"Unrecognized ether type\n");
            exit(1);
    }


    if(int(flow_map.size()) > args.count){
        //exportuj posledny flowik - treba podla last, ktory ma najneskorsi cas?
    }

    //https://stackoverflow.com/a/26282004/20241032
    for (auto const& flow : flow_map)
    {
        if(time_control(currTime, flow.second.First,flow.second.Last)){
            //exportuj do pixi
            return;
        }
    }

    if(flow_map.count(five_tuple) == 1){    //flow is alredy in the map
        flow_map[five_tuple].dPkts ++;
        flow_map[five_tuple].dOctets += ipv4_hl;
        flow_map[five_tuple].tcp_flags |= tcp_flags;
        flow_map[five_tuple].Last = currTime - SysStarttime;
    }
    else{                                       //new flow
        Nf_flow.dPkts = 1;
        Nf_flow.dOctets = ipv4_hl;
        Nf_flow.tcp_flags = tcp_flags;
        Nf_flow.First = currTime - SysStarttime;
        Nf_flow.Last = Nf_flow.First;
        flow_map[five_tuple] = Nf_flow;
    }

    n++; //count of total packets
    int i = 0;

    char saddr[INET_ADDRSTRLEN];
    char daddr[INET_ADDRSTRLEN];

    //inet_ntop(AF_INET,&(ipv4->daddr),daddr,INET_ADDRSTRLEN);

    for (auto const& flow : flow_map)
    {
        //printf("%d", i++);
        inet_ntop(AF_INET,&(flow.second.srcaddr),saddr,INET_ADDRSTRLEN);
        printf("%s", saddr);
    }
}

void parse_args(int argc, char **argv) {

    in_addr *host;
    int opt;
    while ((opt = getopt(argc, argv, "f:c:a:i:m:")) != -1)
    {
        switch (opt){
            case 'f' :
                args.filename = optarg;
                break;
            case 'c' :

                args.netflow_collector = strtok(optarg, ":");
                if((args.port = strtok(nullptr, ":")) == nullptr){
                    args.port = "2055";
                }
                host = (in_addr*)gethostbyname(optarg)->h_addr_list[0];
                args.netflow_collector = inet_ntoa(*host);
                printf("%s:%s", args.netflow_collector, args.port);
                break;
            case 'a' :
                args.active_timer = stoi(optarg);
                break;

            case 'i' :
                args.inactive_timer = stoi(optarg);
                break;

            case 'm' :
                args.count = stoi(optarg);
                break;

            case '?' :
            case ':' :
            default:
                fprintf(stderr,"Invalid argument");
                break;
        }
    }
}

const char *find_interface() {
    pcap_if_t *interface_list;
    pcap_findalldevs(&interface_list,errbuff);
    auto interface = interface_list->name;
    pcap_freealldevs(interface_list);
    return interface;
}

int main(int argc, char **argv)
{
    parse_args(argc, argv);
    const char* filter_exp = "tcp or udp or icmp";

    pcap_t *handle;			        // Session handle
	struct bpf_program fp{};		// Our netmask
    bpf_u_int32 mask = 0;		    // Our netmask
    bpf_u_int32 net = 0;		    // Our IP

    handle = pcap_open_offline(args.filename, errbuff);
	if (!handle) {
		fprintf(stderr, "Couldn't open device %s:\n", errbuff);
		exit(1);
	}

    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device is not an Ethernet\n");
        exit(1);
    }

    // Compile and apply the filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(1);
    }

    // get packets, 0 == infinite looping
    pcap_loop(handle, -1, returned_packet, nullptr);

    // clean and close
    pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
