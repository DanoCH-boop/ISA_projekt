// nazov: isa_netgen.cpp
// popis: Generování NetFlow dat ze zachycené síťové komunikace
// autor: Daniel Chudý, xchudy06, VUT FIT Brno
// 20.10.2022

#include "isa_netgen.h"

char errbuff[PCAP_ERRBUF_SIZE];	// Error string
using namespace std;

// Global variables
NETFLOW_HEADER Nf_header;
NETFLOW_FLOW Nf_flow;
Args args;
uint32_t SysStarttime;
uint32_t unix_usec;
uint32_t unix_sec;
uint32_t currTime;
std::map<mytuple_t, NETFLOW_FLOW> flow_map; //flow cache
uint32_t ipv4_len;
uint8_t tcp_flags;

/**
 * @brief gets the timestamp in ms
 *
 * @param ts Structure cotaining sec and usec in unixtime
 * @return uint32_t
*/
uint32_t get_ts(timeval ts) {
    return ts.tv_sec*1000 + ts.tv_usec/1000;
}

/**
 * @brief gets ports and flags of a tcp packet
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @return std::pair<uint16_t,uint16_t>
*/
pair<uint16_t,uint16_t> tpc_fun(const u_char *packet, unsigned int ip_hl) {
    auto _tcp = (tcphdr*)(packet + SIZE_ETHERNET + ip_hl);
    tcp_flags = _tcp->th_flags;
    uint16_t srcport = ntohs(_tcp->th_sport);
    uint16_t dstport = ntohs(_tcp->th_dport);
    return make_pair(srcport,dstport);
}

/**
 * @brief gets ports of a udp packet
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
 * @brief helper function for getting icmp packet data
 *
 * @param packet pointer to the packet data
 * @param ip_hl length of the IP header
 * @return uint16_t
*/
uint16_t icmp_fun(const u_char *packet, unsigned int ip_hl) {
    //auto _icmp = (icmphdr*)(packet + SIZE_ETHERNET + ip_hl);

    //uint8_t code = _icmp->code;
    //uint8_t type = _icmp->type;

    //uint16_t dstport = type * 256 + code; //computing the port
    return 0;
}

/**
 * @brief get ipv4 adresses, tos, determines the transport layer protocol
 * creates tuple - key for the map of flows
 * @param packet pointer to the packet data
 * @return std::tuple<uint32_t, uint32_t, uint16_t, uint16_t,uint8_t>
*/
mytuple_t ipv4_fun(const u_char *packet) {
    auto ipv4 = (iphdr *)(packet + SIZE_ETHERNET);
    //alternative ip header for len, the tot_len member
    //from iphdr structure does not give the same byte length
    auto my_ip = (ip *)(packet + SIZE_ETHERNET);
    auto ipv4_hl = ipv4->ihl * (unsigned)4;
    ipv4_len = ntohs(my_ip->ip_len);

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
            tcp_flags = 0;
            ports = udp_fun(packet, ipv4_hl);
            break;
        case IPPROTO_ICMP:
            tcp_flags = 0;
            ports = make_pair(icmp_fun(packet, ipv4_hl),0);
            break;
        default:
            fprintf(stderr,"Unrecognized protocol\n");
            exit(1);
    }

    Nf_flow.srcport = ports.first;
    Nf_flow.dstport = ports.second;

    return make_tuple(Nf_flow.srcaddr, Nf_flow.dstaddr, Nf_flow.srcport,  Nf_flow.dstport,  Nf_flow.prot);
}

/**
 * @brief checks the active/inactive timers, if the flow should be exported
 *
 * @param currSysUpTime currentime time in milisecond since the start of the program
 * @param first time in milisecond since the start of the program of the first packet in the flow
 * @param last time in milisecond since the start of the program of the last packet in the flow
 * @return bool
*/
bool time_control(uint32_t currSysUpTime, uint32_t first, uint32_t last) {
    if(currSysUpTime - first > args.active_timer*1000){
        return true;
    }
    if(currSysUpTime - last > args.inactive_timer*1000){
        return true;
    }
    return false;
}

/**
 * @brief prepares the header structure for the export
 *
 * @return void
*/
void make_header() {
    Nf_header.SysUptime = htonl(currTime - SysStarttime);
    Nf_header.count = htons(1);
    Nf_header.flow_sequnce++;
    Nf_header.unix_secs = htonl(unix_sec);
    Nf_header.unix_nsecs = htonl(unix_usec*1000);
}

/**
 * @brief callback function, determines the network layer protocol, exports flows
 * that need to be exported, creates/updates flows using map of flows
 *
 * @param packet pointer to the packet data
 * @param header pcap packet header
 * @return void
*/
void returned_packet(u_char *fargs, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int n = 0;

    //key
    mytuple_t five_tuple;

    //time of the first packet
    if(n == 0){
        SysStarttime = get_ts(header->ts);
    }
    //time of the current packet
    currTime = get_ts(header->ts);
    unix_usec = header->ts.tv_usec;
    unix_sec = header->ts.tv_sec;

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

    //export the oldest flow if the flow cache size exceeds given count (default 1024)
    vector<uint32_t> first_times;
    if(int(flow_map.size()) == args.count){
        printf("size\n");
        for (auto const& flow : flow_map)
        {
            first_times.push_back(flow.second.First);
        }
        uint32_t to_export = *min_element(first_times.begin(), first_times.end());
        for (auto const& flow : flow_map)
        {
            if(flow.second.First == to_export){
                make_header();
                udp_export(flow.second,Nf_header);
                flow_map.erase(flow.first);
                break;
            }
        }
    }

    //https://stackoverflow.com/a/26282004/20241032
    //export a flow if its (in)active timer ran out
    map<mytuple_t, NETFLOW_FLOW>::iterator it;
    for (it = flow_map.begin(); it != flow_map.end();)
    {
        if(time_control(currTime - SysStarttime, it->second.First,it->second.Last)){
            printf("time\n");
            make_header();
            udp_export(it->second, Nf_header);
            it = flow_map.erase(it);
        }
        else{
            it++;
        }
    }

    if(flow_map.find(five_tuple) == flow_map.end()){    //new flow
        Nf_flow.dPkts = 1;
        Nf_flow.dOctets = ipv4_len;
        Nf_flow.tcp_flags = tcp_flags;
        Nf_flow.First = currTime - SysStarttime;
        Nf_flow.Last = Nf_flow.First;
        flow_map.insert({five_tuple, Nf_flow});
    }
    else{                                                       //flow is alredy in the map
        flow_map[five_tuple].dPkts++;
        flow_map[five_tuple].dOctets += ipv4_len;
        flow_map[five_tuple].tcp_flags |= tcp_flags;
        flow_map[five_tuple].Last = currTime - SysStarttime;
    }

    //export a flow if a FIN/RST flag appeared
    if ((tcp_flags & TH_FIN) || (tcp_flags & TH_RST)){
        printf("flag %d\n", tcp_flags);
        make_header();
        udp_export(flow_map[five_tuple],Nf_header);
        flow_map.erase(five_tuple);
    }

    n++; //count of total packets
}

/**
 * @brief parser program arguments
 *
 * @param argc currentime time in milisecond since the start of the program
 * @param argv time in milisecond since the start of the program of the first packet in the flow
 * @return void
*/
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

int main(int argc, char **argv)
{
    parse_args(argc, argv);
    const char* filter_exp = "tcp or udp or icmp";

    pcap_t *handle;			        // Session handle
	struct bpf_program fp{};		// Our netmask
    //bpf_u_int32 mask = 0;		    // Our netmask
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

    // get packets, -1 == infinite looping
    pcap_loop(handle, -1, returned_packet, nullptr);

    //exports leftover packets
    map<mytuple_t, NETFLOW_FLOW>::iterator it;
    for (it = flow_map.begin(); it != flow_map.end();)
    {
        printf("late\n");
        make_header();
        udp_export(it->second, Nf_header);
        it = flow_map.erase(it);
    }

    flow_map.clear();
    // clean and close
    pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
